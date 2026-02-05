import type { Finding } from '../commands/audit.js';
import type { ParsedIdl } from '../parsers/idl.js';
import type { ParsedRust } from '../parsers/rust.js';

/**
 * SOL247: Token Approval/Revoke Safety
 * Detects issues with token approvals that can lead to wallet drainage
 * Reference: SPL Token approve instruction vulnerabilities, Revoke.cash patterns
 */
export function checkTokenRevokeSafety(idl: ParsedIdl | null, rust: ParsedRust | null): Finding[] {
  const findings: Finding[] = [];

  if (rust) {
    for (const fn of rust.functions) {
      const content = fn.body.toLowerCase();

      // Check for unlimited approvals
      if (content.includes('approve') || content.includes('delegate')) {
        if (content.includes('u64::max') || content.includes('max_value') || 
            /amount\s*:\s*[9]{10,}/.test(content)) {
          findings.push({
            id: 'SOL247',
            severity: 'high',
            title: 'Unlimited Token Approval',
            description: 'Maximum token approval detected. If spender is compromised, all tokens can be stolen.',
            location: `Function: ${fn.name}`,
            recommendation: 'Approve only the amount needed for immediate operation. Revoke after use.',
          });
        }

        // Check if approval is revoked after use
        if (!content.includes('revoke')) {
          findings.push({
            id: 'SOL247',
            severity: 'medium',
            title: 'Approval Without Revocation',
            description: 'Token approval without corresponding revocation. Stale approvals are security risks.',
            location: `Function: ${fn.name}`,
            recommendation: 'Revoke approvals immediately after use. Consider permit-style single-use approvals.',
          });
        }
      }

      // Check for approval to untrusted addresses
      if (content.includes('approve') && content.includes('delegate')) {
        if (!content.includes('const') && !content.includes('hardcoded') && 
            !content.includes('trusted_')) {
          findings.push({
            id: 'SOL247',
            severity: 'medium',
            title: 'Approval to Variable Address',
            description: 'Token approval to non-constant address. Frontend could inject malicious delegate.',
            location: `Function: ${fn.name}`,
            recommendation: 'Whitelist trusted delegate addresses. Validate delegate is expected program.',
          });
        }
      }

      // Check for CPI with approved tokens
      if (content.includes('invoke') && content.includes('token')) {
        if (content.includes('delegate') && !content.includes('owner')) {
          findings.push({
            id: 'SOL247',
            severity: 'medium',
            title: 'CPI Using Delegated Authority',
            description: 'Cross-program invocation uses delegated token authority. Delegate trust is transferred.',
            location: `Function: ${fn.name}`,
            recommendation: 'Prefer owner authority when possible. Carefully validate delegate-based operations.',
          });
        }
      }

      // Check for multi-token approvals
      if (content.includes('approve') && (content.includes('loop') || content.includes('for ') || 
          content.includes('iter'))) {
        findings.push({
          id: 'SOL247',
          severity: 'medium',
          title: 'Batch Token Approvals',
          description: 'Multiple token approvals in single transaction. Each approval is a separate risk.',
          location: `Function: ${fn.name}`,
          recommendation: 'Warn users about batch approvals. Show each approval separately for confirmation.',
        });
      }

      // Check for approval amount validation
      if (content.includes('approve')) {
        if (!content.includes('balance') && !content.includes('check') && 
            !content.includes('validate')) {
          findings.push({
            id: 'SOL247',
            severity: 'low',
            title: 'Approval Without Balance Check',
            description: 'Approval may exceed actual token balance. While harmless, suggests poor validation.',
            location: `Function: ${fn.name}`,
            recommendation: 'Validate approval amount against current balance. Provide meaningful limits.',
          });
        }
      }

      // Check for approval in initialize patterns
      if (content.includes('initialize') || content.includes('init')) {
        if (content.includes('approve') || content.includes('delegate')) {
          findings.push({
            id: 'SOL247',
            severity: 'high',
            title: 'Approval During Initialization',
            description: 'Token approval granted during account initialization. May create permanent exposure.',
            location: `Function: ${fn.name}`,
            recommendation: 'Avoid permanent approvals. Request approval only when needed for specific operations.',
          });
        }
      }

      // Check for Token-2022 transfer hook with approvals
      if (content.includes('transfer_hook') || content.includes('token_2022')) {
        if (content.includes('approve') || content.includes('delegate')) {
          findings.push({
            id: 'SOL247',
            severity: 'high',
            title: 'Transfer Hook With Approval Logic',
            description: 'Transfer hook interacts with approvals. Could create unexpected approval side effects.',
            location: `Function: ${fn.name}`,
            recommendation: 'Transfer hooks should not modify approvals. Keep hooks simple and auditable.',
          });
        }
      }

      // Check for approval to program addresses
      if (content.includes('approve') && content.includes('program_id')) {
        findings.push({
          id: 'SOL247',
          severity: 'info',
          title: 'Approval to Program Address',
          description: 'Token approval to a program address. Ensure program properly validates delegate usage.',
          location: `Function: ${fn.name}`,
          recommendation: 'Verify program handles delegated tokens securely. Check program is immutable or audited.',
        });
      }

      // Check for revoke instruction handling
      if (content.includes('revoke')) {
        if (!content.includes('owner') || !content.includes('signer')) {
          findings.push({
            id: 'SOL247',
            severity: 'high',
            title: 'Revoke Without Owner Verification',
            description: 'Revoke operation may not verify token owner. Anyone could revoke others\' approvals.',
            location: `Function: ${fn.name}`,
            recommendation: 'Ensure only token account owner can revoke their approvals.',
          });
        }
      }
    }
  }

  if (idl) {
    // Check for approval-related instructions
    for (const instruction of idl.instructions) {
      const name = instruction.name.toLowerCase();
      
      if (name.includes('approve') || name.includes('delegate')) {
        // Check if amount is an argument
        const hasAmount = instruction.args.some(arg => 
          arg.name.toLowerCase().includes('amount')
        );

        if (!hasAmount) {
          findings.push({
            id: 'SOL247',
            severity: 'high',
            title: 'Approval Instruction Without Amount',
            description: `${instruction.name} lacks explicit amount parameter. May default to unlimited.`,
            location: `Instruction: ${instruction.name}`,
            recommendation: 'Add required amount parameter. Never approve unlimited by default.',
          });
        }

        // Check for delegate account
        const hasDelegate = instruction.accounts.some(acc => 
          acc.name.toLowerCase().includes('delegate') ||
          acc.name.toLowerCase().includes('spender')
        );

        if (hasDelegate) {
          findings.push({
            id: 'SOL247',
            severity: 'info',
            title: 'Token Delegation Instruction',
            description: `${instruction.name} involves token delegation. Ensure proper security documentation.`,
            location: `Instruction: ${instruction.name}`,
            recommendation: 'Document delegation risks in UI. Implement revocation helpers.',
          });
        }
      }
    }
  }

  return findings;
}
