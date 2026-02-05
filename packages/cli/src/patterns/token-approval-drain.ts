import type { Finding } from '../commands/audit.js';
import type { PatternInput } from './index.js';

/**
 * SOL303: Token Approval Drain Attack
 * Detects vulnerabilities in token approval handling
 * Real-world: SPL Token approve instruction exploitation (Hana's revoken)
 */
export function checkTokenApprovalDrain(input: PatternInput): Finding[] {
  const findings: Finding[] = [];

  if (input.rust?.content) {
    const content = input.rust.content;
    const lines = content.split('\n');

    // Detect token approval patterns
    const hasApproval = /approve|delegate|allowance/i.test(content);

    if (hasApproval) {
      // Check for unlimited approvals
      for (let i = 0; i < lines.length; i++) {
        const line = lines[i];

        // Unlimited approval detection
        if (line.includes('approve') && (line.includes('u64::MAX') || line.includes('MAX_AMOUNT'))) {
          findings.push({
            id: 'SOL303',
            title: 'Unlimited Token Approval',
            severity: 'high',
            description: 'Unlimited approvals allow delegates to drain entire token balance if compromised.',
            location: { file: input.path, line: i + 1 },
            suggestion: 'Use exact amounts: approve(ctx, amount_needed)?; // Never use u64::MAX',
            cwe: 'CWE-732',
          });
        }

        // Check for missing revoke after use
        if (line.includes('approve') && !content.includes('revoke')) {
          findings.push({
            id: 'SOL303',
            title: 'Missing Approval Revoke',
            severity: 'medium',
            description: 'Approvals should be revoked after use to minimize attack surface.',
            location: { file: input.path, line: i + 1 },
            suggestion: 'Revoke after use: transfer_tokens(ctx)?; revoke_approval(ctx)?;',
            cwe: 'CWE-269',
          });
          break;
        }
      }

      // Check for delegate validation
      if (content.includes('delegate') && !content.includes('validate_delegate')) {
        findings.push({
          id: 'SOL303',
          title: 'Unvalidated Delegate',
          severity: 'high',
          description: 'Delegates must be validated to prevent approval to malicious addresses.',
          location: { file: input.path, line: 1 },
          suggestion: 'Validate delegate: require!(ALLOWED_DELEGATES.contains(&delegate.key()), InvalidDelegate)',
          cwe: 'CWE-284',
        });
      }

      // Check for approval amount validation
      for (let i = 0; i < lines.length; i++) {
        if (lines[i].includes('approve') && !lines.slice(i, i + 5).join('').includes('balance')) {
          findings.push({
            id: 'SOL303',
            title: 'Approval Without Balance Check',
            severity: 'medium',
            description: 'Approving more than current balance can lead to unexpected behavior.',
            location: { file: input.path, line: i + 1 },
            suggestion: 'Check balance: require!(amount <= token_account.amount, InsufficientBalance)',
            cwe: 'CWE-20',
          });
          break;
        }
      }

      // Check for multi-approval attack
      if (content.includes('approve') && !content.includes('current_delegate')) {
        findings.push({
          id: 'SOL303',
          title: 'Multiple Delegate Risk',
          severity: 'medium',
          description: 'New approvals should check if there is an existing delegate to prevent confusion.',
          location: { file: input.path, line: 1 },
          suggestion: 'Check existing: require!(token_account.delegate.is_none() || overwrite_approved, ExistingDelegate)',
          cwe: 'CWE-362',
        });
      }
    }

    // Check for CPI approval without account validation
    if (content.includes('invoke') && content.includes('approve')) {
      for (let i = 0; i < lines.length; i++) {
        if (lines[i].includes('approve') && lines[i].includes('invoke')) {
          const contextLines = lines.slice(Math.max(0, i - 5), i).join('\n');
          if (!contextLines.includes('owner') && !contextLines.includes('authority')) {
            findings.push({
              id: 'SOL303',
              title: 'CPI Approve Without Authority Check',
              severity: 'critical',
              description: 'CPI approval must validate the token account owner.',
              location: { file: input.path, line: i + 1 },
              suggestion: 'Verify ownership: require!(token_account.owner == ctx.accounts.user.key())',
              cwe: 'CWE-863',
            });
            break;
          }
        }
      }
    }
  }

  return findings;
}
