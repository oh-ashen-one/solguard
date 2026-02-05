import type { Finding } from '../commands/audit.js';
import type { ParsedIdl } from '../parsers/idl.js';
import type { ParsedRust } from '../parsers/rust.js';

/**
 * SOL238: Frontend Security / Parcl-style Attacks
 * Detects patterns that could be exploited via compromised frontends
 * Reference: Parcl Front-End attack (2024), DNS hijacking, script injection
 */
export function checkParclFrontend(idl: ParsedIdl | null, rust: ParsedRust | null): Finding[] {
  const findings: Finding[] = [];

  if (rust) {
    for (const fn of rust.functions) {
      const content = fn.body.toLowerCase();

      // Check for hardcoded trusted addresses
      if ((content.includes('pubkey') || content.includes('address')) && 
          content.includes('from_str')) {
        if (!content.includes('const') && !content.includes('static')) {
          findings.push({
            id: 'SOL238',
            severity: 'high',
            title: 'Non-Constant Trusted Address',
            description: 'Trusted address appears to be parsed at runtime rather than compile-time. A compromised frontend could inject malicious addresses.',
            location: `Function: ${fn.name}`,
            recommendation: 'Use compile-time constants for trusted addresses: pub const ADMIN: Pubkey = pubkey!("...");',
          });
        }
      }

      // Check for URL/endpoint handling
      if (content.includes('http') || content.includes('url') || content.includes('endpoint')) {
        if (!content.includes('const') && !content.includes('env')) {
          findings.push({
            id: 'SOL238',
            severity: 'medium',
            title: 'Dynamic Endpoint Configuration',
            description: 'Endpoint URLs appear configurable. Compromised frontends could redirect to malicious RPC/API endpoints.',
            location: `Function: ${fn.name}`,
            recommendation: 'Whitelist trusted endpoints. Implement certificate pinning for critical connections.',
          });
        }
      }

      // Check for instruction data that could be manipulated
      if (content.includes('instruction_data') || content.includes('ix_data')) {
        if (!content.includes('validate') && !content.includes('verify')) {
          findings.push({
            id: 'SOL238',
            severity: 'medium',
            title: 'Unvalidated Instruction Data',
            description: 'Instruction data used without explicit validation. Malicious frontends could craft unexpected instruction payloads.',
            location: `Function: ${fn.name}`,
            recommendation: 'Validate all instruction data fields. Use strong typing with Borsh deserialization.',
          });
        }
      }

      // Check for approval/delegate patterns
      if (content.includes('approve') || content.includes('delegate')) {
        if (!content.includes('amount') || content.includes('max') || content.includes('u64::max')) {
          findings.push({
            id: 'SOL238',
            severity: 'high',
            title: 'Unlimited Token Approval',
            description: 'Token approval may use maximum amount. Compromised frontends could request unlimited approvals and drain wallets.',
            location: `Function: ${fn.name}`,
            recommendation: 'Request only the necessary approval amount. Warn users about large approvals.',
          });
        }
      }

      // Check for signature request patterns
      if (content.includes('sign_message') || content.includes('sign_transaction')) {
        if (content.includes('blind') || !content.includes('display')) {
          findings.push({
            id: 'SOL238',
            severity: 'high',
            title: 'Blind Signing Risk',
            description: 'Signature request without clear message display. Users could unknowingly sign malicious transactions.',
            location: `Function: ${fn.name}`,
            recommendation: 'Always display human-readable transaction summaries before signing. Implement simulation previews.',
          });
        }
      }

      // Check for versioned transaction handling
      if (content.includes('versioned_transaction') || content.includes('v0_message')) {
        if (content.includes('lookup_table') || content.includes('address_table')) {
          findings.push({
            id: 'SOL238',
            severity: 'medium',
            title: 'Address Lookup Table Usage',
            description: 'Versioned transactions with lookup tables can hide true destination addresses from users.',
            location: `Function: ${fn.name}`,
            recommendation: 'Resolve all lookup table addresses before displaying to users. Verify lookup table ownership.',
          });
        }
      }
    }
  }

  if (idl) {
    // Check for instructions that could be dangerous from untrusted frontends
    for (const instruction of idl.instructions) {
      // Check for upgrade/admin instructions
      if (instruction.name.toLowerCase().includes('upgrade') ||
          instruction.name.toLowerCase().includes('admin') ||
          instruction.name.toLowerCase().includes('migrate')) {
        findings.push({
          id: 'SOL238',
          severity: 'high',
          title: 'Privileged Instruction Exposed',
          description: `Instruction ${instruction.name} is privileged. Ensure frontend cannot trigger this without explicit user action.`,
          location: `Instruction: ${instruction.name}`,
          recommendation: 'Require multi-sig or timelock for privileged operations. Add prominent warnings in UI.',
        });
      }

      // Check for withdrawal/transfer instructions
      if (instruction.name.toLowerCase().includes('withdraw') ||
          instruction.name.toLowerCase().includes('transfer') ||
          instruction.name.toLowerCase().includes('send')) {
        const hasDestination = instruction.accounts.some(acc => 
          acc.name.toLowerCase().includes('destination') || 
          acc.name.toLowerCase().includes('recipient') ||
          acc.name.toLowerCase().includes('to')
        );
        
        if (hasDestination) {
          findings.push({
            id: 'SOL238',
            severity: 'info',
            title: 'Value Transfer Instruction',
            description: `${instruction.name} transfers value to a destination account. Frontend must verify destination.`,
            location: `Instruction: ${instruction.name}`,
            recommendation: 'Display full destination address to users. Consider address book/whitelist features.',
          });
        }
      }
    }
  }

  return findings;
}
