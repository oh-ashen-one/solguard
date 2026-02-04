import type { Finding } from '../commands/audit.js';
import type { PatternInput } from './index.js';

/**
 * SOL136: Supply Chain Attack Vector
 * Detects patterns that increase risk of supply chain attacks
 * Real-world: @solana/web3.js compromise (Dec 2024)
 */
export function checkSupplyChainAttack(input: PatternInput): Finding[] {
  const findings: Finding[] = [];

  if (input.rust?.content) {
    const content = input.rust.content;
    const lines = content.split('\n');

    // Check for external dependency usage without pinning
    const dependencyPatterns = [
      /use\s+\w+::/,
      /extern\s+crate/,
      /mod\s+\w+;/,
    ];

    // Check for hardcoded addresses that should be verified
    for (let i = 0; i < lines.length; i++) {
      const line = lines[i];
      
      // Check for pubkey declarations without const
      if (line.match(/Pubkey::new|pubkey!/) && !line.includes('const') && !line.includes('//')) {
        findings.push({
          id: 'SOL136',
          title: 'Non-Constant Program ID',
          severity: 'medium',
          description: 'Program IDs should be declared as constants to prevent runtime modification.',
          location: { file: input.path, line: i + 1 },
          suggestion: 'Use const: pub const PROGRAM_ID: Pubkey = pubkey!("...")',
          cwe: 'CWE-471',
        });
        break;
      }
    }

    // Check for dynamic program loading patterns
    if (content.includes('invoke_signed') || content.includes('invoke(')) {
      if (!content.includes('ID ==') && !content.includes('key() ==')) {
        findings.push({
          id: 'SOL136',
          title: 'Unverified Program ID in CPI',
          severity: 'critical',
          description: 'CPI targets should be verified against known program IDs to prevent malicious program substitution.',
          location: { file: input.path, line: 1 },
          suggestion: 'Verify program ID: require!(target_program.key() == &EXPECTED_PROGRAM_ID, InvalidProgram)',
          cwe: 'CWE-345',
        });
      }
    }

    // Check for unsafe external data parsing
    if (content.includes('try_from_slice') || content.includes('deserialize')) {
      if (!content.includes('BorshDeserialize') && !content.includes('validate')) {
        findings.push({
          id: 'SOL136',
          title: 'Unsafe Deserialization',
          severity: 'high',
          description: 'Data deserialization should use safe patterns with proper validation.',
          location: { file: input.path, line: 1 },
          suggestion: 'Use Anchor\'s account parsing or implement BorshDeserialize with validation.',
          cwe: 'CWE-502',
        });
      }
    }

    // Check for environment variable usage (common supply chain vector)
    if (content.includes('env::var') || content.includes('std::env')) {
      findings.push({
        id: 'SOL136',
        title: 'Environment Variable Usage',
        severity: 'medium',
        description: 'Environment variables can be compromised in supply chain attacks. Prefer compile-time constants.',
        location: { file: input.path, line: 1 },
        suggestion: 'Use compile-time constants instead of runtime environment variables for security-critical values.',
        cwe: 'CWE-426',
      });
    }
  }

  return findings;
}
