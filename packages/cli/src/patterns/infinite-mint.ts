import type { Finding } from '../commands/audit.js';
import type { PatternInput } from './index.js';

/**
 * SOL134: Infinite Mint Vulnerability
 * Detects vulnerabilities that could allow unlimited token minting
 * Real-world: Cashio ($52M exploit)
 */
export function checkInfiniteMint(input: PatternInput): Finding[] {
  const findings: Finding[] = [];

  if (input.rust?.content) {
    const content = input.rust.content;
    const lines = content.split('\n');

    // Check for minting operations
    const mintPatterns = [
      /mint_to|token::mint/i,
      /MintTo|mint_tokens/i,
      /\.mint\(|\.mint_to\(/i,
    ];

    const hasMinting = mintPatterns.some(p => p.test(content));

    if (hasMinting) {
      // Check for root of trust validation (Cashio attack vector)
      if (!content.includes('collateral') || !content.includes('verify')) {
        for (let i = 0; i < lines.length; i++) {
          if (lines[i].match(/mint_to|MintTo/i)) {
            findings.push({
              id: 'SOL134',
              title: 'Mint Without Collateral Verification',
              severity: 'critical',
              description: 'Minting operations must verify collateral backing to prevent infinite mint attacks.',
              location: { file: input.path, line: i + 1 },
              suggestion: 'Establish root of trust: verify collateral account ownership chains all the way to a trusted source.',
              cwe: 'CWE-284',
            });
            break;
          }
        }
      }

      // Check for mint authority validation
      if (!content.includes('mint_authority') && !content.includes('authority ==')) {
        findings.push({
          id: 'SOL134',
          title: 'Missing Mint Authority Validation',
          severity: 'critical',
          description: 'Mint operations must validate the mint authority to prevent unauthorized minting.',
          location: { file: input.path, line: 1 },
          suggestion: 'Validate mint authority: require!(mint.mint_authority == expected_authority.key(), UnauthorizedMint)',
          cwe: 'CWE-284',
        });
      }

      // Check for supply cap
      if (!content.includes('max_supply') && !content.includes('supply_cap')) {
        findings.push({
          id: 'SOL134',
          title: 'No Maximum Supply Cap',
          severity: 'high',
          description: 'Tokens should have a maximum supply cap to prevent unlimited inflation.',
          location: { file: input.path, line: 1 },
          suggestion: 'Add supply cap: require!(mint.supply + amount <= MAX_SUPPLY, SupplyCapExceeded)',
          cwe: 'CWE-770',
        });
      }

      // Check for nested account validation (Cashio-specific)
      if (content.includes('crate_') || content.includes('collateral_')) {
        if (!content.includes('validate_account_chain') && !content.includes('verify_path')) {
          findings.push({
            id: 'SOL134',
            title: 'Unvalidated Nested Account Structure',
            severity: 'critical',
            description: 'Nested account structures (like Cashio\'s crate system) must validate the entire chain to a trusted root.',
            location: { file: input.path, line: 1 },
            suggestion: 'Validate full account chain: verify each level from the input account back to a trusted root account.',
            cwe: 'CWE-345',
          });
        }
      }
    }
  }

  return findings;
}
