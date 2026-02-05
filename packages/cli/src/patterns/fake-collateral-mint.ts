import type { Finding } from '../commands/audit.js';
import type { PatternInput } from './index.js';

/**
 * SOL184: Fake Collateral/Mint Validation
 * 
 * Detects insufficient validation of collateral tokens that allows
 * attackers to use fake or worthless tokens as collateral.
 * 
 * Real-world exploit: Cashio - $52.8M stolen by minting CASH tokens
 * with fake collateral accounts that bypassed validation.
 */
export function checkFakeCollateralMint(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  const { rust, idl, path } = input;

  if (idl) {
    const mintInstructions = idl.instructions.filter(ix =>
      ix.name.toLowerCase().includes('mint') ||
      ix.name.toLowerCase().includes('collateral') ||
      ix.name.toLowerCase().includes('deposit')
    );

    for (const ix of mintInstructions) {
      const collateralAccounts = ix.accounts?.filter(acc =>
        acc.name.toLowerCase().includes('collateral') ||
        acc.name.toLowerCase().includes('deposit') ||
        acc.name.toLowerCase().includes('lp_token')
      );

      for (const acc of collateralAccounts || []) {
        // Check if there are constraints on the account
        // IDL-level detection is limited, but we can flag potential issues
        findings.push({
          id: 'SOL184',
          severity: 'high',
          title: 'Collateral Account Requires Validation',
          description: `Account "${acc.name}" in instruction "${ix.name}" handles collateral - ensure proper mint and owner validation.`,
          location: { file: path, line: 1 },
          recommendation: 'Verify collateral mint address against a whitelist. Validate LP token backing and pool ownership.',
        });
      }
    }
  }

  if (!rust) return findings;

  const vulnerablePatterns = [
    { pattern: /collateral_mint/, desc: 'Collateral mint reference' },
    { pattern: /lp_token.*mint/, desc: 'LP token mint' },
    { pattern: /deposit.*token/, desc: 'Deposit token handling' },
    { pattern: /backing.*asset/, desc: 'Backing asset reference' },
  ];

  const lines = rust.content.split('\n');
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    for (const { pattern, desc } of vulnerablePatterns) {
      if (pattern.test(line)) {
        const context = lines.slice(i, Math.min(lines.length, i + 30)).join('\n');
        
        // Check for proper mint validation
        const hasValidation = 
          context.includes('require!') ||
          context.includes('constraint =') ||
          context.includes('== ACCEPTED_MINT') ||
          context.includes('whitelist') ||
          context.includes('allowed_mints');

        if (!hasValidation) {
          findings.push({
            id: 'SOL184',
            severity: 'critical',
            title: 'Missing Collateral Mint Validation',
            description: `${desc} - no validation that mint is from trusted/whitelisted source.`,
            location: { file: path, line: i + 1 },
            recommendation: 'Validate collateral mint against a hardcoded or governance-controlled whitelist. Verify LP token pool ownership.',
          });
          break;
        }
      }
    }
  }

  // Check for root of trust issues
  if (rust.content.includes('collateral') && !rust.content.includes('root_of_trust')) {
    const hasChainValidation = 
      rust.content.includes('validate_chain') ||
      rust.content.includes('verify_backing') ||
      rust.content.includes('oracle') && rust.content.includes('collateral');

    if (!hasChainValidation) {
      findings.push({
        id: 'SOL184',
        severity: 'high',
        title: 'No Root of Trust for Collateral',
        description: 'Collateral handling without establishing a root of trust for validation chain.',
        location: { file: path, line: 1 },
        recommendation: 'Establish a root of trust by validating the entire collateral derivation chain.',
      });
    }
  }

  return findings;
}
