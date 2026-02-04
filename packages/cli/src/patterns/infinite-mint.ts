import type { Finding } from '../commands/audit.js';
import type { PatternInput } from './index.js';

/**
 * SOL134: Infinite Mint Vulnerability (Cashio Exploit - $52M)
 * 
 * Detects vulnerabilities where tokens can be minted without proper
 * collateral validation, enabling infinite mint attacks.
 */
export function checkInfiniteMint(input: PatternInput): Finding[] {
  const findings: Finding[] = [];

  if (!input.rust || !input.rust.files) return findings;

  for (const file of input.rust.files) {
    const lines = file.lines;
    const content = file.content;

    lines.forEach((line, index) => {
      const lineNum = index + 1;
      const lineLower = line.toLowerCase();

      // Pattern 1: Mint without collateral root validation
      if (lineLower.includes('mint_to') || lineLower.includes('mint_tokens')) {
        const fnStart = Math.max(0, index - 30);
        const fnEnd = Math.min(lines.length, index + 10);
        const fnBody = lines.slice(fnStart, fnEnd).join('\n').toLowerCase();
        
        if ((fnBody.includes('collateral') || fnBody.includes('backing')) &&
            !fnBody.includes('root') && !fnBody.includes('merkle') && 
            !fnBody.includes('verify_collateral')) {
          findings.push({
            id: `SOL134-${findings.length + 1}`,
            pattern: 'Infinite Mint Vulnerability',
            severity: 'critical',
            title: 'Mint with unverified collateral chain',
            description: 'Token minting uses collateral but does not verify the root/source of collateral. Attacker can create fake collateral accounts to mint tokens (Cashio exploit).',
            location: { file: file.path, line: lineNum },
            suggestion: 'Verify collateral back to a trusted root: validate collateral.mint against whitelisted tokens.',
          });
        }
      }

      // Pattern 2: Collateral account without mint verification
      if (lineLower.includes('collateral') && line.includes('AccountInfo')) {
        if (!content.includes('collateral.mint') && !content.includes('verify_mint')) {
          findings.push({
            id: `SOL134-${findings.length + 1}`,
            pattern: 'Infinite Mint Vulnerability',
            severity: 'critical',
            title: 'Collateral account mint not verified',
            description: 'Collateral token account passed without verifying its mint. Attacker can pass worthless token as collateral.',
            location: { file: file.path, line: lineNum },
            suggestion: 'Add: require!(collateral.mint == expected_mint, InvalidCollateral)',
          });
        }
      }

      // Pattern 3: LP token validation missing
      if ((lineLower.includes('lp_token') || lineLower.includes('pool_token')) && 
          (lineLower.includes('deposit') || lineLower.includes('collateral'))) {
        const fnEnd = Math.min(lines.length, index + 20);
        const fnBody = lines.slice(index, fnEnd).join('\n').toLowerCase();
        
        if (!fnBody.includes('pool.mint') && !fnBody.includes('verify_lp') && 
            !fnBody.includes('pool_state')) {
          findings.push({
            id: `SOL134-${findings.length + 1}`,
            pattern: 'Infinite Mint Vulnerability',
            severity: 'critical',
            title: 'LP token used as collateral without pool verification',
            description: 'LP tokens used as collateral without verifying they belong to the expected pool. Attacker can create fake LP tokens.',
            location: { file: file.path, line: lineNum },
            suggestion: 'Verify LP token derives from expected pool: check pool account and mint relationship.',
          });
        }
      }

      // Pattern 4: Uncapped mint supply
      if (lineLower.includes('mint') && !lineLower.includes('mint_authority')) {
        const fileContent = content.toLowerCase();
        if (!fileContent.includes('max_supply') && !fileContent.includes('cap') && 
            !fileContent.includes('supply_limit')) {
          findings.push({
            id: `SOL134-${findings.length + 1}`,
            pattern: 'Infinite Mint Vulnerability',
            severity: 'high',
            title: 'No maximum supply cap on mint',
            description: 'Token mint has no maximum supply cap. Even with proper collateral, bugs could allow unlimited minting.',
            location: { file: file.path, line: lineNum },
            suggestion: 'Add supply cap: require!(mint.supply + amount <= config.max_supply)',
          });
        }
      }

      // Pattern 5: Saber/swap account validation (specific to Cashio)
      if (lineLower.includes('saber') || lineLower.includes('swap') || lineLower.includes('arrow')) {
        if (line.includes('AccountInfo') && !content.includes('owner =')) {
          findings.push({
            id: `SOL134-${findings.length + 1}`,
            pattern: 'Infinite Mint Vulnerability',
            severity: 'critical',
            title: 'Swap/pool account without owner verification',
            description: 'External swap account (Saber/Arrow) used without owner verification. Attacker can pass fake swap state.',
            location: { file: file.path, line: lineNum },
            suggestion: 'Verify account owner: #[account(owner = saber_stable_swap::ID)]',
          });
        }
      }
    });
  }

  return findings;
}
