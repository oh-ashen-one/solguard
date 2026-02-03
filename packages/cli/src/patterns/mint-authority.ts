import type { Finding } from '../commands/audit.js';
import type { PatternInput } from './index.js';

/**
 * SOL078: Token Mint Authority Security
 * Detects vulnerabilities in token mint authority handling
 */
export function checkMintAuthority(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  const rust = input.rust;

  if (!rust || !rust.content) return findings;

  const hasMint = rust.content.includes('Mint') || 
                  rust.content.includes('mint_authority') ||
                  rust.content.includes('MintTo');

  if (!hasMint) return findings;

  // Check for mint without authority validation
  if (rust.content.includes('MintTo') || rust.content.includes('mint_to')) {
    if (!rust.content.includes('mint_authority') && 
        !rust.content.includes('authority.key()')) {
      findings.push({
        id: 'SOL078',
        severity: 'critical',
        title: 'Mint Without Authority Validation',
        description: 'Token minting without explicit mint authority check',
        location: input.path,
        recommendation: 'Verify mint authority matches expected signer before minting',
      });
    }
  }

  // Check for supply caps
  if (rust.content.includes('mint_to') && !rust.content.includes('max_supply')) {
    if (!rust.content.includes('supply') || !rust.content.includes('>=')) {
      findings.push({
        id: 'SOL078',
        severity: 'high',
        title: 'Unlimited Token Minting',
        description: 'Token minting without supply cap enforcement',
        location: input.path,
        recommendation: 'Implement max supply check before minting new tokens',
      });
    }
  }

  // Check for mint authority transfer
  if (rust.content.includes('SetAuthority') && rust.content.includes('MintTokens')) {
    if (!rust.content.includes('current_authority')) {
      findings.push({
        id: 'SOL078',
        severity: 'high',
        title: 'Mint Authority Transfer Without Validation',
        description: 'Mint authority being transferred without current authority check',
        location: input.path,
        recommendation: 'Verify current_authority is signer before authority transfer',
      });
    }
  }

  // Check for mint authority revocation
  if (rust.content.includes('mint_authority') && rust.content.includes('None')) {
    if (!rust.content.includes('is_signer') && !rust.content.includes('confirm')) {
      findings.push({
        id: 'SOL078',
        severity: 'medium',
        title: 'Irreversible Mint Authority Revocation',
        description: 'Setting mint authority to None is permanent and cannot be undone',
        location: input.path,
        recommendation: 'Ensure mint authority revocation is intentional with confirmation',
      });
    }
  }

  // Check for decimal mismatch in minting
  if (rust.content.includes('mint_to') && rust.content.includes('decimals')) {
    if (!rust.content.includes('10_u64.pow') && !rust.content.includes('checked_mul')) {
      findings.push({
        id: 'SOL078',
        severity: 'medium',
        title: 'Potential Decimal Mismatch in Minting',
        description: 'Minting without proper decimal scaling may cause precision issues',
        location: input.path,
        recommendation: 'Scale amounts by 10^decimals when minting tokens',
      });
    }
  }

  // Check for PDA mint authority
  if (rust.content.includes('mint_authority') && rust.content.includes('find_program_address')) {
    if (!rust.content.includes('invoke_signed')) {
      findings.push({
        id: 'SOL078',
        severity: 'medium',
        title: 'PDA Mint Authority Without Signed Invoke',
        description: 'PDA set as mint authority but invoke_signed not used',
        location: input.path,
        recommendation: 'Use invoke_signed with PDA seeds when PDA is mint authority',
      });
    }
  }

  return findings;
}
