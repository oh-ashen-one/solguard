import type { Finding } from '../commands/audit.js';
import type { PatternInput } from './index.js';

/**
 * SOL302: Malicious Lending Market Detection
 * Detects vulnerabilities allowing fake/malicious lending market creation
 * Real-world: Solend malicious lending market incident
 */
export function checkMaliciousLendingMarket(input: PatternInput): Finding[] {
  const findings: Finding[] = [];

  if (input.rust?.content) {
    const content = input.rust.content;
    const lines = content.split('\n');

    // Detect lending protocol patterns
    const isLendingProtocol = /lending_market|reserve|obligation|collateral|borrow/i.test(content);

    if (isLendingProtocol) {
      // Check for market authority validation
      for (let i = 0; i < lines.length; i++) {
        const line = lines[i];

        // Creating market without proper authority checks
        if (line.includes('create_market') || line.includes('init_market') || line.includes('initialize_market')) {
          const contextLines = lines.slice(i, Math.min(i + 20, lines.length)).join('\n');
          if (!contextLines.includes('owner') && !contextLines.includes('authority') && !contextLines.includes('admin')) {
            findings.push({
              id: 'SOL302',
              title: 'Market Creation Without Authority',
              severity: 'critical',
              description: 'Lending markets can be created without proper authority validation.',
              location: { file: input.path, line: i + 1 },
              suggestion: 'Require authority: #[account(constraint = authority.key() == LENDING_MARKET_OWNER)]',
              cwe: 'CWE-284',
            });
            break;
          }
        }
      }

      // Check for oracle source validation
      if (content.includes('oracle') || content.includes('price_feed')) {
        if (!content.includes('pyth') && !content.includes('switchboard') && !content.includes('chainlink')) {
          findings.push({
            id: 'SOL302',
            title: 'Unvalidated Oracle Source',
            severity: 'critical',
            description: 'Lending markets must validate oracle sources to prevent fake price feeds.',
            location: { file: input.path, line: 1 },
            suggestion: 'Validate oracle: require!(oracle.owner() == PYTH_PROGRAM_ID, InvalidOracle)',
            cwe: 'CWE-346',
          });
        }

        // Check for oracle staleness
        if (!content.includes('stale') && !content.includes('last_update') && !content.includes('timestamp')) {
          findings.push({
            id: 'SOL302',
            title: 'No Oracle Staleness Check',
            severity: 'high',
            description: 'Oracle prices must be checked for staleness to prevent using outdated data.',
            location: { file: input.path, line: 1 },
            suggestion: 'Add staleness check: require!(clock.unix_timestamp - price.timestamp < MAX_ORACLE_AGE, StaleOracle)',
            cwe: 'CWE-672',
          });
        }
      }

      // Check for reserve initialization validation
      if (content.includes('reserve') && content.includes('init')) {
        if (!content.includes('market_authority') || !content.includes('validate_reserve')) {
          findings.push({
            id: 'SOL302',
            title: 'Reserve Without Market Validation',
            severity: 'high',
            description: 'Reserves must be validated against the lending market to prevent rogue reserves.',
            location: { file: input.path, line: 1 },
            suggestion: 'Validate reserve belongs to market: require!(reserve.lending_market == lending_market.key())',
            cwe: 'CWE-284',
          });
        }
      }

      // Check for collateral factor manipulation
      if (content.includes('collateral_factor') || content.includes('ltv')) {
        for (let i = 0; i < lines.length; i++) {
          if (lines[i].includes('collateral_factor') && !lines.slice(i, i + 5).join('').includes('MAX_')) {
            findings.push({
              id: 'SOL302',
              title: 'Unbounded Collateral Factor',
              severity: 'high',
              description: 'Collateral factors must have maximum bounds to prevent infinite leverage.',
              location: { file: input.path, line: i + 1 },
              suggestion: 'Bound collateral factor: require!(collateral_factor <= MAX_COLLATERAL_FACTOR, InvalidFactor)',
              cwe: 'CWE-20',
            });
            break;
          }
        }
      }

      // Check for market isolation
      if (!content.includes('isolated') && !content.includes('cross_margin') && content.includes('borrow')) {
        findings.push({
          id: 'SOL302',
          title: 'No Market Isolation',
          severity: 'medium',
          description: 'Consider implementing isolated markets to contain risk from malicious assets.',
          location: { file: input.path, line: 1 },
          suggestion: 'Add isolation mode: if reserve.is_isolated { validate_isolated_borrow(obligation)? }',
          cwe: 'CWE-653',
        });
      }
    }
  }

  return findings;
}
