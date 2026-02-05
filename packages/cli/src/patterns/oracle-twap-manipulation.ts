import type { Finding } from '../commands/audit.js';
import type { PatternInput } from './index.js';

/**
 * SOL314: Oracle TWAP Manipulation
 * Detects vulnerabilities in time-weighted average price implementations
 * Real-world: Multiple DeFi exploits via TWAP manipulation
 */
export function checkOracleTwapManipulation(input: PatternInput): Finding[] {
  const findings: Finding[] = [];

  if (input.rust?.content) {
    const content = input.rust.content;
    const lines = content.split('\n');

    // Detect TWAP/oracle patterns
    const hasTwap = /twap|time_weighted|moving_average|cumulative_price/i.test(content);
    const hasOracle = /oracle|price_feed|get_price|pyth|switchboard/i.test(content);

    if (hasTwap || hasOracle) {
      // Check for TWAP window size
      if (hasTwap) {
        for (let i = 0; i < lines.length; i++) {
          const line = lines[i];
          
          // Check for short TWAP windows
          const windowMatch = line.match(/window|period|interval.*?(\d+)/i);
          if (windowMatch) {
            const windowSize = parseInt(windowMatch[1]);
            // Assuming seconds, < 600 (10 min) is risky
            if (windowSize > 0 && windowSize < 600) {
              findings.push({
                id: 'SOL314',
                title: 'Short TWAP Window',
                severity: 'high',
                description: `TWAP window of ${windowSize} is too short. Vulnerable to manipulation.`,
                location: { file: input.path, line: i + 1 },
                suggestion: 'Use longer TWAP windows: 30+ minutes for lending, 4+ hours for liquidations',
                cwe: 'CWE-682',
              });
              break;
            }
          }
        }
      }

      // Check for cumulative price overflow
      if (content.includes('cumulative') && content.includes('price')) {
        if (!content.includes('u128') && !content.includes('U256') && !content.includes('checked_')) {
          findings.push({
            id: 'SOL314',
            title: 'TWAP Accumulator Overflow Risk',
            severity: 'high',
            description: 'Cumulative price accumulators can overflow without u128/U256.',
            location: { file: input.path, line: 1 },
            suggestion: 'Use u128: cumulative_price: u128 to handle long-term accumulation',
            cwe: 'CWE-190',
          });
        }
      }

      // Check for single-source TWAP
      if (hasTwap && !content.includes('sources') && !content.includes('aggregate')) {
        findings.push({
          id: 'SOL314',
          title: 'Single-Source TWAP',
          severity: 'medium',
          description: 'Using single price source for TWAP is vulnerable to source manipulation.',
          location: { file: input.path, line: 1 },
          suggestion: 'Aggregate sources: price = median(pyth_price, switchboard_price, amm_twap)',
          cwe: 'CWE-346',
        });
      }

      // Check for TWAP update frequency
      if (content.includes('update') && (hasTwap || hasOracle)) {
        for (let i = 0; i < lines.length; i++) {
          const line = lines[i];
          if (line.includes('update') && line.includes('price')) {
            const contextLines = lines.slice(i, Math.min(i + 10, lines.length)).join('\n');
            if (!contextLines.includes('last_update') && !contextLines.includes('timestamp')) {
              findings.push({
                id: 'SOL314',
                title: 'No Update Frequency Limit',
                severity: 'medium',
                description: 'TWAP updates should have minimum intervals to prevent manipulation.',
                location: { file: input.path, line: i + 1 },
                suggestion: 'Add limit: require!(clock.unix_timestamp - last_update >= MIN_UPDATE_INTERVAL)',
                cwe: 'CWE-799',
              });
              break;
            }
          }
        }
      }

      // Check for deviation bounds
      if (!content.includes('deviation') && !content.includes('band') && !content.includes('tolerance')) {
        findings.push({
          id: 'SOL314',
          title: 'No Price Deviation Bounds',
          severity: 'high',
          description: 'TWAP should reject updates that deviate too much from current price.',
          location: { file: input.path, line: 1 },
          suggestion: 'Add bounds: require!(new_price.within_percent(current_price, MAX_DEVIATION), PriceDeviation)',
          cwe: 'CWE-20',
        });
      }

      // Check for observation array bounds
      if (content.includes('observation') || content.includes('sample')) {
        if (!content.includes('cardinality') && !content.includes('max_') && !content.includes('capacity')) {
          findings.push({
            id: 'SOL314',
            title: 'Unbounded Observation Array',
            severity: 'medium',
            description: 'TWAP observation arrays should have bounded size.',
            location: { file: input.path, line: 1 },
            suggestion: 'Use ring buffer: observations[index % MAX_OBSERVATIONS] = new_observation',
            cwe: 'CWE-770',
          });
        }
      }

      // Check for timestamp manipulation
      if (content.includes('timestamp') && hasOracle) {
        for (let i = 0; i < lines.length; i++) {
          if (lines[i].includes('timestamp') && !lines[i].includes('//')) {
            const contextLines = lines.slice(i, Math.min(i + 8, lines.length)).join('\n');
            if (!contextLines.includes('clock.unix_timestamp') && !contextLines.includes('Clock::get')) {
              findings.push({
                id: 'SOL314',
                title: 'Unverified Oracle Timestamp',
                severity: 'high',
                description: 'Oracle timestamps should be validated against on-chain clock.',
                location: { file: input.path, line: i + 1 },
                suggestion: 'Validate time: require!(abs_diff(oracle.timestamp, clock.unix_timestamp) < MAX_CLOCK_DRIFT)',
                cwe: 'CWE-346',
              });
              break;
            }
          }
        }
      }

      // Check for liquidity-weighted pricing
      if ((content.includes('amm') || content.includes('pool')) && hasOracle) {
        if (!content.includes('liquidity') && !content.includes('depth')) {
          findings.push({
            id: 'SOL314',
            title: 'No Liquidity Weighting',
            severity: 'medium',
            description: 'AMM-based oracles should weight by liquidity to resist manipulation.',
            location: { file: input.path, line: 1 },
            suggestion: 'Weight by liquidity: effective_price = sum(price_i * liquidity_i) / total_liquidity',
            cwe: 'CWE-682',
          });
        }
      }

      // Check for TWAP vs spot usage context
      for (let i = 0; i < lines.length; i++) {
        const line = lines[i];
        if ((line.includes('liquidat') || line.includes('borrow') || line.includes('collateral')) &&
            line.includes('price') && !line.includes('twap')) {
          findings.push({
            id: 'SOL314',
            title: 'Spot Price in Critical Operation',
            severity: 'high',
            description: 'Liquidation/borrow operations should use TWAP, not spot prices.',
            location: { file: input.path, line: i + 1 },
            suggestion: 'Use TWAP: let collateral_value = amount * twap_price instead of spot price',
            cwe: 'CWE-346',
          });
          break;
        }
      }
    }
  }

  return findings;
}
