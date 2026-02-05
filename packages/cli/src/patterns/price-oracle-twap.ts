import type { Finding } from '../commands/audit.js';
import type { PatternInput } from './index.js';

/**
 * SOL187: Price Oracle TWAP Protection
 * 
 * Detects use of spot prices instead of TWAP (Time-Weighted Average Price)
 * which is vulnerable to flash loan manipulation.
 * 
 * Real-world exploit: Mango Markets - $116M stolen via oracle manipulation
 * using spot prices.
 */
export function checkPriceOracleTwap(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  const { rust, idl, path } = input;

  if (idl) {
    const priceInstructions = idl.instructions.filter(ix =>
      ix.name.toLowerCase().includes('price') ||
      ix.name.toLowerCase().includes('oracle') ||
      ix.name.toLowerCase().includes('liquidat') ||
      ix.name.toLowerCase().includes('borrow')
    );

    for (const ix of priceInstructions) {
      const hasTwap = ix.accounts?.some(acc =>
        acc.name.toLowerCase().includes('twap') ||
        acc.name.toLowerCase().includes('average')
      );

      if (!hasTwap) {
        findings.push({
          id: 'SOL187',
          severity: 'high',
          title: 'Potential Spot Price Usage',
          description: `Instruction "${ix.name}" uses price data without apparent TWAP protection.`,
          location: { file: path, line: 1 },
          recommendation: 'Use TWAP oracles or implement price impact limits to prevent manipulation.',
        });
      }
    }
  }

  if (!rust) return findings;

  const vulnerablePatterns = [
    { pattern: /get_price\s*\(\)/, desc: 'Direct price fetch (likely spot)' },
    { pattern: /oracle\.price/, desc: 'Oracle spot price access' },
    { pattern: /current_price/, desc: 'Current (spot) price usage' },
    { pattern: /latest_price/, desc: 'Latest price (no averaging)' },
    { pattern: /price_feed\.get/, desc: 'Price feed without TWAP' },
  ];

  const lines = rust.content.split('\n');
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    for (const { pattern, desc } of vulnerablePatterns) {
      if (pattern.test(line)) {
        const context = lines.slice(Math.max(0, i - 10), Math.min(lines.length, i + 10)).join('\n');
        
        if (!context.includes('twap') && !context.includes('average') && !context.includes('ema')) {
          findings.push({
            id: 'SOL187',
            severity: 'high',
            title: 'Spot Price Without TWAP',
            description: `${desc} - vulnerable to flash loan price manipulation.`,
            location: { file: path, line: i + 1 },
            recommendation: 'Use Time-Weighted Average Price (TWAP) or Exponential Moving Average (EMA) for all price-sensitive operations.',
          });
        }
      }
    }
  }

  // Check for price impact limits
  if (rust.content.includes('price') && rust.content.includes('liquidat')) {
    if (!rust.content.includes('max_price_impact') && !rust.content.includes('price_deviation')) {
      findings.push({
        id: 'SOL187',
        severity: 'high',
        title: 'No Price Impact Limits',
        description: 'Liquidation logic without maximum price impact or deviation checks.',
        location: { file: path, line: 1 },
        recommendation: 'Implement maximum price deviation checks to reject manipulated prices.',
      });
    }
  }

  return findings;
}
