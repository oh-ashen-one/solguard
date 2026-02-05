import type { Finding } from '../commands/audit.js';
import type { PatternInput } from './index.js';

export function checkOracleSafety(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  const content = input.rust?.content || '';
  const fileName = input.rust?.filePath || 'unknown';

  // Check for oracle integration patterns
  const oracleProviders = [
    { pattern: /pyth/gi, name: 'Pyth' },
    { pattern: /switchboard/gi, name: 'Switchboard' },
    { pattern: /chainlink/gi, name: 'Chainlink' },
    { pattern: /oracle/gi, name: 'Oracle' },
    { pattern: /price_feed/gi, name: 'Price Feed' },
  ];

  for (const { pattern, name } of oracleProviders) {
    const matches = [...content.matchAll(pattern)];
    if (matches.length === 0) continue;

    for (const match of matches) {
      const contextEnd = Math.min(content.length, match.index! + 2000);
      const functionContext = content.substring(match.index!, contextEnd);
      
      // Check for price confidence validation (Pyth specific)
      if (name === 'Pyth' && !functionContext.includes('confidence') && 
          !functionContext.includes('conf')) {
        const lineNumber = content.substring(0, match.index).split('\n').length;
        findings.push({
          id: 'SOL164',
          title: 'Pyth Price Without Confidence Check',
          severity: 'critical',
          description: 'Pyth oracle price used without confidence interval validation. Low confidence prices can be manipulated.',
          location: { file: fileName, line: lineNumber },
          recommendation: 'Check price.conf / price.price ratio is within acceptable threshold (e.g., < 1%).',
        });
      }

      // Check for staleness validation
      const stalenessPatterns = ['publish_time', 'last_updated', 'timestamp', 'valid_slot', 'age'];
      const hasStalenessCheck = stalenessPatterns.some(p => functionContext.includes(p));
      
      if (!hasStalenessCheck) {
        const lineNumber = content.substring(0, match.index).split('\n').length;
        findings.push({
          id: 'SOL164',
          title: `${name} Without Staleness Check`,
          severity: 'critical',
          description: `${name} oracle data used without staleness validation. Stale prices can be exploited in market conditions.`,
          location: { file: fileName, line: lineNumber },
          recommendation: 'Validate oracle data age against maximum allowed staleness (e.g., 30 seconds).',
        });
      }

      // Check for price bounds validation
      if (!functionContext.includes('min_price') && !functionContext.includes('max_price') &&
          !functionContext.includes('bounds') && !functionContext.includes('circuit_breaker')) {
        const lineNumber = content.substring(0, match.index).split('\n').length;
        findings.push({
          id: 'SOL164',
          title: 'Oracle Price Without Bounds Check',
          severity: 'high',
          description: 'Oracle price used without sanity bounds. Extreme price movements (flash crashes) can be exploited.',
          location: { file: fileName, line: lineNumber },
          recommendation: 'Implement circuit breakers: reject prices that deviate too far from historical TWAP.',
        });
      }
    }
  }

  // Check for single oracle dependency
  const oracleCount = oracleProviders.filter(({ pattern }) => pattern.test(content)).length;
  if (oracleCount === 1 && (content.includes('liquidate') || content.includes('borrow'))) {
    findings.push({
      id: 'SOL164',
      title: 'Single Oracle Dependency',
      severity: 'high',
      description: 'Protocol relies on single oracle source for critical operations. Oracle manipulation or downtime could be catastrophic.',
      location: { file: fileName, line: 1 },
      recommendation: 'Consider using multiple oracles with median/fallback logic for critical price feeds.',
    });
  }

  // Check for LP token pricing safety
  if (content.includes('lp_token') || content.includes('liquidity_token')) {
    const lpPricePattern = /lp_price|lp_value|pool_value/gi;
    const matches = [...content.matchAll(lpPricePattern)];
    
    for (const match of matches) {
      const contextEnd = Math.min(content.length, match.index! + 1000);
      const functionContext = content.substring(match.index!, contextEnd);
      
      if (!functionContext.includes('reserve') && !functionContext.includes('fair_price') &&
          !functionContext.includes('virtual_price')) {
        const lineNumber = content.substring(0, match.index).split('\n').length;
        findings.push({
          id: 'SOL164',
          title: 'LP Token Naive Pricing',
          severity: 'critical',
          description: 'LP token price may be calculated naively. The OtterSec $200M disclosure showed LP oracle manipulation risks.',
          location: { file: fileName, line: lineNumber },
          recommendation: 'Use fair LP pricing: price = 2 * sqrt(reserve_a * reserve_b * price_a * price_b) / total_supply',
        });
      }
    }
  }

  // Check for TWAP implementation
  if (content.includes('twap') || content.includes('TWAP') || content.includes('time_weighted')) {
    const twapPattern = /twap|time_weighted/gi;
    const matches = [...content.matchAll(twapPattern)];
    
    for (const match of matches) {
      const contextEnd = Math.min(content.length, match.index! + 1000);
      const functionContext = content.substring(match.index!, contextEnd);
      
      // Check for manipulation resistance
      if (!functionContext.includes('cumulative') && !functionContext.includes('accumulator') &&
          !functionContext.includes('observation')) {
        const lineNumber = content.substring(0, match.index).split('\n').length;
        findings.push({
          id: 'SOL164',
          title: 'TWAP Without Cumulative Price',
          severity: 'high',
          description: 'TWAP calculation may not use cumulative prices. Simple averages can still be manipulated.',
          location: { file: fileName, line: lineNumber },
          recommendation: 'Implement TWAP using cumulative price accumulators to resist manipulation.',
        });
      }

      // Check for sufficient TWAP period
      if (!functionContext.includes('period') && !functionContext.includes('window') &&
          !functionContext.includes('duration')) {
        const lineNumber = content.substring(0, match.index).split('\n').length;
        findings.push({
          id: 'SOL164',
          title: 'TWAP Period Not Specified',
          severity: 'medium',
          description: 'TWAP without explicit time period. Short periods are still vulnerable to manipulation.',
          location: { file: fileName, line: lineNumber },
          recommendation: 'Use TWAP periods of at least 10-30 minutes for manipulation resistance.',
        });
      }
    }
  }

  // Check for negative price handling
  if (content.includes('price') && (content.includes('i64') || content.includes('i128'))) {
    const pricePattern = /price\s*:\s*i(?:64|128)/gi;
    const matches = [...content.matchAll(pricePattern)];
    
    for (const match of matches) {
      const contextEnd = Math.min(content.length, match.index! + 500);
      const functionContext = content.substring(match.index!, contextEnd);
      
      if (!functionContext.includes('> 0') && !functionContext.includes('>= 0') &&
          !functionContext.includes('positive')) {
        const lineNumber = content.substring(0, match.index).split('\n').length;
        findings.push({
          id: 'SOL164',
          title: 'Signed Price Without Validation',
          severity: 'high',
          description: 'Signed integer used for price without validating non-negative. Negative prices can cause unexpected behavior.',
          location: { file: fileName, line: lineNumber },
          recommendation: 'Validate price > 0 before use in calculations.',
        });
      }
    }
  }

  return findings;
}
