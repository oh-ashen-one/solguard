import type { Finding } from '../commands/audit.js';
import type { PatternInput } from './index.js';

export function checkStaleData(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  const content = input.rust?.content || '';
  const fileName = input.rust?.filePath || 'unknown';

  // Check for missing staleness checks in oracle data
  const oracleUsagePattern = /(?:get_price|load_price|fetch_price|oracle_price|price_feed)\s*\(/gi;
  const stalenessCheckPatterns = [
    /\.last_update_time/i,
    /\.timestamp/i,
    /staleness/i,
    /max_age/i,
    /is_stale/i,
    /check_stale/i,
    /\.slot/i,
    /\.publish_time/i,
  ];

  const oracleMatches = [...content.matchAll(oracleUsagePattern)];
  for (const match of oracleMatches) {
    const contextStart = Math.max(0, match.index! - 500);
    const contextEnd = Math.min(content.length, match.index! + 500);
    const context = content.substring(contextStart, contextEnd);
    
    const hasStalenessCheck = stalenessCheckPatterns.some(p => p.test(context));
    if (!hasStalenessCheck) {
      const lineNumber = content.substring(0, match.index).split('\n').length;
      findings.push({
        id: 'SOL152',
        title: 'Missing Oracle Staleness Check',
        severity: 'critical',
        description: 'Oracle price data is used without checking if it is stale. Attackers can exploit stale prices to manipulate protocol actions. The Mango Markets exploit used stale price data to drain $116M.',
        location: { file: fileName, line: lineNumber },
        recommendation: 'Always check oracle data freshness by validating last_update_time or slot against current timestamp. Reject transactions using stale data.',
      });
    }
  }

  // Check for cached data usage without refresh
  const cachePatterns = [
    /let\s+(?:mut\s+)?(\w+)\s*=.*?\.data\s*\(\)/g,
    /\.borrow\(\).*?\.data/g,
    /cached_\w+/gi,
  ];

  for (const pattern of cachePatterns) {
    const matches = [...content.matchAll(pattern)];
    for (const match of matches) {
      const contextEnd = Math.min(content.length, match.index! + 1000);
      const followingCode = content.substring(match.index!, contextEnd);
      
      // Check if data is used much later without refresh
      if (followingCode.includes('invoke') && !followingCode.includes('reload') && !followingCode.includes('refresh')) {
        const lineNumber = content.substring(0, match.index).split('\n').length;
        findings.push({
          id: 'SOL152',
          title: 'Potentially Stale Account Data in CPI',
          severity: 'medium',
          description: 'Account data is loaded and then used in a CPI call without verification that the data has not changed. Cross-program invocations can modify account data.',
          location: { file: fileName, line: lineNumber },
          recommendation: 'Reload and revalidate account data after any CPI call before using it for subsequent operations.',
        });
      }
    }
  }

  // Check for missing slot/block checks in time-sensitive operations
  const timeSensitivePatterns = [
    /liquidat/gi,
    /settle/gi,
    /expire/gi,
    /deadline/gi,
    /auction/gi,
  ];

  for (const pattern of timeSensitivePatterns) {
    if (pattern.test(content) && !content.includes('Clock::get') && !content.includes('current_slot')) {
      findings.push({
        id: 'SOL152',
        title: 'Time-Sensitive Operation Without Slot Check',
        severity: 'high',
        description: 'Time-sensitive operation detected without apparent slot or clock validation. Operations like liquidations and auctions require accurate time checks.',
        location: { file: fileName, line: 1 },
        recommendation: 'Use Clock::get() to obtain current slot/timestamp and validate against operation requirements.',
      });
      break;
    }
  }

  return findings;
}
