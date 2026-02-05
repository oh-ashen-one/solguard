import type { Finding } from '../commands/audit.js';
import type { PatternInput } from './index.js';

/**
 * SOL144: Prediction Market Security
 * Detects vulnerabilities in prediction/betting markets (Polymarket-style)
 * 
 * Prediction market risks:
 * - Oracle resolution manipulation
 * - Market manipulation
 * - Settlement edge cases
 */
export function checkPredictionMarket(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  const rust = input.rust;
  if (!rust) return findings;

  const content = rust.content;
  const lines = content.split('\n');

  lines.forEach((line, i) => {
    // Check for market resolution
    if (/resolve.*market|settle.*outcome|declare.*winner/i.test(line)) {
      const nearbyContent = lines.slice(Math.max(0, i - 20), Math.min(lines.length, i + 20)).join('\n');
      
      // Check for oracle decentralization
      if (!/oracle|uma|realit|multisig.*resolve/i.test(nearbyContent)) {
        findings.push({
          id: 'SOL144',
          name: 'Centralized Market Resolution',
          severity: 'critical',
          message: 'Single entity resolving markets can manipulate outcomes',
          location: `${input.path}:${i + 1}`,
          snippet: line.trim(),
          fix: 'Use decentralized oracle (UMA, Reality.eth) or multi-oracle consensus',
        });
      }

      // Check for dispute mechanism
      if (!/dispute|challenge|appeal/i.test(nearbyContent)) {
        findings.push({
          id: 'SOL144',
          name: 'No Dispute Mechanism',
          severity: 'high',
          message: 'Market resolution without dispute period can be final even if wrong',
          location: `${input.path}:${i + 1}`,
          snippet: line.trim(),
          fix: 'Add dispute period where resolution can be challenged with bond',
        });
      }
    }

    // Check for market creation
    if (/create.*market|new.*prediction|init.*market/i.test(line)) {
      const nearbyContent = lines.slice(Math.max(0, i - 15), Math.min(lines.length, i + 15)).join('\n');
      
      // Check for resolution criteria
      if (!/resolution.*source|outcome.*criteria|settle.*rule/i.test(nearbyContent)) {
        findings.push({
          id: 'SOL144',
          name: 'Resolution Criteria Missing',
          severity: 'high',
          message: 'Market without clear resolution criteria leads to disputes',
          location: `${input.path}:${i + 1}`,
          snippet: line.trim(),
          fix: 'Define resolution source and criteria at market creation',
        });
      }

      // Check for edge case handling
      if (!/invalid|void|cancel.*market/i.test(nearbyContent)) {
        findings.push({
          id: 'SOL144',
          name: 'No Invalid Outcome Handling',
          severity: 'medium',
          message: 'Markets need invalid/void outcome for edge cases',
          location: `${input.path}:${i + 1}`,
          snippet: line.trim(),
          fix: 'Support invalid/void resolution for ambiguous outcomes',
        });
      }
    }

    // Check for share trading
    if (/buy.*share|sell.*outcome|trade.*position/i.test(line)) {
      const nearbyContent = lines.slice(Math.max(0, i - 10), Math.min(lines.length, i + 10)).join('\n');
      
      // Check for trading cutoff
      if (!/cutoff|close.*trading|stop.*trading/i.test(nearbyContent)) {
        findings.push({
          id: 'SOL144',
          name: 'No Trading Cutoff',
          severity: 'high',
          message: 'Trading should stop before outcome is known to prevent insider trades',
          location: `${input.path}:${i + 1}`,
          snippet: line.trim(),
          fix: 'Implement trading cutoff before event resolution time',
        });
      }
    }

    // Check for liquidity provision
    if (/add.*liquidity|provide.*liquidity|lp.*market/i.test(line)) {
      const nearbyContent = lines.slice(Math.max(0, i - 10), Math.min(lines.length, i + 10)).join('\n');
      
      if (!/impermanent|divergence|lp.*risk/i.test(nearbyContent)) {
        findings.push({
          id: 'SOL144',
          name: 'LP Risk Not Disclosed',
          severity: 'low',
          message: 'LPs in prediction markets face divergence loss risk',
          location: `${input.path}:${i + 1}`,
          snippet: line.trim(),
          fix: 'Document LP risks - prediction markets can have total LP loss',
        });
      }
    }
  });

  return findings;
}
