import type { Finding } from '../commands/audit.js';
import type { PatternInput } from './index.js';

/**
 * SOL145: Cross-Margin Security
 * Detects vulnerabilities in cross-margin/portfolio margin systems
 * 
 * Cross-margin risks:
 * - Correlation assumptions
 * - Cascading liquidations
 * - Risk calculation errors
 */
export function checkCrossMargin(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  const rust = input.rust;
  if (!rust) return findings;

  const content = rust.content;
  const lines = content.split('\n');

  lines.forEach((line, i) => {
    // Check for cross-margin calculation
    if (/cross.*margin|portfolio.*margin|net.*margin/i.test(line)) {
      const nearbyContent = lines.slice(Math.max(0, i - 20), Math.min(lines.length, i + 20)).join('\n');
      
      // Check for correlation assumptions
      if (!/correlation|hedge.*factor|offset/i.test(nearbyContent)) {
        findings.push({
          id: 'SOL145',
          name: 'Correlation Not Modeled',
          severity: 'high',
          message: 'Cross-margin without correlation modeling can underestimate risk',
          location: `${input.path}:${i + 1}`,
          snippet: line.trim(),
          fix: 'Model asset correlations and apply haircuts for offsetting positions',
        });
      }

      // Check for stress testing
      if (!/stress|scenario|extreme|tail.*risk/i.test(nearbyContent)) {
        findings.push({
          id: 'SOL145',
          name: 'No Stress Testing',
          severity: 'medium',
          message: 'Cross-margin should account for correlation breakdown in stress',
          location: `${input.path}:${i + 1}`,
          snippet: line.trim(),
          fix: 'Add stress scenarios where correlations approach 1 during market stress',
        });
      }
    }

    // Check for account health calculation
    if (/account.*health|margin.*ratio|free.*margin/i.test(line)) {
      const nearbyContent = lines.slice(Math.max(0, i - 15), Math.min(lines.length, i + 15)).join('\n');
      
      // Check for unrealized PnL handling
      if (!/unrealized|pnl|mark.*to.*market/i.test(nearbyContent)) {
        findings.push({
          id: 'SOL145',
          name: 'Unrealized PnL Not Included',
          severity: 'high',
          message: 'Account health should include unrealized PnL for accurate risk',
          location: `${input.path}:${i + 1}`,
          snippet: line.trim(),
          fix: 'Include mark-to-market unrealized PnL in margin calculations',
        });
      }

      // Check for isolated positions
      if (!/isolated|segregate|separate.*margin/i.test(nearbyContent)) {
        findings.push({
          id: 'SOL145',
          name: 'No Position Isolation Option',
          severity: 'low',
          message: 'Consider offering isolated margin for high-risk positions',
          location: `${input.path}:${i + 1}`,
          snippet: line.trim(),
          fix: 'Allow users to isolate risky positions from cross-margin pool',
        });
      }
    }

    // Check for collateral management
    if (/collateral.*type|multi.*collateral|accept.*token/i.test(line)) {
      const nearbyContent = lines.slice(Math.max(0, i - 15), Math.min(lines.length, i + 15)).join('\n');
      
      // Check for collateral haircuts
      if (!/haircut|discount.*factor|collateral.*weight/i.test(nearbyContent)) {
        findings.push({
          id: 'SOL145',
          name: 'Collateral Haircut Missing',
          severity: 'high',
          message: 'Different collateral types need different haircuts for volatility',
          location: `${input.path}:${i + 1}`,
          snippet: line.trim(),
          fix: 'Apply haircuts: stables ~0%, majors ~10-20%, alts ~30-50%',
        });
      }

      // Check for concentration limits
      if (!/concentration|max.*collateral.*type|diversif/i.test(nearbyContent)) {
        findings.push({
          id: 'SOL145',
          name: 'Collateral Concentration Risk',
          severity: 'medium',
          message: 'Allow unlimited concentration in volatile collateral',
          location: `${input.path}:${i + 1}`,
          snippet: line.trim(),
          fix: 'Limit percentage of margin from any single volatile asset',
        });
      }
    }

    // Check for auto-deleverage
    if (/cascade|chain.*liquidation|deleverage.*other/i.test(line)) {
      findings.push({
        id: 'SOL145',
        name: 'Cascading Liquidation Risk',
        severity: 'high',
        message: 'Cross-margin liquidation can cascade across positions',
        location: `${input.path}:${i + 1}`,
        snippet: line.trim(),
        fix: 'Implement circuit breakers and partial liquidation to prevent cascades',
      });
    }
  });

  return findings;
}
