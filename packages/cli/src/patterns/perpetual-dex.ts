import type { Finding } from '../commands/audit.js';
import type { PatternInput } from './index.js';

/**
 * SOL141: Perpetual DEX Security
 * Detects vulnerabilities in perpetual futures protocols (Drift, Jupiter Perps style)
 * 
 * Perp-specific risks:
 * - Funding rate manipulation
 * - Liquidation cascades
 * - Position limit bypass
 */
export function checkPerpetualDex(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  const rust = input.rust;
  if (!rust) return findings;

  const content = rust.content;
  const lines = content.split('\n');

  lines.forEach((line, i) => {
    // Check for funding rate calculation
    if (/funding.*rate|calculate.*funding|funding.*payment/i.test(line)) {
      const nearbyContent = lines.slice(Math.max(0, i - 20), Math.min(lines.length, i + 20)).join('\n');
      
      // Check for funding rate caps
      if (!/max.*funding|cap.*rate|clamp/i.test(nearbyContent)) {
        findings.push({
          id: 'SOL141',
          name: 'Funding Rate Uncapped',
          severity: 'high',
          message: 'Uncapped funding rates can drain positions during extreme moves',
          location: `${input.path}:${i + 1}`,
          snippet: line.trim(),
          fix: 'Cap funding rate (e.g., ±0.1% per hour) to prevent excessive payments',
        });
      }

      // Check for TWAP-based funding
      if (!/twap|time_weighted|average.*price/i.test(nearbyContent)) {
        findings.push({
          id: 'SOL141',
          name: 'Funding Rate Spot Based',
          severity: 'medium',
          message: 'Funding rate based on spot price can be manipulated',
          location: `${input.path}:${i + 1}`,
          snippet: line.trim(),
          fix: 'Use TWAP mark price for funding rate calculation',
        });
      }
    }

    // Check for position management
    if (/open.*position|increase.*position|add.*margin/i.test(line)) {
      const nearbyContent = lines.slice(Math.max(0, i - 15), Math.min(lines.length, i + 15)).join('\n');
      
      // Check for position limits
      if (!/max.*position|position.*limit|open_interest.*cap/i.test(nearbyContent)) {
        findings.push({
          id: 'SOL141',
          name: 'No Position Limits',
          severity: 'high',
          message: 'Unlimited position sizes can concentrate risk and manipulate funding',
          location: `${input.path}:${i + 1}`,
          snippet: line.trim(),
          fix: 'Implement per-user and global position limits',
        });
      }

      // Check for initial margin
      if (!/initial.*margin|margin.*requirement|collateral.*ratio/i.test(nearbyContent)) {
        findings.push({
          id: 'SOL141',
          name: 'Initial Margin Missing',
          severity: 'critical',
          message: 'Position opened without initial margin requirement',
          location: `${input.path}:${i + 1}`,
          snippet: line.trim(),
          fix: 'Require initial margin (e.g., 10%) before opening position',
        });
      }
    }

    // Check for mark price calculation
    if (/mark.*price|index.*price|fair.*price/i.test(line)) {
      const nearbyContent = lines.slice(Math.max(0, i - 10), Math.min(lines.length, i + 10)).join('\n');
      
      if (!/oracle|external.*price|pyth|switchboard/i.test(nearbyContent)) {
        findings.push({
          id: 'SOL141',
          name: 'Mark Price Not Oracle Based',
          severity: 'high',
          message: 'Mark price without external oracle can be manipulated internally',
          location: `${input.path}:${i + 1}`,
          snippet: line.trim(),
          fix: 'Derive mark price from oracle with damping for internal book price',
        });
      }
    }

    // Check for ADL (Auto-Deleveraging)
    if (/auto.*deleverage|adl|socialized.*loss/i.test(line)) {
      const nearbyContent = lines.slice(Math.max(0, i - 10), Math.min(lines.length, i + 10)).join('\n');
      
      if (!/priority|profit.*ranking|pnl.*order/i.test(nearbyContent)) {
        findings.push({
          id: 'SOL141',
          name: 'ADL Priority Not Defined',
          severity: 'medium',
          message: 'Auto-deleveraging without clear priority can be unfair',
          location: `${input.path}:${i + 1}`,
          snippet: line.trim(),
          fix: 'ADL should prioritize by profit/leverage ratio (highest first)',
        });
      }
    }

    // Check for insurance fund
    if (/insurance.*fund|backstop|loss.*pool/i.test(line)) {
      findings.push({
        id: 'SOL141',
        name: 'Insurance Fund Detected',
        severity: 'info',
        message: 'Insurance fund present - ensure proper funding and governance',
        location: `${input.path}:${i + 1}`,
        snippet: line.trim(),
        fix: 'Document insurance fund size requirements and top-up mechanism',
      });
    }
  });

  return findings;
}
