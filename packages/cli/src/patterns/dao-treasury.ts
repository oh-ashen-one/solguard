import type { Finding } from '../commands/audit.js';
import type { PatternInput } from './index.js';

/**
 * SOL148: DAO Treasury Security
 * Detects vulnerabilities in DAO treasury management
 * 
 * Treasury risks:
 * - Governance attacks
 * - Flash loan voting
 * - Timelock bypass
 */
export function checkDaoTreasury(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  const rust = input.rust;
  if (!rust) return findings;

  const content = rust.content;
  const lines = content.split('\n');

  lines.forEach((line, i) => {
    // Check for treasury withdrawal
    if (/withdraw.*treasury|transfer.*from.*treasury|spend.*fund/i.test(line)) {
      const nearbyContent = lines.slice(Math.max(0, i - 20), Math.min(lines.length, i + 20)).join('\n');
      
      // Check for governance approval
      if (!/proposal.*pass|vote.*approve|quorum/i.test(nearbyContent)) {
        findings.push({
          id: 'SOL148',
          name: 'Treasury Withdrawal Without Governance',
          severity: 'critical',
          message: 'Treasury funds can be withdrawn without governance approval',
          location: `${input.path}:${i + 1}`,
          snippet: line.trim(),
          fix: 'Require passed proposal with quorum for treasury withdrawals',
        });
      }

      // Check for timelock
      if (!/timelock|delay|execute.*after/i.test(nearbyContent)) {
        findings.push({
          id: 'SOL148',
          name: 'Treasury No Timelock',
          severity: 'high',
          message: 'Treasury withdrawal without timelock allows no reaction time',
          location: `${input.path}:${i + 1}`,
          snippet: line.trim(),
          fix: 'Add 24-48h timelock between proposal passing and execution',
        });
      }

      // Check for withdrawal limits
      if (!/max.*withdraw|limit.*per|daily.*cap/i.test(nearbyContent)) {
        findings.push({
          id: 'SOL148',
          name: 'Treasury No Withdrawal Limits',
          severity: 'medium',
          message: 'Single proposal can drain entire treasury',
          location: `${input.path}:${i + 1}`,
          snippet: line.trim(),
          fix: 'Implement per-proposal or daily withdrawal limits',
        });
      }
    }

    // Check for voting power
    if (/voting.*power|vote.*weight|token.*vote/i.test(line)) {
      const nearbyContent = lines.slice(Math.max(0, i - 15), Math.min(lines.length, i + 15)).join('\n');
      
      // Check for flash loan protection
      if (!/snapshot|checkpoint|lock.*period/i.test(nearbyContent)) {
        findings.push({
          id: 'SOL148',
          name: 'Flash Loan Voting',
          severity: 'critical',
          message: 'Voting power can be acquired via flash loan',
          location: `${input.path}:${i + 1}`,
          snippet: line.trim(),
          fix: 'Use snapshot of voting power from previous epoch/block',
        });
      }

      // Check for delegation
      if (!/delegate|proxy.*vote|voting.*escrow/i.test(nearbyContent)) {
        findings.push({
          id: 'SOL148',
          name: 'No Vote Delegation',
          severity: 'low',
          message: 'Without delegation, voter turnout may be low',
          location: `${input.path}:${i + 1}`,
          snippet: line.trim(),
          fix: 'Consider delegation to improve participation',
        });
      }
    }

    // Check for proposal creation
    if (/create.*proposal|submit.*proposal|new.*proposal/i.test(line)) {
      const nearbyContent = lines.slice(Math.max(0, i - 10), Math.min(lines.length, i + 10)).join('\n');
      
      // Check for proposal threshold
      if (!/threshold|min.*token|propose.*require/i.test(nearbyContent)) {
        findings.push({
          id: 'SOL148',
          name: 'No Proposal Threshold',
          severity: 'medium',
          message: 'Anyone can create proposals leading to spam',
          location: `${input.path}:${i + 1}`,
          snippet: line.trim(),
          fix: 'Require minimum token holding to create proposals',
        });
      }
    }

    // Check for emergency actions
    if (/emergency|guardian|pause.*treasury/i.test(line)) {
      findings.push({
        id: 'SOL148',
        name: 'Emergency Control Exists',
        severity: 'info',
        message: 'Emergency controls present - ensure proper key management',
        location: `${input.path}:${i + 1}`,
        snippet: line.trim(),
        fix: 'Document emergency key holders and sunset plan',
      });
    }
  });

  return findings;
}
