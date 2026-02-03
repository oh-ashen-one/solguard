import type { Finding } from '../commands/audit.js';
import type { PatternInput } from './index.js';

/**
 * SOL091: SPL Governance Security
 * Detects vulnerabilities in governance implementations
 */
export function checkSplGovernance(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  const rust = input.rust;

  if (!rust || !rust.content) return findings;

  const hasGovernance = rust.content.includes('governance') ||
                        rust.content.includes('proposal') ||
                        rust.content.includes('vote') ||
                        rust.content.includes('quorum');

  if (!hasGovernance) return findings;

  // Check for voting without time locks
  if (rust.content.includes('vote') && !rust.content.includes('time_lock') && 
      !rust.content.includes('delay')) {
    findings.push({
      id: 'SOL091',
      severity: 'high',
      title: 'Voting Without Time Lock',
      description: 'Governance voting without execution delay - vulnerable to flash loan attacks',
      location: input.path,
      recommendation: 'Add time lock between vote completion and execution',
    });
  }

  // Check for quorum manipulation
  if (rust.content.includes('quorum')) {
    if (!rust.content.includes('snapshot') && !rust.content.includes('checkpoint')) {
      findings.push({
        id: 'SOL091',
        severity: 'high',
        title: 'Quorum Without Snapshot',
        description: 'Quorum calculated without voting power snapshot - manipulable',
        location: input.path,
        recommendation: 'Use voting power snapshot at proposal creation time',
      });
    }
  }

  // Check for proposal execution
  if (rust.content.includes('execute') && rust.content.includes('proposal')) {
    if (!rust.content.includes('executed') && !rust.content.includes('status')) {
      findings.push({
        id: 'SOL091',
        severity: 'critical',
        title: 'Proposal Re-execution Risk',
        description: 'Proposal execution without status tracking - may execute twice',
        location: input.path,
        recommendation: 'Track proposal.executed = true after execution',
      });
    }
  }

  // Check for vote delegation
  if (rust.content.includes('delegate')) {
    if (!rust.content.includes('self') && !rust.content.includes('own')) {
      findings.push({
        id: 'SOL091',
        severity: 'medium',
        title: 'Delegation Without Self-Vote Option',
        description: 'Vote delegation may prevent self-voting if not handled',
        location: input.path,
        recommendation: 'Allow users to vote directly or reclaim delegation',
      });
    }
  }

  return findings;
}
