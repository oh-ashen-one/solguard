import type { Finding } from '../commands/audit.js';
import type { ParsedIdl } from '../parsers/idl.js';
import type { ParsedRust } from '../parsers/rust.js';

/**
 * SOL234: Turbine Propagation Safety
 * Detects patterns that could be affected by or exploit Solana's Turbine data propagation
 * Reference: 2023 Turbine failure incidents, block propagation delays
 */
export function checkTurbinePropagation(idl: ParsedIdl | null, rust: ParsedRust | null): Finding[] {
  const findings: Finding[] = [];

  if (rust) {
    for (const fn of rust.functions) {
      const content = fn.body.toLowerCase();

      // Check for slot-sensitive operations without confirmation checks
      if (content.includes('get_slot') || content.includes('clock.slot')) {
        if (!content.includes('confirm') && !content.includes('commitment')) {
          if (content.includes('transfer') || content.includes('withdraw') || content.includes('liquidat')) {
            findings.push({
              id: 'SOL234',
              severity: 'medium',
              title: 'Slot-Sensitive Operation Without Confirmation',
              description: 'Critical operation uses slot data without checking block confirmation. During Turbine propagation delays, this could lead to inconsistent state.',
              location: `Function: ${fn.name}`,
              recommendation: 'For critical operations, verify block finalization or use sufficient confirmation depth before proceeding.',
            });
          }
        }
      }

      // Check for leader schedule assumptions
      if (content.includes('leader_schedule') || content.includes('get_leader')) {
        findings.push({
          id: 'SOL234',
          severity: 'low',
          title: 'Leader Schedule Dependency',
          description: 'Code depends on leader schedule. During network partitions or Turbine failures, leader schedules may not propagate correctly.',
          location: `Function: ${fn.name}`,
          recommendation: 'Avoid relying on specific leader assignments. Design for leader schedule uncertainty.',
        });
      }

      // Check for shred-level operations
      if (content.includes('shred') || content.includes('erasure') || content.includes('reed_solomon')) {
        findings.push({
          id: 'SOL234',
          severity: 'info',
          title: 'Low-Level Shred Operations',
          description: 'Code interacts with shred-level data. Ensure proper handling of partial data and erasure coding edge cases.',
          location: `Function: ${fn.name}`,
          recommendation: 'Handle incomplete shred sets gracefully. Consider Turbine propagation delays in timeout calculations.',
        });
      }

      // Check for vote-dependent logic
      if (content.includes('vote_account') || content.includes('vote_state')) {
        if (content.includes('stake_weight') || content.includes('super_majority')) {
          findings.push({
            id: 'SOL234',
            severity: 'medium',
            title: 'Vote State Dependency',
            description: 'Critical logic depends on vote state. During network issues, vote states may lag behind actual confirmations.',
            location: `Function: ${fn.name}`,
            recommendation: 'Add tolerance for vote state lag. Consider using committed or finalized confirmation levels.',
          });
        }
      }

      // Check for blockhash usage patterns
      if (content.includes('recent_blockhash') || content.includes('get_recent_blockhash')) {
        if (!content.includes('retry') && (content.includes('loop') || content.includes('while'))) {
          findings.push({
            id: 'SOL234',
            severity: 'medium',
            title: 'Blockhash Without Retry Logic',
            description: 'Blockhash used in loop without explicit retry logic. Stale blockhashes during network delays can cause transaction failures.',
            location: `Function: ${fn.name}`,
            recommendation: 'Implement blockhash refresh and transaction retry logic for resilience during network partitions.',
          });
        }
      }
    }
  }

  return findings;
}
