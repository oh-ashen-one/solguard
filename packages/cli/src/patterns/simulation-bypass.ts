import type { Finding } from '../commands/audit.js';
import type { PatternInput } from './index.js';

/**
 * SOL313: Simulation Bypass Detection
 * Detects attempts to detect and bypass transaction simulation
 * Real-world: Opcodes simulation detection research
 */
export function checkSimulationBypass(input: PatternInput): Finding[] {
  const findings: Finding[] = [];

  if (input.rust?.content) {
    const content = input.rust.content;
    const lines = content.split('\n');

    // Detect simulation detection patterns (potential red flag)
    for (let i = 0; i < lines.length; i++) {
      const line = lines[i];

      // Check for bank/simulation detection
      if (line.includes('is_simulation') || line.includes('simulation_mode') || 
          line.includes('bank_hash') || line.includes('skip_verification')) {
        findings.push({
          id: 'SOL313',
          title: 'Simulation Detection Attempt',
          severity: 'critical',
          description: 'Code appears to detect simulation mode. This is typically malicious.',
          location: { file: input.path, line: i + 1 },
          suggestion: 'Remove simulation detection. Programs should behave identically in simulation and execution.',
          cwe: 'CWE-693',
        });
      }

      // Check for fee payer balance checks (simulation detection technique)
      if (line.includes('fee_payer') && line.includes('lamports')) {
        const contextLines = lines.slice(i, Math.min(i + 5, lines.length)).join('\n');
        if (contextLines.includes('== 0') || contextLines.includes('insufficient')) {
          findings.push({
            id: 'SOL313',
            title: 'Potential Simulation Detection via Fee Payer',
            severity: 'high',
            description: 'Checking fee payer balance can be used to detect simulation.',
            location: { file: input.path, line: i + 1 },
            suggestion: 'Avoid fee payer balance checks that could differentiate simulation from execution.',
            cwe: 'CWE-693',
          });
        }
      }

      // Check for slot/blockhash manipulation detection
      if (line.includes('recent_blockhash') || line.includes('slot_hashes')) {
        const contextLines = lines.slice(i, Math.min(i + 5, lines.length)).join('\n');
        if (contextLines.includes('!= ') || contextLines.includes('different')) {
          findings.push({
            id: 'SOL313',
            title: 'Blockhash/Slot Comparison',
            severity: 'medium',
            description: 'Blockhash comparisons may behave differently in simulation.',
            location: { file: input.path, line: i + 1 },
            suggestion: 'Ensure blockhash logic works consistently in simulation and execution.',
            cwe: 'CWE-362',
          });
        }
      }
    }

    // Check for preflight bypass indicators
    if (content.includes('skip_preflight') || content.includes('preflight_commitment')) {
      findings.push({
        id: 'SOL313',
        title: 'Preflight Skip Reference',
        severity: 'info',
        description: 'Code references preflight skipping. Ensure users understand risks.',
        location: { file: input.path, line: 1 },
        suggestion: 'Document preflight risks: Skipping preflight can lead to failed transactions and lost fees.',
        cwe: 'CWE-754',
      });
    }

    // Check for compute budget manipulation
    if (content.includes('compute_budget') || content.includes('ComputeBudget')) {
      for (let i = 0; i < lines.length; i++) {
        if (lines[i].includes('set_compute_unit_limit') || lines[i].includes('request_units')) {
          // Check if limit is dynamically calculated
          const contextLines = lines.slice(Math.max(0, i - 5), i + 5).join('\n');
          if (contextLines.includes('if') && !contextLines.includes('const')) {
            findings.push({
              id: 'SOL313',
              title: 'Dynamic Compute Budget',
              severity: 'medium',
              description: 'Dynamically setting compute budget can affect simulation vs execution behavior.',
              location: { file: input.path, line: i + 1 },
              suggestion: 'Use consistent compute budget for predictable behavior.',
              cwe: 'CWE-682',
            });
          }
        }
      }
    }

    // Check for clock-based behavior differences
    if (content.includes('Clock') || content.includes('unix_timestamp')) {
      for (let i = 0; i < lines.length; i++) {
        const line = lines[i];
        if (line.includes('unix_timestamp') && !line.includes('//')) {
          const contextLines = lines.slice(i, Math.min(i + 10, lines.length)).join('\n');
          // Tight time windows can behave differently
          if (contextLines.match(/\+\s*[1-9]\s*\)/) || contextLines.includes('< 10') || contextLines.includes('< 60')) {
            findings.push({
              id: 'SOL313',
              title: 'Tight Time Window',
              severity: 'medium',
              description: 'Very tight time windows (<60s) may behave differently in simulation due to timing.',
              location: { file: input.path, line: i + 1 },
              suggestion: 'Use reasonable time windows (minutes, not seconds) for consistent behavior.',
              cwe: 'CWE-362',
            });
            break;
          }
        }
      }
    }

    // Check for error handling that might differ
    if (content.includes('Err(') && content.includes('log')) {
      for (let i = 0; i < lines.length; i++) {
        if (lines[i].includes('msg!') || lines[i].includes('sol_log')) {
          const contextLines = lines.slice(i, Math.min(i + 3, lines.length)).join('\n');
          if (contextLines.includes('Err(')) {
            // Logging before error is fine, but check for conditional logging
            if (lines.slice(Math.max(0, i - 2), i).join('').includes('if')) {
              findings.push({
                id: 'SOL313',
                title: 'Conditional Error Logging',
                severity: 'low',
                description: 'Conditional logging may produce different outputs in simulation.',
                location: { file: input.path, line: i + 1 },
                suggestion: 'Log errors consistently regardless of conditions.',
                cwe: 'CWE-778',
              });
              break;
            }
          }
        }
      }
    }
  }

  return findings;
}
