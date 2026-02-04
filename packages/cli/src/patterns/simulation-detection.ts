import type { Finding } from '../commands/audit.js';
import type { PatternInput } from './index.js';

/**
 * SOL146: Transaction Simulation Detection
 * Detects code that behaves differently in simulation vs execution
 * Real-world: Various scam tokens that pass simulation but fail execution
 */
export function checkSimulationDetection(input: PatternInput): Finding[] {
  const findings: Finding[] = [];

  if (input.rust?.content) {
    const content = input.rust.content;
    const lines = content.split('\n');

    // Check for simulation detection patterns
    const simPatterns = [
      /is_simulation|simulation_mode/i,
      /preflight|pre_flight/i,
      /sol_log_compute_units/i,
    ];

    for (let i = 0; i < lines.length; i++) {
      const line = lines[i];

      // Check for explicit simulation detection
      if (simPatterns.some(p => p.test(line))) {
        findings.push({
          id: 'SOL146',
          title: 'Simulation Detection',
          severity: 'critical',
          description: 'Code that detects simulation mode can be used to create scam tokens or hide malicious behavior.',
          location: { file: input.path, line: i + 1 },
          suggestion: 'Remove simulation detection. Code should behave identically in simulation and execution.',
          cwe: 'CWE-693',
        });
      }

      // Check for instruction count-based detection
      if (line.includes('sol_log_compute_units') || line.includes('compute_units_consumed')) {
        findings.push({
          id: 'SOL146',
          title: 'Compute Unit Detection',
          severity: 'high',
          description: 'Using compute unit counts to detect execution context can enable malicious behavior.',
          location: { file: input.path, line: i + 1 },
          suggestion: 'Avoid compute-unit based logic that affects transaction outcome.',
          cwe: 'CWE-693',
        });
      }
    }

    // Check for bank/slot-based simulation detection
    if (content.includes('Bank') || content.includes('BankForks')) {
      findings.push({
        id: 'SOL146',
        title: 'Bank State Detection',
        severity: 'critical',
        description: 'Accessing bank state can be used to distinguish simulation from execution.',
        location: { file: input.path, line: 1 },
        suggestion: 'Do not use internal runtime state to alter program behavior.',
        cwe: 'CWE-693',
      });
    }

    // Check for conditional behavior based on slot
    if (content.includes('slot') && (content.includes('if') || content.includes('match'))) {
      // Look for suspicious slot-based logic
      for (let i = 0; i < lines.length; i++) {
        if (lines[i].includes('slot') && (lines[i].includes('==') || lines[i].includes('!='))) {
          if (!lines[i].includes('last_update_slot') && !lines[i].includes('valid_slot')) {
            findings.push({
              id: 'SOL146',
              title: 'Suspicious Slot-Based Logic',
              severity: 'medium',
              description: 'Slot-based conditional logic may be used for simulation detection.',
              location: { file: input.path, line: i + 1 },
              suggestion: 'Ensure slot checks are for legitimate purposes (cooldowns, TWAP) not simulation detection.',
              cwe: 'CWE-693',
            });
            break;
          }
        }
      }
    }
  }

  return findings;
}
