import type { Finding } from '../commands/audit.js';
import type { PatternInput } from './index.js';

/**
 * SOL052: Clock/Time Dependency Issues
 * Vulnerabilities related to time-based logic.
 */
export function checkClockDependency(input: PatternInput): Finding[] {
  const findings: Finding[] = [];

  if (!input.rust || !input.rust.files) return findings;

  for (const file of input.rust.files) {
    const lines = file.lines;

    lines.forEach((line, index) => {
      const lineNum = index + 1;

      // Pattern 1: Tight time window
      if (line.includes('unix_timestamp') || line.includes('Clock::get')) {
        const contextEnd = Math.min(lines.length, index + 10);
        const context = lines.slice(index, contextEnd).join('\n');

        // Check for tight windows (< 60 seconds)
        const secondsMatch = context.match(/[<>]=?\s*(\d+)\s*[;,)]/);
        if (secondsMatch) {
          const seconds = parseInt(secondsMatch[1]);
          if (seconds > 0 && seconds < 60) {
            findings.push({
              id: `SOL052-${findings.length + 1}`,
              pattern: 'Clock Dependency Issue',
              severity: 'medium',
              title: 'Very tight time window',
              description: `Time window of ${seconds}s may be too tight. Block times vary.`,
              location: { file: file.path, line: lineNum },
              suggestion: 'Use larger time windows to account for block time variance.',
            });
          }
        }
      }

      // Pattern 2: Exact timestamp comparison
      if (line.includes('==') && (line.includes('timestamp') || line.includes('time'))) {
        findings.push({
          id: `SOL052-${findings.length + 1}`,
          pattern: 'Clock Dependency Issue',
          severity: 'low',
          title: 'Exact timestamp comparison',
          description: 'Exact time match is unreliable. Use >= or <= with tolerance.',
          location: { file: file.path, line: lineNum },
          suggestion: 'Use range comparison: time >= start && time <= end',
        });
      }

      // Pattern 3: Time-based unlocking without grace period
      if ((line.includes('unlock') || line.includes('vest')) && 
          (line.includes('time') || line.includes('timestamp'))) {
        const contextStart = Math.max(0, index - 10);
        const context = lines.slice(contextStart, index + 10).join('\n');

        if (!context.includes('grace') && !context.includes('buffer') && 
            !context.includes('margin')) {
          findings.push({
            id: `SOL052-${findings.length + 1}`,
            pattern: 'Clock Dependency Issue',
            severity: 'low',
            title: 'Time-based unlock without grace period',
            description: 'Hard time cutoffs may cause issues if transaction is delayed.',
            location: { file: file.path, line: lineNum },
            suggestion: 'Consider adding small grace period for edge cases.',
          });
        }
      }
    });
  }

  return findings;
}
