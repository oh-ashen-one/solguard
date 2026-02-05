import type { Finding } from '../commands/audit.js';
import type { PatternInput } from './index.js';

/**
 * SOL193: JIT/Cache Safety
 * 
 * Detects patterns that might be affected by JIT compilation bugs
 * or caching issues in the Solana runtime.
 * 
 * Real-world exploit: Solana JIT Cache Bug - 5-hour network outage
 * due to JIT compilation vulnerability.
 */
export function checkJitCacheBug(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  const { rust, path } = input;

  if (!rust) return findings;

  const sensitivePatterns = [
    { pattern: /unsafe\s*\{/, desc: 'Unsafe block' },
    { pattern: /transmute/, desc: 'Memory transmutation' },
    { pattern: /ptr::read/, desc: 'Raw pointer read' },
    { pattern: /ptr::write/, desc: 'Raw pointer write' },
    { pattern: /mem::zeroed/, desc: 'Zeroed memory' },
    { pattern: /MaybeUninit/, desc: 'Potentially uninitialized memory' },
  ];

  const lines = rust.content.split('\n');
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    for (const { pattern, desc } of sensitivePatterns) {
      if (pattern.test(line)) {
        findings.push({
          id: 'SOL193',
          severity: 'medium',
          title: 'Unsafe Memory Operation',
          description: `${desc} - could interact poorly with JIT compilation or caching.`,
          location: { file: path, line: i + 1 },
          recommendation: 'Minimize unsafe code. Test thoroughly across Solana runtime versions.',
        });
      }
    }
  }

  return findings;
}
