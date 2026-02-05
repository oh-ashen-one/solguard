import type { Finding } from '../commands/audit.js';
import type { PatternInput } from './index.js';

/**
 * SOL190: Dependency Hijacking Prevention
 * 
 * Detects patterns that could indicate supply chain attacks
 * through compromised dependencies.
 * 
 * Real-world exploit: Web3.js supply chain attack - malicious
 * code injected into @solana/web3.js npm package.
 */
export function checkDependencyHijacking(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  const { rust, path } = input;

  if (!rust) return findings;

  const dangerousPatterns = [
    { pattern: /eval\s*\(/, severity: 'critical' as const, desc: 'Dynamic code execution via eval' },
    { pattern: /exec\s*\(/, severity: 'high' as const, desc: 'Shell command execution' },
    { pattern: /spawn\s*\(/, severity: 'high' as const, desc: 'Process spawning' },
    { pattern: /http.*request.*unchecked/i, severity: 'high' as const, desc: 'Unchecked HTTP requests' },
    { pattern: /fetch.*external/i, severity: 'medium' as const, desc: 'External data fetching' },
    { pattern: /deserialize.*untrusted/i, severity: 'critical' as const, desc: 'Deserializing untrusted data' },
    { pattern: /load_module.*dynamic/i, severity: 'critical' as const, desc: 'Dynamic module loading' },
    { pattern: /require\s*\(.*\+/i, severity: 'critical' as const, desc: 'Dynamic require' },
    { pattern: /import\s*\(.*\+/i, severity: 'critical' as const, desc: 'Dynamic import' },
  ];

  const lines = rust.content.split('\n');
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    for (const { pattern, severity, desc } of dangerousPatterns) {
      if (pattern.test(line)) {
        findings.push({
          id: 'SOL190',
          severity,
          title: 'Supply Chain Attack Vector',
          description: `${desc} - could be exploited if dependencies are compromised.`,
          location: { file: path, line: i + 1 },
          recommendation: 'Pin exact dependency versions, use lockfiles, and audit all dependencies regularly.',
        });
      }
    }
  }

  // Check for unsafe extern crate usage
  if (rust.content.includes('extern crate')) {
    const externLines = rust.content.split('\n').filter(l => l.includes('extern crate'));
    for (const line of externLines) {
      if (!line.includes('std') && !line.includes('core')) {
        findings.push({
          id: 'SOL190',
          severity: 'medium',
          title: 'External Crate Dependency',
          description: 'External crate imported - ensure it is from a trusted source with pinned version.',
          location: { file: path, line: rust.content.split('\n').indexOf(line) + 1 },
          recommendation: 'Audit all external crates, pin exact versions in Cargo.toml.',
        });
      }
    }
  }

  return findings;
}
