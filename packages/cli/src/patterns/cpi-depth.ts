import type { Finding } from '../commands/audit.js';
import type { PatternInput } from './index.js';

/**
 * SOL121: CPI Depth Management
 * Detects potential CPI depth issues
 */
export function checkCpiDepth(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  const rust = input.rust;

  if (!rust || !rust.content) return findings;

  // Count nested CPIs
  const cpiCalls = (rust.content.match(/invoke|CpiContext/g) || []).length;
  if (cpiCalls > 3) {
    findings.push({
      id: 'SOL121',
      severity: 'medium',
      title: 'Multiple CPI Calls',
      description: `${cpiCalls} CPI calls detected - watch for depth limits (max 4)`,
      location: input.path,
      recommendation: 'Solana CPI depth limit is 4 - ensure calls don\'t exceed this',
    });
  }

  // Check for recursive patterns
  if (rust.content.includes('invoke') && rust.content.includes('self')) {
    findings.push({
      id: 'SOL121',
      severity: 'high',
      title: 'Potential Recursive CPI',
      description: 'CPI may call back into same program - can exhaust depth',
      location: input.path,
      recommendation: 'Add recursion guards or depth tracking',
    });
  }

  return findings;
}
