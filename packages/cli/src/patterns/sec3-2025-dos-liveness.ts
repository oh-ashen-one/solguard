import type { Finding } from '../commands/audit.js';
import type { PatternInput } from './index.js';

/**
 * SEC3 2025 Report: Denial of Service & Liveness Patterns (8.5% of vulnerabilities)
 * Based on Sec3's analysis of 163 Solana security audits
 */
export function checkSec32025DosLiveness(input: PatternInput): Finding[] {
  const findings: Finding[] = [];

  if (input.rust?.content) {
    const content = input.rust.content;
    const lines = content.split('\n');

    for (let i = 0; i < lines.length; i++) {
      const line = lines[i];
      const context = lines.slice(Math.max(0, i - 5), Math.min(lines.length, i + 10)).join('\n');

      // DOS001: Unbounded Iteration
      if ((line.includes('for ') || line.includes('.iter()')) && 
          !line.includes('// bounded') && !line.includes('// SAFETY')) {
        if (context.includes('Vec<') && !context.includes('MAX_') &&
            !context.includes('.take(') && !context.includes('limit')) {
          findings.push({
            id: 'SEC3-DOS001',
            title: 'Unbounded Loop Over Dynamic Collection',
            severity: 'high',
            description: 'Iterating over unbounded collections can exhaust compute budget.',
            location: { file: input.path, line: i + 1 },
            suggestion: 'Bound iteration: for item in items.iter().take(MAX_ITEMS)',
            cwe: 'CWE-400',
          });
        }
      }

      // DOS002: No Compute Budget Check
      if ((line.includes('pub fn') || line.includes('fn process')) &&
          !line.includes('//')) {
        if (content.includes('for ') && !content.includes('compute_budget') &&
            !content.includes('ComputeBudget')) {
          findings.push({
            id: 'SEC3-DOS002',
            title: 'No Compute Budget Management',
            severity: 'medium',
            description: 'Complex operations should track compute budget to fail gracefully.',
            location: { file: input.path, line: i + 1 },
            suggestion: 'Add early exit if running low on compute units.',
            cwe: 'CWE-400',
          });
        }
      }

      // DOS003: Blocking Operation Without Timeout
      if ((line.includes('while ') || line.includes('loop {')) &&
          !context.includes('break') && !context.includes('return')) {
        if (!context.includes('max_iter') && !context.includes('timeout') &&
            !context.includes('deadline')) {
          findings.push({
            id: 'SEC3-DOS003',
            title: 'Potentially Infinite Loop',
            severity: 'critical',
            description: 'Loop without clear termination condition can hang transaction.',
            location: { file: input.path, line: i + 1 },
            suggestion: 'Add iteration limit: while condition && iterations < MAX_ITER',
            cwe: 'CWE-835',
          });
        }
      }

      // DOS004: External Dependency Without Fallback
      if ((line.includes('oracle') || line.includes('price_feed')) &&
          !line.includes('//')) {
        if (!context.includes('fallback') && !context.includes('backup') &&
            !context.includes('stale_price')) {
          findings.push({
            id: 'SEC3-DOS004',
            title: 'Oracle Dependency Without Fallback',
            severity: 'high',
            description: 'Oracle failures can DOS the protocol. Have fallback pricing.',
            location: { file: input.path, line: i + 1 },
            suggestion: 'Add fallback: let price = oracle.get_price().or_else(|| backup_oracle.get_price())?',
            cwe: 'CWE-754',
          });
        }
      }

      // DOS005: Large Account Reallocation
      if (line.includes('realloc') && !line.includes('//')) {
        if (!context.includes('MAX_SIZE') && !context.includes('max_size') &&
            !context.includes('limit')) {
          findings.push({
            id: 'SEC3-DOS005',
            title: 'Unbounded Account Reallocation',
            severity: 'high',
            description: 'Account reallocation without size limit can cause DOS.',
            location: { file: input.path, line: i + 1 },
            suggestion: 'Set maximum: require!(new_size <= MAX_ACCOUNT_SIZE, AccountTooLarge)',
            cwe: 'CWE-400',
          });
        }
      }

      // DOS006: Recursive CPI Without Depth Limit
      if (line.includes('invoke') && context.includes('self') && 
          !context.includes('depth') && !context.includes('MAX_DEPTH')) {
        findings.push({
          id: 'SEC3-DOS006',
          title: 'Recursive CPI Without Depth Limit',
          severity: 'high',
          description: 'Self-referencing CPI can cause stack overflow or compute exhaustion.',
          location: { file: input.path, line: i + 1 },
          suggestion: 'Track and limit CPI depth: require!(depth < MAX_CPI_DEPTH)',
          cwe: 'CWE-674',
        });
      }

      // DOS007: No Rate Limiting
      if ((line.includes('pub fn mint') || line.includes('pub fn create') ||
           line.includes('pub fn register')) && !line.includes('//')) {
        if (!context.includes('rate_limit') && !context.includes('cooldown') &&
            !context.includes('last_action')) {
          findings.push({
            id: 'SEC3-DOS007',
            title: 'No Rate Limiting on Creation',
            severity: 'medium',
            description: 'Account/token creation without rate limits enables spam attacks.',
            location: { file: input.path, line: i + 1 },
            suggestion: 'Add rate limiting: require!(clock.unix_timestamp > user.last_create + COOLDOWN)',
            cwe: 'CWE-770',
          });
        }
      }

      // DOS008: Serialization Attack Surface
      if ((line.includes('borsh::') || line.includes('BorshDeserialize')) &&
          context.includes('Vec<') && !context.includes('max_len')) {
        findings.push({
          id: 'SEC3-DOS008',
          title: 'Unbounded Deserialization',
          severity: 'high',
          description: 'Deserializing unbounded vectors can exhaust memory.',
          location: { file: input.path, line: i + 1 },
          suggestion: 'Use bounded types or validate length before deserializing.',
          cwe: 'CWE-502',
        });
      }

      // DOS009: CPI to Unknown Program
      if (line.includes('invoke') && !line.includes('token_program') &&
          !line.includes('system_program') && !line.includes('//')) {
        if (!context.includes('program_id ==') && !context.includes('whitelist')) {
          findings.push({
            id: 'SEC3-DOS009',
            title: 'CPI to Unvalidated Program',
            severity: 'high',
            description: 'CPI to unvalidated program could invoke malicious code.',
            location: { file: input.path, line: i + 1 },
            suggestion: 'Validate CPI target: require!(target_program.key() == KNOWN_PROGRAM_ID)',
            cwe: 'CWE-829',
          });
        }
      }

      // DOS010: Event Spamming
      if ((line.includes('emit!') || line.includes('msg!')) && 
          (context.includes('for ') || context.includes('loop'))) {
        if (!context.includes('limit') && !context.includes('MAX_')) {
          findings.push({
            id: 'SEC3-DOS010',
            title: 'Event Emission in Loop',
            severity: 'low',
            description: 'Emitting events in unbounded loops wastes compute and bloats logs.',
            location: { file: input.path, line: i + 1 },
            suggestion: 'Emit summary event after loop instead of per-iteration events.',
            cwe: 'CWE-400',
          });
        }
      }
    }
  }

  return findings;
}
