import type { Finding } from '../commands/audit.js';
import type { PatternInput } from './index.js';

/**
 * SEC3 2025 Report: Data Integrity & Arithmetic Patterns (8.9% of vulnerabilities)
 * Based on Sec3's analysis of 163 Solana security audits
 */
export function checkSec32025DataIntegrity(input: PatternInput): Finding[] {
  const findings: Finding[] = [];

  if (input.rust?.content) {
    const content = input.rust.content;
    const lines = content.split('\n');

    for (let i = 0; i < lines.length; i++) {
      const line = lines[i];
      const context = lines.slice(Math.max(0, i - 5), Math.min(lines.length, i + 10)).join('\n');

      // DI001: Precision Loss in Division
      if (line.includes(' / ') && !line.includes('//')) {
        if ((line.includes('u64') || line.includes('u128')) && 
            !context.includes('checked_div') && !context.includes('saturating')) {
          if (line.includes(' * ') && line.indexOf(' / ') > line.indexOf(' * ')) {
            // Division after multiplication - potential precision loss
            findings.push({
              id: 'SEC3-DI001',
              title: 'Division Before Multiplication',
              severity: 'high',
              description: 'Division before multiplication can cause precision loss. Always multiply first.',
              location: { file: input.path, line: i + 1 },
              suggestion: 'Reorder: (a * b) / c instead of (a / c) * b',
              cwe: 'CWE-682',
            });
          }
        }
      }

      // DI002: Rounding Direction Not Specified
      if ((line.includes('as u64') || line.includes('as u128')) && 
          (context.includes(' / ') || context.includes('div'))) {
        if (!context.includes('floor') && !context.includes('ceil') && 
            !context.includes('round') && !context.includes('direction')) {
          findings.push({
            id: 'SEC3-DI002',
            title: 'Implicit Rounding Direction',
            severity: 'medium',
            description: 'Integer division implicitly floors. Specify rounding direction explicitly.',
            location: { file: input.path, line: i + 1 },
            suggestion: 'Use explicit rounding: floor for protocol benefit, ceil for user protection.',
            cwe: 'CWE-682',
          });
        }
      }

      // DI003: State Inconsistency After Partial Update
      if ((line.includes('.save()') || line.includes('serialize')) && !line.includes('//')) {
        if (!context.includes('atomic') && !context.includes('transaction') &&
            !context.includes('all_or_nothing')) {
          const stateUpdates = (context.match(/\.\s*\w+\s*=/g) || []).length;
          if (stateUpdates >= 3) {
            findings.push({
              id: 'SEC3-DI003',
              title: 'Non-Atomic Multi-State Update',
              severity: 'high',
              description: 'Multiple state updates without atomic transaction can leave inconsistent state on failure.',
              location: { file: input.path, line: i + 1 },
              suggestion: 'Group related state changes atomically. Consider using a state machine.',
              cwe: 'CWE-362',
            });
          }
        }
      }

      // DI004: Share Calculation Vulnerable to Inflation Attack
      if ((line.includes('shares') || line.includes('share_price')) &&
          (line.includes(' / ') || line.includes(' * '))) {
        if (!context.includes('virtual') && !context.includes('OFFSET') &&
            !context.includes('MIN_DEPOSIT')) {
          findings.push({
            id: 'SEC3-DI004',
            title: 'Share Calculation Without Inflation Protection',
            severity: 'critical',
            description: 'Share calculations without virtual offset are vulnerable to first-depositor inflation attack.',
            location: { file: input.path, line: i + 1 },
            suggestion: 'Add virtual shares offset: shares = (deposit + 1) * TOTAL_SHARES / (totalAssets + 1)',
            cwe: 'CWE-682',
          });
        }
      }

      // DI005: Cross-Account Data Dependency
      if (line.includes('other_account') || line.includes('related_account')) {
        if (!context.includes('reload') && !context.includes('refresh') &&
            !context.includes('re-fetch')) {
          findings.push({
            id: 'SEC3-DI005',
            title: 'Cross-Account Data Without Refresh',
            severity: 'medium',
            description: 'Reading from related accounts without refresh may use stale data.',
            location: { file: input.path, line: i + 1 },
            suggestion: 'Reload related account data: account.reload()?',
            cwe: 'CWE-662',
          });
        }
      }

      // DI006: Merkle Proof Without Index Validation
      if (line.includes('merkle') && (line.includes('verify') || line.includes('proof'))) {
        if (!context.includes('index') && !context.includes('leaf_index') &&
            !context.includes('position')) {
          findings.push({
            id: 'SEC3-DI006',
            title: 'Merkle Proof Missing Index Validation',
            severity: 'high',
            description: 'Merkle proofs should verify the leaf index to prevent replay at different positions.',
            location: { file: input.path, line: i + 1 },
            suggestion: 'Include leaf index in hash: hash(index || leaf_data)',
            cwe: 'CWE-354',
          });
        }
      }

      // DI007: Balance Tracking Mismatch
      if ((line.includes('balance') || line.includes('amount')) && 
          (line.includes('+=') || line.includes('-='))) {
        if (!context.includes('total') && !context.includes('sum') &&
            !context.includes('invariant')) {
          findings.push({
            id: 'SEC3-DI007',
            title: 'Balance Update Without Invariant Check',
            severity: 'high',
            description: 'Balance updates should verify total invariants (sum of parts = whole).',
            location: { file: input.path, line: i + 1 },
            suggestion: 'Add invariant: require!(user_balances.sum() == total_balance, InvariantViolation)',
            cwe: 'CWE-682',
          });
        }
      }

      // DI008: Nonce Not Incremented Atomically
      if (line.includes('nonce') && (line.includes('+= 1') || line.includes('+ 1'))) {
        if (!context.includes('checked_add') && !context.includes('wrapping')) {
          findings.push({
            id: 'SEC3-DI008',
            title: 'Nonce Increment Without Overflow Check',
            severity: 'medium',
            description: 'Nonce increment should handle overflow (wrap or reject).',
            location: { file: input.path, line: i + 1 },
            suggestion: 'Use: nonce = nonce.checked_add(1).ok_or(NonceOverflow)?',
            cwe: 'CWE-190',
          });
        }
      }

      // DI009: Epoch/Timestamp Boundary Issues
      if ((line.includes('epoch') || line.includes('period')) && 
          (line.includes(' / ') || line.includes('div'))) {
        if (!context.includes('boundary') && !context.includes('start_time') &&
            !context.includes('end_time')) {
          findings.push({
            id: 'SEC3-DI009',
            title: 'Epoch Calculation Without Boundary Handling',
            severity: 'medium',
            description: 'Epoch calculations should handle boundary conditions explicitly.',
            location: { file: input.path, line: i + 1 },
            suggestion: 'Define epoch_start and epoch_end, handle edge cases at boundaries.',
            cwe: 'CWE-682',
          });
        }
      }

      // DI010: Fixed-Point Math Precision
      if (line.includes('10_u128.pow') || line.includes('10u128.pow') ||
          line.includes('PRECISION') || line.includes('SCALE')) {
        if (!context.includes('DECIMALS') && !context.includes('decimal_places')) {
          findings.push({
            id: 'SEC3-DI010',
            title: 'Fixed-Point Math Without Decimal Tracking',
            severity: 'medium',
            description: 'Fixed-point operations should track decimal places to prevent precision errors.',
            location: { file: input.path, line: i + 1 },
            suggestion: 'Document precision: /// Price is stored with 6 decimal places (PRICE_DECIMALS = 6)',
            cwe: 'CWE-682',
          });
        }
      }
    }
  }

  return findings;
}
