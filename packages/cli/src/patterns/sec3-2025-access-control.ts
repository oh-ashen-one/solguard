import type { Finding } from '../commands/audit.js';
import type { PatternInput } from './index.js';

/**
 * SEC3 2025 Report: Access Control & Authorization Patterns (19% of vulnerabilities)
 * Based on Sec3's analysis of 163 Solana security audits
 * Third most common vulnerability category, 20.7% of high/critical findings
 */
export function checkSec32025AccessControl(input: PatternInput): Finding[] {
  const findings: Finding[] = [];

  if (input.rust?.content) {
    const content = input.rust.content;
    const lines = content.split('\n');

    for (let i = 0; i < lines.length; i++) {
      const line = lines[i];
      const context = lines.slice(Math.max(0, i - 5), Math.min(lines.length, i + 10)).join('\n');

      // AC001: Admin Function Without Authority Check
      if ((line.includes('pub fn admin') || line.includes('pub fn set_') ||
           line.includes('pub fn update_') || line.includes('pub fn pause')) &&
          !line.includes('//')) {
        if (!context.includes('has_one') && !context.includes('constraint =') &&
            !context.includes('authority') && !context.includes('admin')) {
          findings.push({
            id: 'SEC3-AC001',
            title: 'Admin Function Without Authority Constraint',
            severity: 'critical',
            description: 'Administrative function lacks authority validation.',
            location: { file: input.path, line: i + 1 },
            suggestion: 'Add Anchor constraint: #[account(has_one = authority @ UnauthorizedAdmin)]',
            cwe: 'CWE-862',
          });
        }
      }

      // AC002: Multi-Sig Not Enforced for Critical Operations
      if ((line.includes('upgrade') || line.includes('withdraw_all') || 
           line.includes('emergency') || line.includes('migrate')) &&
          !line.includes('//')) {
        if (!context.includes('multisig') && !context.includes('multi_sig') &&
            !context.includes('threshold') && !context.includes('signers')) {
          findings.push({
            id: 'SEC3-AC002',
            title: 'Critical Operation Without Multi-Sig',
            severity: 'high',
            description: 'Critical operations should require multi-signature authorization.',
            location: { file: input.path, line: i + 1 },
            suggestion: 'Implement multi-sig: require!(approved_signers >= threshold, InsufficientSigners)',
            cwe: 'CWE-287',
          });
        }
      }

      // AC003: Role-Based Access Missing
      if (line.includes('pub fn') && (line.includes('_admin') || line.includes('_operator') ||
          line.includes('_manager'))) {
        if (!context.includes('role') && !context.includes('permission') &&
            !context.includes('is_authorized')) {
          findings.push({
            id: 'SEC3-AC003',
            title: 'Role-Based Function Without Role Check',
            severity: 'high',
            description: 'Function implies role-based access but lacks explicit role verification.',
            location: { file: input.path, line: i + 1 },
            suggestion: 'Verify role: require!(user.role == Role::Admin, UnauthorizedRole)',
            cwe: 'CWE-285',
          });
        }
      }

      // AC004: Signer Not Verified in CPI
      if (line.includes('invoke') && !line.includes('invoke_signed')) {
        if (!context.includes('is_signer') && !context.includes('Signer<')) {
          findings.push({
            id: 'SEC3-AC004',
            title: 'CPI Without Signer Verification',
            severity: 'high',
            description: 'Cross-program invocation without verifying the signer authority.',
            location: { file: input.path, line: i + 1 },
            suggestion: 'Verify signer: require!(authority.is_signer, MissingSigner)',
            cwe: 'CWE-863',
          });
        }
      }

      // AC005: Delegate Authority Not Scoped
      if (line.includes('delegate') && !line.includes('//')) {
        if (!context.includes('max_amount') && !context.includes('expiry') &&
            !context.includes('allowed_operations')) {
          findings.push({
            id: 'SEC3-AC005',
            title: 'Delegation Without Scope Limits',
            severity: 'medium',
            description: 'Delegated authority should have amount limits and expiry.',
            location: { file: input.path, line: i + 1 },
            suggestion: 'Scope delegation: delegate.max_amount, delegate.expiry, delegate.allowed_ops',
            cwe: 'CWE-269',
          });
        }
      }

      // AC006: Ownership Transfer Without Confirmation
      if ((line.includes('transfer_ownership') || line.includes('new_owner') ||
           line.includes('pending_owner')) && !line.includes('//')) {
        if (!context.includes('accept_ownership') && !context.includes('confirm') &&
            !context.includes('two_step')) {
          findings.push({
            id: 'SEC3-AC006',
            title: 'Ownership Transfer Without 2-Step Confirmation',
            severity: 'high',
            description: 'Ownership transfers should use 2-step process to prevent accidental loss.',
            location: { file: input.path, line: i + 1 },
            suggestion: 'Use pending_owner pattern: set_pending_owner() -> accept_ownership()',
            cwe: 'CWE-269',
          });
        }
      }

      // AC007: Token Authority Not Program-Derived
      if ((line.includes('mint_authority') || line.includes('freeze_authority')) &&
          !context.includes('PDA') && !context.includes('find_program_address') &&
          !context.includes('seeds')) {
        findings.push({
          id: 'SEC3-AC007',
          title: 'Token Authority Not PDA',
          severity: 'medium',
          description: 'Token authorities should be PDAs for programmatic control.',
          location: { file: input.path, line: i + 1 },
          suggestion: 'Derive authority from PDA: seeds = [b"mint_authority", mint.key().as_ref()]',
          cwe: 'CWE-269',
        });
      }

      // AC008: Permissionless Cranking Without Protection
      if ((line.includes('pub fn crank') || line.includes('pub fn update_price') ||
           line.includes('pub fn liquidate')) && !line.includes('//')) {
        if (!context.includes('reward') && !context.includes('fee') &&
            !context.includes('incentive')) {
          findings.push({
            id: 'SEC3-AC008',
            title: 'Permissionless Crank Without Incentive',
            severity: 'low',
            description: 'Permissionless functions should incentivize crankers to ensure liveness.',
            location: { file: input.path, line: i + 1 },
            suggestion: 'Add cranker rewards to incentivize timely execution.',
            cwe: 'CWE-400',
          });
        }
      }

      // AC009: Close Authority Not Restricted
      if (line.includes('close =') || line.includes('close_account')) {
        if (!context.includes('authority') && !context.includes('has_one') &&
            !context.includes('owner')) {
          findings.push({
            id: 'SEC3-AC009',
            title: 'Account Close Without Authority Check',
            severity: 'critical',
            description: 'Account closure must verify the closer has authority.',
            location: { file: input.path, line: i + 1 },
            suggestion: 'Add constraint: #[account(close = authority, has_one = authority)]',
            cwe: 'CWE-862',
          });
        }
      }

      // AC010: Timelock Bypass Possible
      if (line.includes('timelock') && !line.includes('//')) {
        if (!context.includes('min_delay') && !context.includes('MIN_DELAY') &&
            !context.includes('TIMELOCK_DURATION')) {
          findings.push({
            id: 'SEC3-AC010',
            title: 'Timelock Without Minimum Delay',
            severity: 'high',
            description: 'Timelocks should have a minimum delay that cannot be bypassed.',
            location: { file: input.path, line: i + 1 },
            suggestion: 'Enforce minimum: require!(delay >= MIN_TIMELOCK_DELAY, DelayTooShort)',
            cwe: 'CWE-269',
          });
        }
      }
    }
  }

  return findings;
}
