// SOL743: Cypher Protocol Insider Theft Pattern (Aug 2023 - $317K)
// Based on the Cypher exploit where an insider (Hoak) stole funds after the initial hack

import type { ParsedRust } from '../parsers/rust.js';
import type { Finding } from '../commands/audit.js';
import type { PatternInput } from './index.js';

/**
 * Cypher Protocol Insider Theft Patterns (August 2023)
 * 
 * After Cypher Protocol's initial $1M exploit, an insider named "Hoak" 
 * (a pseudonymous developer with admin access) stole an additional $317,000.
 * This highlights the growing threat of insider attacks in DeFi.
 * 
 * Key vulnerabilities:
 * 1. Single admin key access to critical functions
 * 2. No separation of duties for fund management
 * 3. Insufficient audit trails for admin actions
 * 4. Missing timelocks on privileged operations
 */

export function checkCypherInsiderTheft(parsed: ParsedRust): Finding[] {
  const findings: Finding[] = [];

  // Check for admin-only functions without separation of duties
  const adminPatterns = [
    /admin_only|only_admin|require_admin/i,
    /authority_check|owner_only/i,
    /privileged|superuser|root_access/i,
  ];

  const dangerousOperations = [
    /withdraw|transfer|drain/i,
    /set_fee|change_param|update_config/i,
    /pause|emergency|shutdown/i,
  ];

  for (const func of parsed.functions) {
    const content = func.content.toLowerCase();
    
    const hasAdmin = adminPatterns.some(p => p.test(content));
    const hasDangerousOp = dangerousOperations.some(p => p.test(content));
    
    if (hasAdmin && hasDangerousOp) {
      // Check for multisig requirement
      if (!/multisig|multi_sig|threshold|m_of_n/i.test(content)) {
        findings.push({
          id: 'SOL679',
          severity: 'critical',
          title: 'Cypher-style Single Admin Control Risk',
          description: `Function '${func.name}' allows single admin to perform dangerous operations`,
          location: func.location,
          recommendation: 'Require multisig approval for withdrawals, parameter changes, and emergency functions. Use at least 2-of-3 threshold.',
        });
      }

      // Check for timelock
      if (!/timelock|delay|pending|queue/i.test(content)) {
        findings.push({
          id: 'SOL680',
          severity: 'high',
          title: 'Admin Action Without Timelock',
          description: `Function '${func.name}' allows immediate admin actions without delay`,
          location: func.location,
          recommendation: 'Implement 24-48 hour timelocks on privileged operations to allow community review and intervention.',
        });
      }
    }
  }

  // Check for audit trail/logging
  const auditPatterns = [
    /emit!|log_action|audit_trail/i,
    /event.*admin|admin.*event/i,
    /record_action|log_admin/i,
  ];

  for (const func of parsed.functions) {
    const content = func.content.toLowerCase();
    
    const hasAdmin = adminPatterns.some(p => p.test(content));
    
    if (hasAdmin) {
      const hasAudit = auditPatterns.some(p => p.test(content));
      
      if (!hasAudit) {
        findings.push({
          id: 'SOL681',
          severity: 'medium',
          title: 'Missing Admin Action Audit Trail',
          description: `Function '${func.name}' performs admin actions without visible event emission`,
          location: func.location,
          recommendation: 'Emit events for all admin actions to create on-chain audit trail for transparency and accountability.',
        });
      }
    }
  }

  return findings;
}

// Check for access control separation
export function checkSeparationOfDuties(parsed: ParsedRust): Finding[] {
  const findings: Finding[] = [];

  // Different role patterns
  const rolePatterns = [
    { pattern: /withdraw_authority|withdrawer/i, role: 'withdrawer' },
    { pattern: /upgrade_authority|upgrader/i, role: 'upgrader' },
    { pattern: /fee_authority|fee_collector/i, role: 'fee_collector' },
    { pattern: /admin|owner|governance/i, role: 'admin' },
  ];

  // Count unique roles in structs
  for (const struct of parsed.structs) {
    const content = struct.fields.join(' ').toLowerCase();
    const foundRoles = rolePatterns.filter(r => r.pattern.test(content));
    
    if (foundRoles.length >= 3) {
      // Good: multiple role separation
      continue;
    } else if (foundRoles.length === 1 && foundRoles[0].role === 'admin') {
      findings.push({
        id: 'SOL682',
        severity: 'medium',
        title: 'Insufficient Role Separation',
        description: `Struct '${struct.name}' uses single admin role for multiple responsibilities`,
        location: struct.location,
        recommendation: 'Separate roles: admin for governance, withdrawer for fund management, upgrader for code updates. Reduces insider threat risk.',
      });
    }
  }

  return findings;
}

// Export combined check
export function checkCypherStyleInsiderThreats(input: PatternInput): Finding[] {
  if (!input.rust) return [];
  return [
    ...checkCypherInsiderTheft(input.rust),
    ...checkSeparationOfDuties(input.rust),
  ];
}
