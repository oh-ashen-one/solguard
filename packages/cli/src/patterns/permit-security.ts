import type { Finding } from '../commands/audit.js';
import type { PatternInput } from './index.js';

export function checkPermitSecurity(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  const content = input.rust?.content || '';
  const fileName = input.rust?.filePath || 'unknown';

  // Check for signature-based permits
  const permitPatterns = [
    /fn\s+permit/gi,
    /fn\s+permit_transfer/gi,
    /signature_transfer/gi,
    /signed_approval/gi,
  ];

  for (const pattern of permitPatterns) {
    const matches = [...content.matchAll(pattern)];
    for (const match of matches) {
      const contextEnd = Math.min(content.length, match.index! + 1500);
      const functionContext = content.substring(match.index!, contextEnd);
      
      // Check for nonce handling
      if (!functionContext.includes('nonce') && !functionContext.includes('sequence')) {
        const lineNumber = content.substring(0, match.index).split('\n').length;
        findings.push({
          id: 'SOL169',
          title: 'Permit Without Nonce',
          severity: 'critical',
          description: 'Signature-based permit without nonce. Signatures can be replayed multiple times.',
          location: { file: fileName, line: lineNumber },
          recommendation: 'Include incrementing nonce in signed message and validate on-chain.',
        });
      }

      // Check for deadline
      if (!functionContext.includes('deadline') && !functionContext.includes('expiry') &&
          !functionContext.includes('valid_until')) {
        const lineNumber = content.substring(0, match.index).split('\n').length;
        findings.push({
          id: 'SOL169',
          title: 'Permit Without Deadline',
          severity: 'high',
          description: 'Permit signature without expiration. Leaked signatures remain valid forever.',
          location: { file: fileName, line: lineNumber },
          recommendation: 'Include deadline timestamp in signed message and reject expired permits.',
        });
      }

      // Check for domain separator
      if (!functionContext.includes('domain') && !functionContext.includes('chain') &&
          !functionContext.includes('program_id')) {
        const lineNumber = content.substring(0, match.index).split('\n').length;
        findings.push({
          id: 'SOL169',
          title: 'Permit Without Domain Binding',
          severity: 'high',
          description: 'Permit without domain/program binding. Signatures may be valid across different programs.',
          location: { file: fileName, line: lineNumber },
          recommendation: 'Include program_id and optionally chain_id in signed message.',
        });
      }
    }
  }

  // Check for signature verification
  const signaturePatterns = [
    /verify_signature/gi,
    /ed25519_verify/gi,
    /signature.*verify/gi,
  ];

  for (const pattern of signaturePatterns) {
    const matches = [...content.matchAll(pattern)];
    for (const match of matches) {
      const contextEnd = Math.min(content.length, match.index! + 1000);
      const functionContext = content.substring(match.index!, contextEnd);
      
      // Check for proper error handling
      if (!functionContext.includes('?') && !functionContext.includes('expect') &&
          !functionContext.includes('unwrap_or') && !functionContext.includes('match')) {
        const lineNumber = content.substring(0, match.index).split('\n').length;
        findings.push({
          id: 'SOL169',
          title: 'Signature Verification Without Error Handling',
          severity: 'high',
          description: 'Signature verification without proper error handling. Invalid signatures may not be rejected.',
          location: { file: fileName, line: lineNumber },
          recommendation: 'Properly handle verification failure: return error if signature is invalid.',
        });
      }

      // Check for signer validation
      if (!functionContext.includes('signer') && !functionContext.includes('owner') &&
          !functionContext.includes('authority')) {
        const lineNumber = content.substring(0, match.index).split('\n').length;
        findings.push({
          id: 'SOL169',
          title: 'Signature Without Signer Validation',
          severity: 'critical',
          description: 'Signature verified but signer not validated against expected account.',
          location: { file: fileName, line: lineNumber },
          recommendation: 'Verify recovered signer matches expected authority account.',
        });
      }
    }
  }

  // Check for off-chain signature message construction
  const messagePatterns = [
    /message.*hash/gi,
    /sign.*message/gi,
    /msg_hash/gi,
  ];

  for (const pattern of messagePatterns) {
    const matches = [...content.matchAll(pattern)];
    for (const match of matches) {
      const contextEnd = Math.min(content.length, match.index! + 800);
      const functionContext = content.substring(match.index!, contextEnd);
      
      // Check for structured message
      if (!functionContext.includes('struct') && !functionContext.includes('type') &&
          !functionContext.includes('prefix')) {
        const lineNumber = content.substring(0, match.index).split('\n').length;
        findings.push({
          id: 'SOL169',
          title: 'Unstructured Signature Message',
          severity: 'medium',
          description: 'Signature message may not be properly structured. Vulnerable to signature collision.',
          location: { file: fileName, line: lineNumber },
          recommendation: 'Use typed structured data for signatures (similar to EIP-712).',
        });
      }
    }
  }

  // Check for withdrawal permit security
  if (content.includes('permit') && (content.includes('withdraw') || content.includes('transfer'))) {
    const withdrawPermitPattern = /permit.*withdraw|permit.*transfer/gi;
    const matches = [...content.matchAll(withdrawPermitPattern)];
    
    for (const match of matches) {
      const contextEnd = Math.min(content.length, match.index! + 1000);
      const functionContext = content.substring(match.index!, contextEnd);
      
      // Check for amount binding
      if (!functionContext.includes('amount')) {
        const lineNumber = content.substring(0, match.index).split('\n').length;
        findings.push({
          id: 'SOL169',
          title: 'Withdraw Permit Without Amount Binding',
          severity: 'critical',
          description: 'Withdrawal permit signature may not bind specific amount. Could withdraw more than intended.',
          location: { file: fileName, line: lineNumber },
          recommendation: 'Include exact withdrawal amount in signed message.',
        });
      }

      // Check for recipient binding
      if (!functionContext.includes('recipient') && !functionContext.includes('destination') &&
          !functionContext.includes('to')) {
        const lineNumber = content.substring(0, match.index).split('\n').length;
        findings.push({
          id: 'SOL169',
          title: 'Withdraw Permit Without Recipient Binding',
          severity: 'high',
          description: 'Withdrawal permit may not bind specific recipient. Funds could go to attacker.',
          location: { file: fileName, line: lineNumber },
          recommendation: 'Include intended recipient in signed message.',
        });
      }
    }
  }

  return findings;
}
