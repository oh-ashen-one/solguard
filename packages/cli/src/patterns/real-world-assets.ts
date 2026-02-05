import type { Finding } from '../commands/audit.js';
import type { ParsedIdl } from '../parsers/idl.js';
import type { ParsedRust } from '../parsers/rust.js';

/**
 * SOL491-SOL500: Real World Asset (RWA) Security Patterns
 * 
 * RWA tokenization faces unique risks around off-chain verification,
 * custody, and regulatory compliance.
 */
export function checkRealWorldAssets(input: { idl?: ParsedIdl; rust?: ParsedRust }): Finding[] {
  const findings: Finding[] = [];
  
  if (input.rust?.sourceCode) {
    const code = input.rust.sourceCode;
    
    // SOL491: Off-chain asset verification
    if (/rwa|real_world|tokenized/i.test(code) && 
        /asset|property|commodity/i.test(code) &&
        !/oracle|attestation|proof_of_reserve/.test(code)) {
      findings.push({
        id: 'SOL491',
        severity: 'critical',
        title: 'Off-Chain Asset Not Verified',
        description: 'RWA tokens must verify underlying asset existence.',
        location: 'Asset verification',
        recommendation: 'Implement proof of reserves or third-party attestation.',
      });
    }
    
    // SOL492: Custody verification
    if (/custody|custodian/i.test(code) && 
        /rwa|asset/i.test(code) &&
        !/verify_custody|custody_proof/.test(code)) {
      findings.push({
        id: 'SOL492',
        severity: 'critical',
        title: 'Custodian Not Verified',
        description: 'RWA requires verified custody of underlying assets.',
        location: 'Custody management',
        recommendation: 'Implement custody verification and attestation.',
      });
    }
    
    // SOL493: KYC/AML requirements
    if (/rwa|security_token/i.test(code) && 
        /transfer|trade/i.test(code) &&
        !/kyc|aml|whitelist|accredit/.test(code)) {
      findings.push({
        id: 'SOL493',
        severity: 'high',
        title: 'No KYC/AML Enforcement',
        description: 'RWA tokens may require compliance checks for transfers.',
        location: 'Transfer logic',
        recommendation: 'Implement KYC whitelist and transfer restrictions.',
      });
    }
    
    // SOL494: Jurisdiction restrictions
    if (/rwa|security/i.test(code) && 
        /transfer/i.test(code) &&
        !/jurisdiction|region|country/.test(code)) {
      findings.push({
        id: 'SOL494',
        severity: 'high',
        title: 'No Jurisdiction Restrictions',
        description: 'RWA may have jurisdiction-specific transfer restrictions.',
        location: 'Transfer restrictions',
        recommendation: 'Implement jurisdiction-based transfer controls.',
      });
    }
    
    // SOL495: Dividend/yield distribution
    if (/dividend|yield|distribution/i.test(code) && 
        /rwa|security/i.test(code) &&
        !/snapshot|record_date/.test(code)) {
      findings.push({
        id: 'SOL495',
        severity: 'high',
        title: 'Dividend Record Date Not Snapshotted',
        description: 'Dividends should use snapshot to prevent gaming.',
        location: 'Dividend distribution',
        recommendation: 'Snapshot holdings at record date for distributions.',
      });
    }
    
    // SOL496: Fractionalization limits
    if (/fraction|share/i.test(code) && 
        /rwa|real_world/i.test(code) &&
        !/min_fraction|max_fraction/.test(code)) {
      findings.push({
        id: 'SOL496',
        severity: 'medium',
        title: 'No Fractionalization Limits',
        description: 'Asset fractionalization should have reasonable limits.',
        location: 'Fractionalization',
        recommendation: 'Set minimum and maximum fraction sizes.',
      });
    }
    
    // SOL497: Price oracle staleness
    if (/price|valuation/i.test(code) && 
        /rwa|asset/i.test(code) &&
        !/freshness|last_update|stale/.test(code)) {
      findings.push({
        id: 'SOL497',
        severity: 'high',
        title: 'RWA Price Can Be Stale',
        description: 'RWA valuations can become stale quickly.',
        location: 'Price feed',
        recommendation: 'Check price freshness and add staleness guards.',
      });
    }
    
    // SOL498: Redemption mechanism
    if (/redeem|burn/i.test(code) && 
        /rwa|tokenized/i.test(code) &&
        !/verify_redemption|delivery/.test(code)) {
      findings.push({
        id: 'SOL498',
        severity: 'critical',
        title: 'Redemption Without Delivery Verification',
        description: 'RWA redemption must verify off-chain asset delivery.',
        location: 'Redemption logic',
        recommendation: 'Implement redemption verification before burn.',
      });
    }
    
    // SOL499: Audit trail
    if (/rwa|security_token/i.test(code) && 
        !/audit|log|event|history/.test(code)) {
      findings.push({
        id: 'SOL499',
        severity: 'medium',
        title: 'Insufficient Audit Trail',
        description: 'RWA requires comprehensive audit trail for compliance.',
        location: 'Event logging',
        recommendation: 'Emit events for all material state changes.',
      });
    }
    
    // SOL500: Force transfer authority
    if (/rwa|security/i.test(code) && 
        /force|recover|freeze/i.test(code) &&
        !/court_order|legal|regulated/.test(code)) {
      findings.push({
        id: 'SOL500',
        severity: 'high',
        title: 'Force Transfer Without Legal Authority',
        description: 'Force transfers should require proper legal authorization.',
        location: 'Force transfer',
        recommendation: 'Implement proper authorization for force transfers.',
      });
    }
  }
  
  return findings;
}
