import type { Finding } from '../commands/audit.js';
import type { ParsedIdl } from '../parsers/idl.js';
import type { ParsedRust } from '../parsers/rust.js';

/**
 * SOL481-SOL490: Restaking Security Patterns
 * 
 * Restaking protocols face slashing risks, operator trust,
 * and complex withdrawal mechanics.
 */
export function checkRestaking(input: { idl?: ParsedIdl; rust?: ParsedRust }): Finding[] {
  const findings: Finding[] = [];
  
  if (input.rust?.sourceCode) {
    const code = input.rust.sourceCode;
    
    // SOL481: Slashing conditions undefined
    if (/slash|penalty/i.test(code) && 
        /restake|avs/i.test(code) &&
        !/slash_condition|proof_of_fault/.test(code)) {
      findings.push({
        id: 'SOL481',
        severity: 'critical',
        title: 'Slashing Conditions Not Defined',
        description: 'Restaked assets can be slashed without clear fault proof.',
        location: 'Slashing logic',
        recommendation: 'Define explicit slashing conditions with proof requirements.',
      });
    }
    
    // SOL482: Operator trust
    if (/operator|node_operator/i.test(code) && 
        /restake/i.test(code) &&
        !/verify|attestation|collateral/.test(code)) {
      findings.push({
        id: 'SOL482',
        severity: 'high',
        title: 'Operator Not Verified',
        description: 'Operators should provide collateral or attestation.',
        location: 'Operator onboarding',
        recommendation: 'Require operator collateral and verification.',
      });
    }
    
    // SOL483: Withdrawal delay bypass
    if (/withdraw|unstake/i.test(code) && 
        /restake/i.test(code) &&
        !/withdrawal_delay|cooldown/.test(code)) {
      findings.push({
        id: 'SOL483',
        severity: 'high',
        title: 'No Withdrawal Delay',
        description: 'Instant withdrawals can destabilize restaking security.',
        location: 'Withdrawal logic',
        recommendation: 'Implement withdrawal delay period for restaked assets.',
      });
    }
    
    // SOL484: Multi-AVS slashing cascade
    if (/avs|actively_validated/i.test(code) && 
        /multiple|several/i.test(code) &&
        !/slash_cap|max_slash/.test(code)) {
      findings.push({
        id: 'SOL484',
        severity: 'critical',
        title: 'Multiple AVS Slashing Cascade Risk',
        description: 'Same stake securing multiple AVS can face cascading slashing.',
        location: 'Multi-AVS security',
        recommendation: 'Cap total slashing across multiple AVS assignments.',
      });
    }
    
    // SOL485: Reward distribution
    if (/reward|yield/i.test(code) && 
        /restake|avs/i.test(code) &&
        !/fair|pro_rata|proportional/.test(code)) {
      findings.push({
        id: 'SOL485',
        severity: 'medium',
        title: 'Unfair Reward Distribution',
        description: 'Restaking rewards should be distributed proportionally.',
        location: 'Reward mechanism',
        recommendation: 'Implement pro-rata reward distribution.',
      });
    }
    
    // SOL486: AVS registration validation
    if (/register.*avs|avs.*register/i.test(code) && 
        !/verify_avs|validate_avs/.test(code)) {
      findings.push({
        id: 'SOL486',
        severity: 'high',
        title: 'AVS Registration Not Validated',
        description: 'Malicious AVS can steal or slash delegated stake.',
        location: 'AVS registration',
        recommendation: 'Validate AVS contracts before allowing delegation.',
      });
    }
    
    // SOL487: Delegation accounting
    if (/delegat/i.test(code) && 
        /restake/i.test(code) &&
        !/track|account|balance/.test(code)) {
      findings.push({
        id: 'SOL487',
        severity: 'high',
        title: 'Delegation Accounting Missing',
        description: 'Delegated amounts must be tracked per delegator.',
        location: 'Delegation tracking',
        recommendation: 'Maintain accurate per-delegator accounting.',
      });
    }
    
    // SOL488: Operator key rotation
    if (/operator.*key|signing_key/i.test(code) && 
        /restake/i.test(code) &&
        !/rotate|update_key/.test(code)) {
      findings.push({
        id: 'SOL488',
        severity: 'medium',
        title: 'Operator Key Cannot Be Rotated',
        description: 'Compromised operator keys need rotation capability.',
        location: 'Key management',
        recommendation: 'Implement operator key rotation with verification.',
      });
    }
    
    // SOL489: Slashing dispute window
    if (/slash/i.test(code) && 
        !/dispute|challenge|appeal/.test(code)) {
      findings.push({
        id: 'SOL489',
        severity: 'high',
        title: 'No Slashing Dispute Mechanism',
        description: 'Slashing should have dispute window for wrongful penalties.',
        location: 'Slashing execution',
        recommendation: 'Add dispute period before slashing finalization.',
      });
    }
    
    // SOL490: Restaking ratio limits
    if (/restake|rehypothecate/i.test(code) && 
        !/max_restake|restake_limit|ratio/.test(code)) {
      findings.push({
        id: 'SOL490',
        severity: 'high',
        title: 'No Restaking Ratio Limits',
        description: 'Unlimited restaking creates systemic risk.',
        location: 'Restaking limits',
        recommendation: 'Limit how much can be restaked against base stake.',
      });
    }
  }
  
  return findings;
}
