import type { Finding } from '../commands/audit.js';
import type { ParsedIdl } from '../parsers/idl.js';
import type { ParsedRust } from '../parsers/rust.js';

/**
 * SOL471-SOL480: DAO Treasury Security Patterns
 * 
 * DAO treasuries face governance attacks, flash loan voting,
 * and treasury drain risks.
 */
export function checkDaoTreasury(input: { idl?: ParsedIdl; rust?: ParsedRust }): Finding[] {
  const findings: Finding[] = [];
  
  if (input.rust?.sourceCode) {
    const code = input.rust.sourceCode;
    
    // SOL471: Flash loan governance
    if (/vote|proposal/i.test(code) && 
        /governance|dao/i.test(code) &&
        !/timelock|snapshot|checkpoint/.test(code)) {
      findings.push({
        id: 'SOL471',
        severity: 'critical',
        title: 'Governance Vulnerable to Flash Loan Attack',
        description: 'Voting power should be time-locked or snapshotted.',
        location: 'Voting mechanism',
        recommendation: 'Checkpoint voting power at proposal creation.',
      });
    }
    
    // SOL472: Proposal spam
    if (/create.*proposal/i.test(code) && 
        !/min_stake|proposal_threshold/.test(code)) {
      findings.push({
        id: 'SOL472',
        severity: 'medium',
        title: 'No Proposal Threshold',
        description: 'Anyone can spam proposals without minimum stake.',
        location: 'Proposal creation',
        recommendation: 'Require minimum token holding to create proposals.',
      });
    }
    
    // SOL473: Treasury drain in single tx
    if (/treasury|vault/i.test(code) && 
        /withdraw|transfer/i.test(code) &&
        !/limit|cap|daily_max/.test(code)) {
      findings.push({
        id: 'SOL473',
        severity: 'critical',
        title: 'Treasury Can Be Drained in Single Transaction',
        description: 'Large treasury withdrawals should have limits or delays.',
        location: 'Treasury withdrawal',
        recommendation: 'Implement withdrawal limits and timelock for large amounts.',
      });
    }
    
    // SOL474: Execution timelock
    if (/execute.*proposal|proposal.*execute/i.test(code) && 
        !/timelock|delay|queue/.test(code)) {
      findings.push({
        id: 'SOL474',
        severity: 'high',
        title: 'No Execution Timelock',
        description: 'Passed proposals should have delay before execution.',
        location: 'Proposal execution',
        recommendation: 'Add mandatory timelock between passing and execution.',
      });
    }
    
    // SOL475: Quorum manipulation
    if (/quorum/i.test(code) && 
        !/min_participation|dynamic_quorum/.test(code)) {
      findings.push({
        id: 'SOL475',
        severity: 'high',
        title: 'Static Quorum Vulnerable',
        description: 'Fixed quorum can be gamed with low participation.',
        location: 'Quorum calculation',
        recommendation: 'Use dynamic quorum based on historical participation.',
      });
    }
    
    // SOL476: Vote buying
    if (/vote|delegate/i.test(code) && 
        /governance/i.test(code) &&
        !/commit_reveal|private_vote/.test(code)) {
      findings.push({
        id: 'SOL476',
        severity: 'medium',
        title: 'Votes Visible Before Close',
        description: 'Visible votes enable vote buying and manipulation.',
        location: 'Voting system',
        recommendation: 'Consider commit-reveal voting or shielded voting.',
      });
    }
    
    // SOL477: Guardian override
    if (/guardian|admin|emergency/i.test(code) && 
        /dao|treasury/i.test(code) &&
        !/multi_sig|threshold|timelock/.test(code)) {
      findings.push({
        id: 'SOL477',
        severity: 'critical',
        title: 'Single Guardian Can Override',
        description: 'Guardian powers should require multisig or timelock.',
        location: 'Guardian controls',
        recommendation: 'Require multisig for guardian actions.',
      });
    }
    
    // SOL478: Delegation security
    if (/delegate|delegation/i.test(code) && 
        !/revoke|undelegate|expire/.test(code)) {
      findings.push({
        id: 'SOL478',
        severity: 'medium',
        title: 'Delegation Cannot Be Revoked',
        description: 'Token holders should be able to revoke delegation.',
        location: 'Delegation system',
        recommendation: 'Implement delegation revocation and expiry.',
      });
    }
    
    // SOL479: Proposal calldata validation
    if (/proposal.*execute|call.*data/i.test(code) && 
        !/validate_call|whitelist|allowed_target/.test(code)) {
      findings.push({
        id: 'SOL479',
        severity: 'critical',
        title: 'Arbitrary Calldata in Proposals',
        description: 'Malicious proposals can execute arbitrary code.',
        location: 'Proposal execution',
        recommendation: 'Whitelist allowed proposal targets and validate calldata.',
      });
    }
    
    // SOL480: Veto power abuse
    if (/veto/i.test(code) && 
        !/time_limit|override|sunset/.test(code)) {
      findings.push({
        id: 'SOL480',
        severity: 'high',
        title: 'Unlimited Veto Power',
        description: 'Permanent veto power can freeze governance.',
        location: 'Veto mechanism',
        recommendation: 'Add veto override mechanism or sunset veto power.',
      });
    }
  }
  
  return findings;
}
