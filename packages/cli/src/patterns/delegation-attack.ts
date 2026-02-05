import type { Finding } from '../commands/audit.js';
import type { PatternInput } from './index.js';

export function checkDelegationAttack(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  const content = input.rust?.content || '';
  const fileName = input.rust?.filePath || 'unknown';

  // Check for unchecked delegate usage
  const delegatePatterns = [
    /delegate/gi,
    /delegated_amount/gi,
    /approve\s*\(/gi,
    /Approve\s*\{/gi,
  ];

  for (const pattern of delegatePatterns) {
    const matches = [...content.matchAll(pattern)];
    for (const match of matches) {
      const contextEnd = Math.min(content.length, match.index! + 1000);
      const functionContext = content.substring(match.index!, contextEnd);
      
      // Check for delegate authority validation
      if (functionContext.includes('delegate') && !functionContext.includes('delegate_authority') &&
          !functionContext.includes('delegate ==') && !functionContext.includes('has_delegate')) {
        const lineNumber = content.substring(0, match.index).split('\n').length;
        findings.push({
          id: 'SOL163',
          title: 'Delegate Used Without Validation',
          severity: 'high',
          description: 'Token delegation used without validating delegate authority. Unauthorized delegates may be able to transfer tokens.',
          location: { file: fileName, line: lineNumber },
          recommendation: 'Verify delegate matches expected authority before allowing delegated operations.',
        });
      }
    }
  }

  // Check for approval revocation issues
  const approvalPatterns = [
    /fn\s+approve/gi,
    /set_authority.*Approve/gi,
  ];

  for (const pattern of approvalPatterns) {
    const matches = [...content.matchAll(pattern)];
    for (const match of matches) {
      const contextEnd = Math.min(content.length, match.index! + 1000);
      const functionContext = content.substring(match.index!, contextEnd);
      
      // Check for unlimited approval
      if (functionContext.includes('u64::MAX') || functionContext.includes('U64_MAX')) {
        const lineNumber = content.substring(0, match.index).split('\n').length;
        findings.push({
          id: 'SOL163',
          title: 'Unlimited Token Approval',
          severity: 'high',
          description: 'Unlimited token approval granted (u64::MAX). Compromised delegate can drain entire balance.',
          location: { file: fileName, line: lineNumber },
          recommendation: 'Use exact amounts needed for approval. Implement approval revocation after use.',
        });
      }
    }
  }

  // Check for stake delegation vulnerabilities
  if (content.includes('stake') && content.includes('delegate')) {
    const stakeDelegatePattern = /delegate_stake|stake_delegate|delegation/gi;
    const matches = [...content.matchAll(stakeDelegatePattern)];
    
    for (const match of matches) {
      const contextEnd = Math.min(content.length, match.index! + 1500);
      const functionContext = content.substring(match.index!, contextEnd);
      
      // Check for validator verification
      if (!functionContext.includes('validator') && !functionContext.includes('vote_account')) {
        const lineNumber = content.substring(0, match.index).split('\n').length;
        findings.push({
          id: 'SOL163',
          title: 'Stake Delegation Without Validator Check',
          severity: 'high',
          description: 'Stake delegation without validator verification. Funds may be delegated to malicious validators.',
          location: { file: fileName, line: lineNumber },
          recommendation: 'Verify delegation target is a valid, trusted validator vote account.',
        });
      }

      // Check for deactivation cooldown
      if (functionContext.includes('undelegate') || functionContext.includes('deactivate')) {
        if (!functionContext.includes('epoch') && !functionContext.includes('cooldown')) {
          const lineNumber = content.substring(0, match.index).split('\n').length;
          findings.push({
            id: 'SOL163',
            title: 'Missing Delegation Cooldown',
            severity: 'medium',
            description: 'Undelegation without cooldown period check. May cause issues with Solana staking mechanics.',
            location: { file: fileName, line: lineNumber },
            recommendation: 'Implement proper cooldown period tracking for stake deactivation.',
          });
        }
      }
    }
  }

  // Check for governance delegation issues
  if (content.includes('governance') || content.includes('vote')) {
    const govDelegatePattern = /delegate_vote|voting_power|delegation/gi;
    const matches = [...content.matchAll(govDelegatePattern)];
    
    for (const match of matches) {
      const contextEnd = Math.min(content.length, match.index! + 1000);
      const functionContext = content.substring(match.index!, contextEnd);
      
      // Check for self-delegation
      if (!functionContext.includes('!= self') && !functionContext.includes('!= delegator')) {
        const lineNumber = content.substring(0, match.index).split('\n').length;
        findings.push({
          id: 'SOL163',
          title: 'Governance Self-Delegation Not Prevented',
          severity: 'low',
          description: 'Vote delegation may allow self-delegation which could cause loops or unexpected behavior.',
          location: { file: fileName, line: lineNumber },
          recommendation: 'Prevent self-delegation: require!(delegate != delegator)',
        });
      }

      // Check for delegation chain attacks
      if (!functionContext.includes('depth') && !functionContext.includes('max_delegation') &&
          !functionContext.includes('chain')) {
        const lineNumber = content.substring(0, match.index).split('\n').length;
        findings.push({
          id: 'SOL163',
          title: 'Unbounded Delegation Chain',
          severity: 'medium',
          description: 'Vote delegation without chain depth limit. Deep delegation chains can cause compute issues.',
          location: { file: fileName, line: lineNumber },
          recommendation: 'Implement maximum delegation chain depth or flatten delegations.',
        });
      }
    }
  }

  // Check for authority delegation without expiry
  const authorityDelegatePattern = /delegate_authority|temporary_authority|proxy/gi;
  const authMatches = [...content.matchAll(authorityDelegatePattern)];
  
  for (const match of authMatches) {
    const contextEnd = Math.min(content.length, match.index! + 800);
    const functionContext = content.substring(match.index!, contextEnd);
    
    if (!functionContext.includes('expiry') && !functionContext.includes('valid_until') &&
        !functionContext.includes('deadline') && !functionContext.includes('ttl')) {
      const lineNumber = content.substring(0, match.index).split('\n').length;
      findings.push({
        id: 'SOL163',
        title: 'Authority Delegation Without Expiry',
        severity: 'high',
        description: 'Authority delegated without expiration. Compromised delegates retain permanent access.',
        location: { file: fileName, line: lineNumber },
        recommendation: 'Add expiration timestamp to delegated authorities and validate before use.',
      });
    }
  }

  return findings;
}
