import type { Finding } from '../commands/audit.js';
import type { PatternInput } from './index.js';

export function checkVoteManipulation(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  const content = input.rust?.content || '';
  const fileName = input.rust?.filePath || 'unknown';

  // Check for voting power snapshot
  const votePatterns = [
    /fn\s+(?:cast_)?vote/gi,
    /voting_power/gi,
    /vote_weight/gi,
  ];

  for (const pattern of votePatterns) {
    const matches = [...content.matchAll(pattern)];
    for (const match of matches) {
      const contextEnd = Math.min(content.length, match.index! + 1500);
      const functionContext = content.substring(match.index!, contextEnd);
      
      // Check for snapshot mechanism
      if (!functionContext.includes('snapshot') && !functionContext.includes('checkpoint') &&
          !functionContext.includes('block_height') && !functionContext.includes('slot')) {
        const lineNumber = content.substring(0, match.index).split('\n').length;
        findings.push({
          id: 'SOL167',
          title: 'Vote Without Snapshot',
          severity: 'critical',
          description: 'Voting without power snapshot. Users can borrow tokens to vote, then return them immediately.',
          location: { file: fileName, line: lineNumber },
          recommendation: 'Snapshot voting power at proposal creation. Use checkpoints for historical balance.',
        });
      }
    }
  }

  // Check for double voting
  const voteCastPattern = /fn\s+(?:cast_)?vote\s*\(/gi;
  const voteCastMatches = [...content.matchAll(voteCastPattern)];
  
  for (const match of voteCastMatches) {
    const contextEnd = Math.min(content.length, match.index! + 1000);
    const functionContext = content.substring(match.index!, contextEnd);
    
    // Check for vote record
    if (!functionContext.includes('has_voted') && !functionContext.includes('vote_record') &&
        !functionContext.includes('voter_info')) {
      const lineNumber = content.substring(0, match.index).split('\n').length;
      findings.push({
        id: 'SOL167',
        title: 'No Double Vote Prevention',
        severity: 'critical',
        description: 'Vote function without checking if user already voted. Double voting may be possible.',
        location: { file: fileName, line: lineNumber },
        recommendation: 'Track voter records per proposal and reject duplicate votes.',
      });
    }
  }

  // Check for proposal spam prevention
  const proposalPattern = /fn\s+create_proposal/gi;
  const proposalMatches = [...content.matchAll(proposalPattern)];
  
  for (const match of proposalMatches) {
    const contextEnd = Math.min(content.length, match.index! + 1500);
    const functionContext = content.substring(match.index!, contextEnd);
    
    // Check for proposal threshold
    if (!functionContext.includes('threshold') && !functionContext.includes('min_tokens') &&
        !functionContext.includes('proposer_balance')) {
      const lineNumber = content.substring(0, match.index).split('\n').length;
      findings.push({
        id: 'SOL167',
        title: 'Proposal Creation Without Threshold',
        severity: 'high',
        description: 'No minimum token threshold to create proposals. Spam proposals can overwhelm governance.',
        location: { file: fileName, line: lineNumber },
        recommendation: 'Require minimum token balance or stake to create proposals.',
      });
    }

    // Check for proposal cooldown
    if (!functionContext.includes('cooldown') && !functionContext.includes('last_proposal') &&
        !functionContext.includes('rate_limit')) {
      const lineNumber = content.substring(0, match.index).split('\n').length;
      findings.push({
        id: 'SOL167',
        title: 'Proposal Creation Without Rate Limit',
        severity: 'medium',
        description: 'No rate limiting on proposal creation. Single user can flood governance.',
        location: { file: fileName, line: lineNumber },
        recommendation: 'Implement cooldown period between proposals from same address.',
      });
    }
  }

  // Check for quorum requirements
  if (content.includes('vote') || content.includes('proposal')) {
    const quorumPatterns = ['quorum', 'min_votes', 'participation_threshold'];
    const hasQuorum = quorumPatterns.some(p => content.includes(p));
    
    if (!hasQuorum) {
      findings.push({
        id: 'SOL167',
        title: 'Governance Without Quorum',
        severity: 'high',
        description: 'Voting without quorum requirements. Low participation proposals can pass easily.',
        location: { file: fileName, line: 1 },
        recommendation: 'Implement minimum quorum (e.g., 10% of total supply must vote for proposal to be valid).',
      });
    }
  }

  // Check for timelock on execution
  const executePattern = /fn\s+execute_proposal/gi;
  const executeMatches = [...content.matchAll(executePattern)];
  
  for (const match of executeMatches) {
    const contextEnd = Math.min(content.length, match.index! + 1000);
    const functionContext = content.substring(match.index!, contextEnd);
    
    if (!functionContext.includes('timelock') && !functionContext.includes('delay') &&
        !functionContext.includes('eta') && !functionContext.includes('execution_time')) {
      const lineNumber = content.substring(0, match.index).split('\n').length;
      findings.push({
        id: 'SOL167',
        title: 'Proposal Execution Without Timelock',
        severity: 'high',
        description: 'Proposal executed immediately after passing. No time for users to exit if they disagree.',
        location: { file: fileName, line: lineNumber },
        recommendation: 'Implement execution timelock (e.g., 24-48 hours) after proposal passes.',
      });
    }
  }

  // Check for vote delegation attacks
  if (content.includes('delegate') && content.includes('vote')) {
    const delegatePattern = /delegate_vote|voting_delegate/gi;
    const delegateMatches = [...content.matchAll(delegatePattern)];
    
    for (const match of delegateMatches) {
      const contextEnd = Math.min(content.length, match.index! + 800);
      const functionContext = content.substring(match.index!, contextEnd);
      
      // Check for delegation before vote
      if (!functionContext.includes('snapshot') && !functionContext.includes('before_vote')) {
        const lineNumber = content.substring(0, match.index).split('\n').length;
        findings.push({
          id: 'SOL167',
          title: 'Vote Delegation Timing Attack',
          severity: 'high',
          description: 'Delegation may be changed after proposal creation but before voting ends.',
          location: { file: fileName, line: lineNumber },
          recommendation: 'Snapshot delegation at proposal creation or lock delegation during voting.',
        });
      }
    }
  }

  return findings;
}
