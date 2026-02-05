import type { Finding } from '../commands/audit.js';
import type { PatternInput } from './index.js';

export function checkEmergencyWithdraw(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  const content = input.rust?.content || '';
  const fileName = input.rust?.filePath || 'unknown';

  // Check if emergency functions exist
  const emergencyPatterns = [
    /fn\s+emergency_withdraw/gi,
    /fn\s+emergency_exit/gi,
    /fn\s+rescue/gi,
    /fn\s+recover/gi,
  ];

  let hasEmergencyFunction = false;
  for (const pattern of emergencyPatterns) {
    if (pattern.test(content)) {
      hasEmergencyFunction = true;
      
      const matches = [...content.matchAll(pattern)];
      for (const match of matches) {
        const contextEnd = Math.min(content.length, match.index! + 1500);
        const functionContext = content.substring(match.index!, contextEnd);
        
        // Check for proper access control
        if (!functionContext.includes('admin') && !functionContext.includes('authority') &&
            !functionContext.includes('emergency_admin') && !functionContext.includes('multisig')) {
          const lineNumber = content.substring(0, match.index).split('\n').length;
          findings.push({
            id: 'SOL168',
            title: 'Emergency Function Without Access Control',
            severity: 'critical',
            description: 'Emergency withdrawal function without apparent access control. Anyone may be able to drain funds.',
            location: { file: fileName, line: lineNumber },
            recommendation: 'Restrict emergency functions to authorized admin/multisig only.',
          });
        }

        // Check for event emission
        if (!functionContext.includes('emit!') && !functionContext.includes('event') &&
            !functionContext.includes('log')) {
          const lineNumber = content.substring(0, match.index).split('\n').length;
          findings.push({
            id: 'SOL168',
            title: 'Emergency Function Without Event',
            severity: 'medium',
            description: 'Emergency action without event emission. Hard to track emergency actions.',
            location: { file: fileName, line: lineNumber },
            recommendation: 'Emit event on emergency actions for transparency and monitoring.',
          });
        }
      }
    }
  }

  // Check if protocol has value but no emergency mechanism
  const hasValue = content.includes('transfer') || content.includes('vault') || 
                   content.includes('pool') || content.includes('treasury');
  
  if (hasValue && !hasEmergencyFunction) {
    findings.push({
      id: 'SOL168',
      title: 'No Emergency Withdrawal Mechanism',
      severity: 'high',
      description: 'Protocol handles value but has no emergency withdrawal. Funds may be locked during emergencies.',
      location: { file: fileName, line: 1 },
      recommendation: 'Implement emergency_withdraw function with proper access control for edge cases.',
    });
  }

  // Check for pause mechanism with emergency
  const pausePattern = /fn\s+(?:pause|freeze|halt)/gi;
  const pauseMatches = [...content.matchAll(pausePattern)];
  
  if (pauseMatches.length > 0) {
    for (const match of pauseMatches) {
      const contextEnd = Math.min(content.length, match.index! + 1000);
      const functionContext = content.substring(match.index!, contextEnd);
      
      // Check for unpause capability
      if (!content.includes('unpause') && !content.includes('resume') && 
          !content.includes('unfreeze')) {
        const lineNumber = content.substring(0, match.index).split('\n').length;
        findings.push({
          id: 'SOL168',
          title: 'Pause Without Unpause',
          severity: 'high',
          description: 'Pause function exists but no apparent unpause. Protocol may be permanently halted.',
          location: { file: fileName, line: lineNumber },
          recommendation: 'Implement unpause function or automatic timeout for pause.',
        });
      }

      // Check if emergency withdraw still works when paused
      if (!functionContext.includes('emergency')) {
        const lineNumber = content.substring(0, match.index).split('\n').length;
        findings.push({
          id: 'SOL168',
          title: 'Pause May Block Emergency Functions',
          severity: 'medium',
          description: 'Pause mechanism may block emergency withdrawals. Users could be trapped.',
          location: { file: fileName, line: lineNumber },
          recommendation: 'Ensure emergency_withdraw bypasses pause state for user protection.',
        });
      }
    }
  }

  // Check for timelocked emergency actions
  if (hasEmergencyFunction) {
    if (!content.includes('timelock') && !content.includes('delay') && 
        !content.includes('pending_admin')) {
      findings.push({
        id: 'SOL168',
        title: 'Emergency Actions Without Timelock',
        severity: 'medium',
        description: 'Emergency functions can be executed immediately. Malicious admin has instant power.',
        location: { file: fileName, line: 1 },
        recommendation: 'Consider timelock for non-critical emergency actions to allow user response.',
      });
    }
  }

  // Check for sweep/recover functions
  const sweepPattern = /fn\s+sweep|fn\s+recover_tokens/gi;
  const sweepMatches = [...content.matchAll(sweepPattern)];
  
  for (const match of sweepMatches) {
    const contextEnd = Math.min(content.length, match.index! + 1000);
    const functionContext = content.substring(match.index!, contextEnd);
    
    // Check if sweep can take user funds
    if (!functionContext.includes('dust') && !functionContext.includes('excess') &&
        !functionContext.includes('!=') && !functionContext.includes('whitelist')) {
      const lineNumber = content.substring(0, match.index).split('\n').length;
      findings.push({
        id: 'SOL168',
        title: 'Sweep Function May Drain User Funds',
        severity: 'critical',
        description: 'Token sweep function without proper restrictions. Could be used to drain any token.',
        location: { file: fileName, line: lineNumber },
        recommendation: 'Restrict sweep to excess/dust amounts. Blacklist user deposit tokens from sweep.',
      });
    }
  }

  // Check for guardian/multisig requirement
  if (hasEmergencyFunction && !content.includes('multisig') && 
      !content.includes('guardian') && !content.includes('committee')) {
    findings.push({
      id: 'SOL168',
      title: 'Emergency Without Multi-Party Control',
      severity: 'high',
      description: 'Emergency functions controlled by single key. Compromised key can drain all funds.',
      location: { file: fileName, line: 1 },
      recommendation: 'Use multisig or guardian committee for emergency actions.',
    });
  }

  return findings;
}
