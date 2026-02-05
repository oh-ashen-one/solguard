import type { Finding } from '../commands/audit.js';
import type { PatternInput } from './index.js';

export function checkInstructionGuard(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  const content = input.rust?.content || '';
  const fileName = input.rust?.filePath || 'unknown';

  // Check for atomic instruction requirements
  const criticalOps = [
    { pattern: /fn\s+(?:liquidate|settle|finalize)/gi, name: 'settlement operation' },
    { pattern: /fn\s+(?:claim|withdraw|redeem)/gi, name: 'withdrawal operation' },
    { pattern: /fn\s+(?:swap|exchange)/gi, name: 'swap operation' },
  ];

  for (const { pattern, name } of criticalOps) {
    const matches = [...content.matchAll(pattern)];
    for (const match of matches) {
      const contextEnd = Math.min(content.length, match.index! + 1500);
      const functionContext = content.substring(match.index!, contextEnd);
      
      // Check for instruction introspection
      const hasInstructionGuard = 
        functionContext.includes('Instructions') ||
        functionContext.includes('get_instruction_relative') ||
        functionContext.includes('load_current_index') ||
        functionContext.includes('sysvar::instructions');

      if (!hasInstructionGuard) {
        const lineNumber = content.substring(0, match.index).split('\n').length;
        findings.push({
          id: 'SOL162',
          title: `${name} Without Instruction Guard`,
          severity: 'high',
          description: `Critical ${name} without instruction introspection. Attackers can compose malicious instruction sequences (e.g., sandwich attacks).`,
          location: { file: fileName, line: lineNumber },
          recommendation: 'Use instruction introspection to verify no malicious instructions precede or follow this operation.',
        });
      }
    }
  }

  // Check for CPI guard protection
  if (content.includes('invoke') || content.includes('CpiContext')) {
    const cpiPattern = /invoke(?:_signed)?\s*\(/g;
    const matches = [...content.matchAll(cpiPattern)];
    
    for (const match of matches) {
      const contextStart = Math.max(0, match.index! - 500);
      const contextEnd = Math.min(content.length, match.index! + 500);
      const context = content.substring(contextStart, contextEnd);
      
      // Check if CPI is protected against re-entry
      if (!context.includes('cpi_guard') && !context.includes('reentrancy') && 
          !context.includes('lock') && !context.includes('in_progress')) {
        const lineNumber = content.substring(0, match.index).split('\n').length;
        findings.push({
          id: 'SOL162',
          title: 'CPI Without Guard Protection',
          severity: 'high',
          description: 'Cross-program invocation without apparent guard against reentrancy or malicious callbacks.',
          location: { file: fileName, line: lineNumber },
          recommendation: 'Set a guard flag before CPI and check it on entry. Consider using Token-2022 CPI guard extension.',
        });
      }
    }
  }

  // Check for missing privilege checks on sensitive instructions
  const sensitiveInstructions = [
    { pattern: /fn\s+(?:update_config|set_config|configure)/gi, name: 'configuration update' },
    { pattern: /fn\s+(?:set_authority|transfer_authority)/gi, name: 'authority transfer' },
    { pattern: /fn\s+(?:pause|unpause|freeze)/gi, name: 'pause control' },
    { pattern: /fn\s+(?:upgrade|migrate)/gi, name: 'upgrade operation' },
  ];

  for (const { pattern, name } of sensitiveInstructions) {
    const matches = [...content.matchAll(pattern)];
    for (const match of matches) {
      const contextEnd = Math.min(content.length, match.index! + 1000);
      const functionContext = content.substring(match.index!, contextEnd);
      
      const hasAuth = functionContext.includes('authority') || functionContext.includes('admin') ||
                      functionContext.includes('signer') || functionContext.includes('has_one');
      
      if (!hasAuth) {
        const lineNumber = content.substring(0, match.index).split('\n').length;
        findings.push({
          id: 'SOL162',
          title: `Unprotected ${name}`,
          severity: 'critical',
          description: `Sensitive ${name} without apparent authorization check. Anyone may be able to call this function.`,
          location: { file: fileName, line: lineNumber },
          recommendation: 'Add authority/admin signer check before allowing sensitive operations.',
        });
      }
    }
  }

  // Check for instruction data validation
  const instructionDataPattern = /instruction_data|ix_data|data\[/gi;
  const dataMatches = [...content.matchAll(instructionDataPattern)];
  
  for (const match of dataMatches) {
    const contextEnd = Math.min(content.length, match.index! + 400);
    const context = content.substring(match.index!, contextEnd);
    
    if (!context.includes('len()') && !context.includes('try_from_slice') && 
        !context.includes('deserialize')) {
      const lineNumber = content.substring(0, match.index).split('\n').length;
      findings.push({
        id: 'SOL162',
        title: 'Raw Instruction Data Access',
        severity: 'medium',
        description: 'Direct instruction data access without apparent validation or deserialization.',
        location: { file: fileName, line: lineNumber },
        recommendation: 'Use safe deserialization methods and validate instruction data structure.',
      });
    }
  }

  // Check for expected instruction count
  if (content.includes('instructions::') || content.includes('Instructions')) {
    const instructionAccessPattern = /load_instruction_at|get_instruction_relative/g;
    const instructionMatches = [...content.matchAll(instructionAccessPattern)];
    
    for (const match of instructionMatches) {
      const contextEnd = Math.min(content.length, match.index! + 600);
      const context = content.substring(match.index!, contextEnd);
      
      if (!context.includes('program_id') && !context.includes('expected_program')) {
        const lineNumber = content.substring(0, match.index).split('\n').length;
        findings.push({
          id: 'SOL162',
          title: 'Instruction Introspection Without Program Check',
          severity: 'medium',
          description: 'Loading instructions without verifying they come from expected programs.',
          location: { file: fileName, line: lineNumber },
          recommendation: 'Verify instruction.program_id matches expected program for security-sensitive checks.',
        });
      }
    }
  }

  return findings;
}
