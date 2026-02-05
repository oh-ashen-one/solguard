import type { Finding } from '../commands/audit.js';
import type { PatternInput } from './index.js';

/**
 * SOL304: Semantic Inconsistency Detection
 * Detects logical inconsistencies between related operations
 * Real-world: Solana Stake Pool semantic inconsistency (Sec3)
 */
export function checkSemanticInconsistency(input: PatternInput): Finding[] {
  const findings: Finding[] = [];

  if (input.rust?.content) {
    const content = input.rust.content;
    const lines = content.split('\n');

    // Track function pairs that should be symmetric
    const symmetricOps = [
      { deposit: 'withdraw', stake: 'unstake', lock: 'unlock', mint: 'burn' },
    ];

    // Find all function definitions
    const functions: { name: string; line: number; body: string }[] = [];
    let currentFunc = '';
    let funcStart = 0;
    let braceCount = 0;
    let funcBody = '';

    for (let i = 0; i < lines.length; i++) {
      const line = lines[i];
      const funcMatch = line.match(/pub\s+fn\s+(\w+)/);
      
      if (funcMatch && braceCount === 0) {
        if (currentFunc) {
          functions.push({ name: currentFunc, line: funcStart, body: funcBody });
        }
        currentFunc = funcMatch[1];
        funcStart = i + 1;
        funcBody = '';
      }

      if (currentFunc) {
        braceCount += (line.match(/\{/g) || []).length;
        braceCount -= (line.match(/\}/g) || []).length;
        funcBody += line + '\n';
      }
    }
    if (currentFunc) {
      functions.push({ name: currentFunc, line: funcStart, body: funcBody });
    }

    // Check for symmetric operation inconsistencies
    for (const pair of Object.entries(symmetricOps[0])) {
      const [op1, op2] = pair;
      const func1 = functions.find(f => f.name.includes(op1));
      const func2 = functions.find(f => f.name.includes(op2));

      if (func1 && func2) {
        // Check if validation patterns are symmetric
        const hasOwnerCheck1 = /owner|authority/.test(func1.body);
        const hasOwnerCheck2 = /owner|authority/.test(func2.body);
        
        if (hasOwnerCheck1 !== hasOwnerCheck2) {
          findings.push({
            id: 'SOL304',
            title: 'Asymmetric Authority Validation',
            severity: 'critical',
            description: `${op1} and ${op2} have inconsistent authority checks. Both should validate ownership.`,
            location: { file: input.path, line: hasOwnerCheck1 ? func2.line : func1.line },
            suggestion: 'Ensure symmetric validation: both operations must check authority consistently',
            cwe: 'CWE-863',
          });
        }

        // Check for state validation consistency
        const hasStateCheck1 = /state|status|is_/.test(func1.body);
        const hasStateCheck2 = /state|status|is_/.test(func2.body);
        
        if (hasStateCheck1 && !hasStateCheck2) {
          findings.push({
            id: 'SOL304',
            title: 'Missing State Validation',
            severity: 'high',
            description: `${op2} lacks state validation that ${op1} has. Operations should be semantically consistent.`,
            location: { file: input.path, line: func2.line },
            suggestion: `Add state check in ${op2}: require!(account.state == ExpectedState, InvalidState)`,
            cwe: 'CWE-672',
          });
        }
      }
    }

    // Check for calculation consistency
    const calcPatterns = /\.checked_add|\.checked_sub|\.checked_mul|\.checked_div/g;
    
    for (let i = 0; i < lines.length; i++) {
      const line = lines[i];
      
      // Inconsistent checked vs unchecked math
      if ((line.includes(' + ') || line.includes(' - ') || line.includes(' * ') || line.includes(' / ')) 
          && !line.includes('//') && !line.includes('checked_')) {
        const nearbyLines = lines.slice(Math.max(0, i - 10), Math.min(lines.length, i + 10)).join('\n');
        if (nearbyLines.match(calcPatterns)) {
          findings.push({
            id: 'SOL304',
            title: 'Inconsistent Math Safety',
            severity: 'high',
            description: 'Mix of checked and unchecked math in same context creates semantic inconsistency.',
            location: { file: input.path, line: i + 1 },
            suggestion: 'Use checked math consistently: amount.checked_add(fee).ok_or(MathError)?',
            cwe: 'CWE-682',
          });
          break;
        }
      }
    }

    // Check for event emission consistency
    const emitPatterns = /emit!|emit_cpi|log_instruction/;
    const eventFuncs = functions.filter(f => emitPatterns.test(f.body));
    const noEventFuncs = functions.filter(f => !emitPatterns.test(f.body) && 
      /transfer|deposit|withdraw|stake|unstake|swap/.test(f.name));

    if (eventFuncs.length > 0 && noEventFuncs.length > 0) {
      for (const func of noEventFuncs) {
        findings.push({
          id: 'SOL304',
          title: 'Inconsistent Event Emission',
          severity: 'medium',
          description: `${func.name} doesn't emit events while similar functions do. This creates tracking gaps.`,
          location: { file: input.path, line: func.line },
          suggestion: `Add event emission: emit!(${func.name.charAt(0).toUpperCase() + func.name.slice(1)}Event { ... })`,
          cwe: 'CWE-778',
        });
      }
    }
  }

  return findings;
}
