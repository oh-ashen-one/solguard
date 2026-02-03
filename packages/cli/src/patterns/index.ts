import type { Finding } from '../commands/audit.js';
import type { ParsedIdl } from '../parsers/idl.js';
import type { ParsedRust } from '../parsers/rust.js';
import { checkMissingOwner } from './owner-check.js';
import { checkMissingSigner } from './signer-check.js';
import { checkIntegerOverflow } from './overflow.js';
import { checkPdaValidation } from './pda-validation.js';

export interface PatternInput {
  idl: ParsedIdl | null;
  rust: ParsedRust | null;
  path: string;
}

export interface Pattern {
  id: string;
  name: string;
  severity: 'critical' | 'high' | 'medium' | 'low' | 'info';
  run: (input: PatternInput) => Finding[];
}

// Pattern registry
const patterns: Pattern[] = [
  {
    id: 'SOL001',
    name: 'Missing Owner Check',
    severity: 'critical',
    run: checkMissingOwner,
  },
  {
    id: 'SOL002', 
    name: 'Missing Signer Check',
    severity: 'critical',
    run: checkMissingSigner,
  },
  {
    id: 'SOL003',
    name: 'Integer Overflow',
    severity: 'high',
    run: checkIntegerOverflow,
  },
  {
    id: 'SOL004',
    name: 'PDA Validation Gap',
    severity: 'high',
    run: checkPdaValidation,
  },
];

export async function runPatterns(input: PatternInput): Promise<Finding[]> {
  const findings: Finding[] = [];
  
  for (const pattern of patterns) {
    try {
      const patternFindings = pattern.run(input);
      findings.push(...patternFindings);
    } catch (error) {
      console.warn(`Pattern ${pattern.id} failed: ${error}`);
    }
  }
  
  // Sort by severity
  const severityOrder = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
  findings.sort((a, b) => severityOrder[a.severity] - severityOrder[b.severity]);
  
  return findings;
}

export function getPatternById(id: string): Pattern | undefined {
  return patterns.find(p => p.id === id);
}

export function listPatterns(): Pattern[] {
  return patterns;
}
