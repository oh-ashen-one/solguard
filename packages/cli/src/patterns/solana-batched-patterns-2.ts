import type { Finding } from '../commands/audit.js';
import type { PatternInput } from './index.js';

/** SOL236: Floating Point Usage */
export function checkFloatingPoint(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  const { rust, path } = input;
  if (!rust) return findings;
  const lines = rust.content.split('\n');
  for (let i = 0; i < lines.length; i++) {
    if (/f32|f64|\.0f/.test(lines[i])) {
      findings.push({ id: 'SOL236', severity: 'high', title: 'Floating Point Usage', description: 'Floating point in financial calculations.', location: { file: path, line: i + 1 }, recommendation: 'Use fixed-point arithmetic.' });
    }
  }
  return findings;
}

/** SOL237: Modulo Bias */
export function checkModuloBias(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  const { rust, path } = input;
  if (!rust) return findings;
  const lines = rust.content.split('\n');
  for (let i = 0; i < lines.length; i++) {
    if (/%\s*\d+/.test(lines[i]) && (lines[i].includes('random') || lines[i].includes('rand'))) {
      findings.push({ id: 'SOL237', severity: 'medium', title: 'Modulo Bias', description: 'Random with modulo may have bias.', location: { file: path, line: i + 1 }, recommendation: 'Use proper uniform distribution.' });
    }
  }
  return findings;
}

/** SOL238: Weak Randomness */
export function checkWeakRandomness(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  const { rust, path } = input;
  if (!rust) return findings;
  const lines = rust.content.split('\n');
  for (let i = 0; i < lines.length; i++) {
    if (/clock.*random|slot.*random|timestamp.*seed/i.test(lines[i])) {
      findings.push({ id: 'SOL238', severity: 'critical', title: 'Weak Randomness', description: 'Using predictable values for randomness.', location: { file: path, line: i + 1 }, recommendation: 'Use VRF or commit-reveal scheme.' });
    }
  }
  return findings;
}

/** SOL239: Magic Number */
export function checkMagicNumber(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  const { rust, path } = input;
  if (!rust) return findings;
  const lines = rust.content.split('\n');
  for (let i = 0; i < lines.length; i++) {
    if (/[^0-9]\d{4,}[^0-9]/.test(lines[i]) && !lines[i].includes('const') && !lines[i].includes('//')) {
      findings.push({ id: 'SOL239', severity: 'low', title: 'Magic Number', description: 'Hardcoded numeric constant.', location: { file: path, line: i + 1 }, recommendation: 'Use named constants.' });
    }
  }
  return findings;
}

/** SOL240: Unchecked Array Index */
export function checkUncheckedArrayIndex(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  const { rust, path } = input;
  if (!rust) return findings;
  const lines = rust.content.split('\n');
  for (let i = 0; i < lines.length; i++) {
    if (/\[\s*\w+\s*\]/.test(lines[i]) && !lines[i].includes('get(') && !lines[i].includes('.len()')) {
      const context = lines.slice(Math.max(0, i-5), i).join('');
      if (!context.includes('if') && !context.includes('match') && !context.includes('len')) {
        // Skip if it looks like a type annotation
        if (!lines[i].includes(': [') && !lines[i].includes('-> [')) {
          findings.push({ id: 'SOL240', severity: 'high', title: 'Unchecked Array Index', description: 'Array access without bounds check.', location: { file: path, line: i + 1 }, recommendation: 'Use .get() for safe access.' });
        }
      }
    }
  }
  return findings;
}

/** SOL241: Empty Error Message */
export function checkEmptyErrorMessage(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  const { rust, path } = input;
  if (!rust) return findings;
  const lines = rust.content.split('\n');
  for (let i = 0; i < lines.length; i++) {
    if (/err!\s*\(\s*\)/.test(lines[i]) || /error!\s*\(\s*\)/.test(lines[i])) {
      findings.push({ id: 'SOL241', severity: 'low', title: 'Empty Error Message', description: 'Error without descriptive message.', location: { file: path, line: i + 1 }, recommendation: 'Add descriptive error messages.' });
    }
  }
  return findings;
}

/** SOL242: Dead Code */
export function checkDeadCode(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  const { rust, path } = input;
  if (!rust) return findings;
  const lines = rust.content.split('\n');
  for (let i = 0; i < lines.length; i++) {
    if (/return\s*;/.test(lines[i]) && lines[i+1] && lines[i+1].trim() && !lines[i+1].includes('}')) {
      findings.push({ id: 'SOL242', severity: 'low', title: 'Dead Code', description: 'Unreachable code after return.', location: { file: path, line: i + 2 }, recommendation: 'Remove dead code.' });
    }
  }
  return findings;
}

/** SOL243: Infinite Loop Risk */
export function checkInfiniteLoopRisk(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  const { rust, path } = input;
  if (!rust) return findings;
  const lines = rust.content.split('\n');
  for (let i = 0; i < lines.length; i++) {
    if (/loop\s*\{/.test(lines[i]) || /while\s+true/.test(lines[i])) {
      const context = lines.slice(i, Math.min(lines.length, i+20)).join('');
      if (!context.includes('break') && !context.includes('return')) {
        findings.push({ id: 'SOL243', severity: 'high', title: 'Infinite Loop Risk', description: 'Loop without apparent exit condition.', location: { file: path, line: i + 1 }, recommendation: 'Add explicit break conditions.' });
      }
    }
  }
  return findings;
}

/** SOL244: Recursion Without Limit */
export function checkUnboundedRecursion(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  const { rust, path } = input;
  if (!rust) return findings;
  // Simple heuristic: function calls itself
  const fnMatch = rust.content.match(/fn\s+(\w+)/g);
  if (fnMatch) {
    for (const fn of fnMatch) {
      const name = fn.replace('fn ', '');
      const fnRegex = new RegExp(`fn\\s+${name}[\\s\\S]*?${name}\\s*\\(`);
      if (fnRegex.test(rust.content)) {
        findings.push({ id: 'SOL244', severity: 'medium', title: 'Recursion Detected', description: `Function "${name}" may be recursive.`, location: { file: path, line: 1 }, recommendation: 'Add recursion depth limit.' });
      }
    }
  }
  return findings;
}

/** SOL245: Unchecked Arithmetic */
export function checkUncheckedArithmetic(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  const { rust, path } = input;
  if (!rust) return findings;
  const lines = rust.content.split('\n');
  for (let i = 0; i < lines.length; i++) {
    if (/[+\-*\/]\s*=/.test(lines[i]) && !lines[i].includes('checked') && !lines[i].includes('saturating')) {
      findings.push({ id: 'SOL245', severity: 'high', title: 'Unchecked Arithmetic', description: 'Arithmetic operation without overflow check.', location: { file: path, line: i + 1 }, recommendation: 'Use checked_* or saturating_* methods.' });
    }
  }
  return findings;
}
