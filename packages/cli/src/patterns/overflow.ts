import type { Finding } from '../commands/audit.js';
import type { PatternInput } from './index.js';
import { findUncheckedArithmetic } from '../parsers/rust.js';

export function checkIntegerOverflow(input: PatternInput): Finding[] {
  const findings: Finding[] = [];

  if (!input.rust) return findings;

  const issues = findUncheckedArithmetic(input.rust);
  
  for (const issue of issues) {
    // Filter out false positives (common safe patterns)
    if (isSafeArithmetic(issue.code)) continue;
    
    findings.push({
      id: `SOL003-${findings.length + 1}`,
      pattern: 'Integer Overflow',
      severity: 'high',
      title: 'Potential integer overflow in arithmetic operation',
      description: `Unchecked arithmetic operation found. In Rust, integer overflow in release mode wraps around silently, which can lead to serious vulnerabilities like incorrect balances or bypassed checks.`,
      location: {
        file: issue.file,
        line: issue.line,
      },
      code: issue.code,
      suggestion: `Use checked arithmetic:\nlet result = a.checked_add(b).ok_or(ErrorCode::Overflow)?;\n\nOr saturating arithmetic:\nlet result = a.saturating_add(b);`,
    });
  }

  return findings;
}

function isSafeArithmetic(code: string): boolean {
  // Skip if using checked or saturating operations
  if (/\.checked_|\.saturating_|\.overflowing_/.test(code)) return true;
  
  // Skip obvious non-numeric operations (string concatenation, etc.)
  if (/\".*\"/.test(code)) return true;
  
  // Skip loop counters (usually safe)
  if (/for\s+\w+\s+in/.test(code)) return true;
  
  // Skip array indexing
  if (/\[\s*\w+\s*\+\s*\d+\s*\]/.test(code)) return true;
  
  // Skip if it's just incrementing by 1 (usually loop counter)
  if (/\+\s*1\s*[;\)]/.test(code) && !/amount|balance|value|price|total/i.test(code)) return true;
  
  return false;
}
