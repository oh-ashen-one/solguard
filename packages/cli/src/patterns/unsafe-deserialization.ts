import type { Finding } from '../commands/audit.js';
import type { PatternInput } from './index.js';

export function checkUnsafeDeserialization(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  const content = input.rust?.content || '';
  const fileName = input.rust?.filePath || 'unknown';

  const unsafePatterns = [
    {
      pattern: /try_from_slice_unchecked/g,
      name: 'try_from_slice_unchecked',
      severity: 'critical' as const,
      description: 'Unchecked deserialization bypasses all validation. Attackers can craft malicious data to cause unexpected behavior.',
    },
    {
      pattern: /deserialize_unchecked/g,
      name: 'deserialize_unchecked',
      severity: 'critical' as const,
      description: 'Unchecked deserialization can process malformed data without validation.',
    },
    {
      pattern: /from_bytes_unchecked/g,
      name: 'from_bytes_unchecked',
      severity: 'critical' as const,
      description: 'Unchecked byte conversion can lead to invalid data interpretation.',
    },
    {
      pattern: /transmute\s*[:<]/g,
      name: 'std::mem::transmute',
      severity: 'critical' as const,
      description: 'Raw memory transmutation bypasses type safety and can cause undefined behavior.',
    },
    {
      pattern: /\.data\.borrow\(\)\[[\d:]+\]/g,
      name: 'raw data slice access',
      severity: 'high' as const,
      description: 'Direct data slice access without bounds checking can lead to panics or incorrect data.',
    },
    {
      pattern: /as_ptr\s*\(\)/g,
      name: 'raw pointer access',
      severity: 'high' as const,
      description: 'Raw pointer access bypasses Rust safety guarantees.',
    },
    {
      pattern: /unsafe\s*\{[\s\S]*?slice::from_raw_parts/g,
      name: 'unsafe slice creation',
      severity: 'critical' as const,
      description: 'Creating slices from raw pointers in unsafe blocks can lead to memory corruption.',
    },
  ];

  for (const { pattern, name, severity, description } of unsafePatterns) {
    const matches = [...content.matchAll(pattern)];
    for (const match of matches) {
      const lineNumber = content.substring(0, match.index).split('\n').length;
      findings.push({
        id: 'SOL155',
        title: `Unsafe Deserialization: ${name}`,
        severity,
        description,
        location: { file: fileName, line: lineNumber },
        recommendation: 'Use safe deserialization methods like try_from_slice() or Anchor\'s Account<T> which includes automatic validation.',
      });
    }
  }

  // Check for missing discriminator checks in manual deserialization
  const manualDeserPattern = /fn\s+(?:try_)?deserialize|impl.*Deserialize/g;
  const deserMatches = [...content.matchAll(manualDeserPattern)];
  for (const match of deserMatches) {
    const contextEnd = Math.min(content.length, match.index! + 500);
    const functionContext = content.substring(match.index!, contextEnd);
    
    if (!functionContext.includes('discriminator') && !functionContext.includes('DISCRIMINATOR')) {
      const lineNumber = content.substring(0, match.index).split('\n').length;
      findings.push({
        id: 'SOL155',
        title: 'Manual Deserialization Without Discriminator',
        severity: 'high',
        description: 'Custom deserialization logic without discriminator validation. Account type confusion attacks become possible.',
        location: { file: fileName, line: lineNumber },
        recommendation: 'Always validate account discriminator before deserializing to prevent type confusion attacks.',
      });
    }
  }

  // Check for unvalidated account data length
  const dataLenPattern = /\.data\.borrow\(\)/g;
  const dataMatches = [...content.matchAll(dataLenPattern)];
  for (const match of dataMatches) {
    const contextStart = Math.max(0, match.index! - 200);
    const contextEnd = Math.min(content.length, match.index! + 200);
    const context = content.substring(contextStart, contextEnd);
    
    if (!context.includes('.len()') && !context.includes('data_len')) {
      const lineNumber = content.substring(0, match.index).split('\n').length;
      findings.push({
        id: 'SOL155',
        title: 'Account Data Access Without Length Check',
        severity: 'medium',
        description: 'Account data accessed without checking length. Undersized accounts can cause panics or partial reads.',
        location: { file: fileName, line: lineNumber },
        recommendation: 'Always validate account data length before accessing: require!(account.data_len() >= EXPECTED_SIZE, Error)',
      });
    }
  }

  // Check for unsafe string handling
  const stringPatterns = [
    /String::from_utf8_unchecked/g,
    /str::from_utf8_unchecked/g,
    /CStr::from_ptr/g,
  ];

  for (const pattern of stringPatterns) {
    const matches = [...content.matchAll(pattern)];
    for (const match of matches) {
      const lineNumber = content.substring(0, match.index).split('\n').length;
      findings.push({
        id: 'SOL155',
        title: 'Unsafe String Deserialization',
        severity: 'high',
        description: 'Unchecked string conversion can cause undefined behavior if data is not valid UTF-8.',
        location: { file: fileName, line: lineNumber },
        recommendation: 'Use String::from_utf8() or str::from_utf8() which return Result and handle invalid input safely.',
      });
    }
  }

  return findings;
}
