import type { Finding } from '../commands/audit.js';
import type { PatternInput } from './index.js';

const DEPRECATED_FUNCTIONS = [
  { pattern: /verify_signatures_of_signing_authorities/g, name: 'verify_signatures_of_signing_authorities', replacement: 'verify_signatures' },
  { pattern: /load_current_index\s*\(/g, name: 'load_current_index', replacement: 'load_current_index_checked' },
  { pattern: /invoke_signed_unchecked/g, name: 'invoke_signed_unchecked', replacement: 'invoke_signed' },
  { pattern: /deserialize_unchecked/g, name: 'deserialize_unchecked', replacement: 'try_from_slice_unchecked with validation' },
  { pattern: /try_accounts_raw/g, name: 'try_accounts_raw', replacement: 'try_accounts' },
  { pattern: /AccountSerialize::try_serialize_unchecked/g, name: 'try_serialize_unchecked', replacement: 'try_serialize' },
  { pattern: /solana_program::sysvar::clock::Clock::get_without_validation/g, name: 'Clock::get_without_validation', replacement: 'Clock::get' },
  { pattern: /legacy_verify_signatures/g, name: 'legacy_verify_signatures', replacement: 'modern verification methods' },
  { pattern: /deprecated_invoke/g, name: 'deprecated_invoke', replacement: 'invoke or invoke_signed' },
  { pattern: /#\[deprecated\][\s\S]*?fn\s+(\w+)/gm, name: 'deprecated function call', replacement: 'non-deprecated alternative' },
];

const UNSAFE_LEGACY_PATTERNS = [
  { pattern: /\.to_account_info_unchecked\s*\(\)/g, name: 'to_account_info_unchecked' },
  { pattern: /AccountInfo::try_from_unchecked/g, name: 'AccountInfo::try_from_unchecked' },
  { pattern: /Pack::unpack_unchecked/g, name: 'Pack::unpack_unchecked' },
  { pattern: /BorshDeserialize::deserialize_unchecked/g, name: 'BorshDeserialize::deserialize_unchecked' },
];

export function checkDeprecatedFunction(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  const content = input.rust?.content || '';
  const fileName = input.rust?.filePath || 'unknown';

  for (const { pattern, name, replacement } of DEPRECATED_FUNCTIONS) {
    const matches = content.matchAll(pattern);
    for (const match of matches) {
      const lineNumber = content.substring(0, match.index).split('\n').length;
      findings.push({
        id: 'SOL151',
        title: `Deprecated Function: ${name}`,
        severity: 'high',
        description: `Use of deprecated function '${name}' detected. This function may have known security vulnerabilities or has been superseded by safer alternatives. The Wormhole exploit ($326M) was caused by using a deprecated signature verification function.`,
        location: { file: fileName, line: lineNumber },
        recommendation: `Replace with ${replacement}. Review the migration guide for the updated function and ensure all security checks are preserved.`,
      });
    }
  }

  for (const { pattern, name } of UNSAFE_LEGACY_PATTERNS) {
    const matches = content.matchAll(pattern);
    for (const match of matches) {
      const lineNumber = content.substring(0, match.index).split('\n').length;
      findings.push({
        id: 'SOL151',
        title: `Unsafe Legacy Pattern: ${name}`,
        severity: 'critical',
        description: `Use of unsafe legacy pattern '${name}' detected. These patterns bypass critical validation checks and should never be used in production code.`,
        location: { file: fileName, line: lineNumber },
        recommendation: `Use the checked/validated version of this function. Ensure all account data is properly validated before use.`,
      });
    }
  }

  return findings;
}
