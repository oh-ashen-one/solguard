import type { Finding } from '../commands/audit.js';
import type { PatternInput } from './index.js';

/**
 * SEC3 2025 Report: Input Validation & Data Hygiene Patterns (25% of vulnerabilities)
 * Based on Sec3's analysis of 163 Solana security audits
 * Second most common vulnerability category
 */
export function checkSec32025InputValidation(input: PatternInput): Finding[] {
  const findings: Finding[] = [];

  if (input.rust?.content) {
    const content = input.rust.content;
    const lines = content.split('\n');

    for (let i = 0; i < lines.length; i++) {
      const line = lines[i];
      const context = lines.slice(Math.max(0, i - 5), Math.min(lines.length, i + 10)).join('\n');

      // IV001: Instruction Data Size Not Validated
      if (line.includes('instruction_data') || line.includes('data: &[u8]')) {
        if (!context.includes('.len()') && !context.includes('size_of')) {
          findings.push({
            id: 'SEC3-IV001',
            title: 'Instruction Data Size Not Validated',
            severity: 'high',
            description: 'Instruction data should have size validation before deserialization.',
            location: { file: input.path, line: i + 1 },
            suggestion: 'Check: require!(data.len() >= MIN_SIZE && data.len() <= MAX_SIZE, InvalidDataLength)',
            cwe: 'CWE-20',
          });
        }
      }

      // IV002: String/Bytes Length Unbounded
      if ((line.includes('String') || line.includes('Vec<u8>')) && 
          line.includes('pub ') && !line.includes('//')) {
        if (!context.includes('max_len') && !context.includes('MAX_') &&
            !context.includes('#[max_len')) {
          findings.push({
            id: 'SEC3-IV002',
            title: 'Unbounded String/Bytes Field',
            severity: 'medium',
            description: 'String or byte vector without maximum length constraint can cause DoS.',
            location: { file: input.path, line: i + 1 },
            suggestion: 'Add Anchor constraint: #[max_len(256)] or validate length manually.',
            cwe: 'CWE-400',
          });
        }
      }

      // IV003: Numeric Range Not Checked
      if ((line.includes('amount') || line.includes('quantity') || line.includes('price')) &&
          line.includes(': u') && !line.includes('//')) {
        if (!context.includes('> 0') && !context.includes('!= 0') &&
            !context.includes('require!') && !context.includes('assert!')) {
          findings.push({
            id: 'SEC3-IV003',
            title: 'Numeric Input Without Range Validation',
            severity: 'medium',
            description: 'Numeric inputs should be validated for acceptable ranges.',
            location: { file: input.path, line: i + 1 },
            suggestion: 'Add validation: require!(amount > 0 && amount <= MAX_AMOUNT, InvalidAmount)',
            cwe: 'CWE-20',
          });
        }
      }

      // IV004: Timestamp Input Not Sanitized
      if ((line.includes('timestamp') || line.includes('expiry') || line.includes('deadline')) &&
          !line.includes('clock.unix_timestamp')) {
        if (line.includes(': i64') || line.includes(': u64')) {
          findings.push({
            id: 'SEC3-IV004',
            title: 'Timestamp Input Not Clock-Validated',
            severity: 'high',
            description: 'User-provided timestamps should be validated against on-chain clock.',
            location: { file: input.path, line: i + 1 },
            suggestion: 'Compare to clock: require!(timestamp > clock.unix_timestamp, TimestampInPast)',
            cwe: 'CWE-20',
          });
        }
      }

      // IV005: Pubkey Array Unbounded
      if (line.includes('Vec<Pubkey>') && !context.includes('max_len') && !context.includes('MAX_')) {
        findings.push({
          id: 'SEC3-IV005',
          title: 'Unbounded Pubkey Array',
          severity: 'medium',
          description: 'Arrays of pubkeys without bounds can cause compute exhaustion.',
          location: { file: input.path, line: i + 1 },
          suggestion: 'Limit array size: require!(accounts.len() <= MAX_ACCOUNTS, TooManyAccounts)',
          cwe: 'CWE-400',
        });
      }

      // IV006: Mint Decimals Assumption
      if (line.includes('decimals') && (line.includes('9') || line.includes('6'))) {
        if (!context.includes('mint.decimals') && !context.includes('.decimals')) {
          findings.push({
            id: 'SEC3-IV006',
            title: 'Hardcoded Decimal Assumption',
            severity: 'high',
            description: 'Hardcoded decimal values instead of reading from mint. Different tokens have different decimals.',
            location: { file: input.path, line: i + 1 },
            suggestion: 'Always read decimals from mint account: let decimals = ctx.accounts.mint.decimals;',
            cwe: 'CWE-682',
          });
        }
      }

      // IV007: Seed Input Not Sanitized
      if (line.includes('seeds') && line.includes('&[')) {
        if (context.includes('as &[u8]') && !context.includes('validate') &&
            !context.includes('.len()')) {
          findings.push({
            id: 'SEC3-IV007',
            title: 'PDA Seed Input Not Sanitized',
            severity: 'high',
            description: 'User-provided PDA seeds should be length-validated to prevent collision attacks.',
            location: { file: input.path, line: i + 1 },
            suggestion: 'Validate seed length: require!(seed.len() <= 32, SeedTooLong)',
            cwe: 'CWE-20',
          });
        }
      }

      // IV008: Enum Variant Not Bounded
      if (line.includes('as u8') && context.includes('enum') && !context.includes('TryFrom')) {
        findings.push({
          id: 'SEC3-IV008',
          title: 'Enum Cast Without Bounds Check',
          severity: 'medium',
          description: 'Casting integers to enums should use TryFrom to validate variants.',
          location: { file: input.path, line: i + 1 },
          suggestion: 'Use TryFrom: let variant = MyEnum::try_from(value).map_err(|_| InvalidVariant)?;',
          cwe: 'CWE-20',
        });
      }

      // IV009: Account Data Deserialization Without Size Check
      if ((line.includes('try_from_slice') || line.includes('deserialize')) &&
          !context.includes('.len()') && !context.includes('size_of')) {
        findings.push({
          id: 'SEC3-IV009',
          title: 'Deserialization Without Size Validation',
          severity: 'high',
          description: 'Deserializing account data without size check can cause panics or read garbage.',
          location: { file: input.path, line: i + 1 },
          suggestion: 'Check size before deserializing: require!(data.len() >= std::mem::size_of::<T>())',
          cwe: 'CWE-502',
        });
      }

      // IV010: Slippage Parameter Unchecked
      if ((line.includes('slippage') || line.includes('min_out') || line.includes('max_in')) &&
          !context.includes('require!') && !context.includes('assert!')) {
        findings.push({
          id: 'SEC3-IV010',
          title: 'Slippage Parameter Not Enforced',
          severity: 'high',
          description: 'Slippage parameters must be enforced to protect users from sandwich attacks.',
          location: { file: input.path, line: i + 1 },
          suggestion: 'Enforce: require!(actual_output >= min_output, SlippageExceeded)',
          cwe: 'CWE-20',
        });
      }
    }
  }

  return findings;
}
