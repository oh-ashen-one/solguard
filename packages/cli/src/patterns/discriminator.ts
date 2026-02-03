import type { Finding } from '../commands/audit.js';
import type { PatternInput } from './index.js';

/**
 * SOL079: Account Discriminator Security
 * Detects missing or improper account discriminator handling
 */
export function checkDiscriminator(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  const rust = input.rust;

  if (!rust || !rust.content) return findings;

  // Check for manual deserialization without discriminator
  if (rust.content.includes('try_from_slice') || rust.content.includes('deserialize')) {
    if (!rust.content.includes('discriminator') && 
        !rust.content.includes('DISCRIMINATOR') &&
        !rust.content.includes('[8..]')) {
      findings.push({
        id: 'SOL079',
        severity: 'critical',
        title: 'Deserialization Without Discriminator Check',
        description: 'Account data deserialized without checking discriminator bytes',
        location: input.path,
        recommendation: 'Check first 8 bytes match expected discriminator before deserializing',
      });
    }
  }

  // Check for #[account] without proper initialization
  if (rust.content.includes('#[account]') && rust.content.includes('pub struct')) {
    // Anchor handles discriminators automatically, but check for manual structs
    if (!rust.content.includes('#[derive(') && rust.content.includes('borsh')) {
      findings.push({
        id: 'SOL079',
        severity: 'high',
        title: 'Manual Account Struct Without Discriminator',
        description: 'Account struct may lack automatic discriminator from Anchor',
        location: input.path,
        recommendation: 'Use Anchor #[account] macro or implement manual discriminator field',
      });
    }
  }

  // Check for hardcoded discriminator values
  const hardcodedDiscriminator = /discriminator\s*==?\s*\[\s*\d+\s*,\s*\d+/;
  if (hardcodedDiscriminator.test(rust.content)) {
    findings.push({
      id: 'SOL079',
      severity: 'low',
      title: 'Hardcoded Discriminator Values',
      description: 'Discriminator compared against hardcoded bytes instead of computed constant',
      location: input.path,
      recommendation: 'Use computed discriminator: sha256("account:AccountName")[..8]',
    });
  }

  // Check for discriminator length
  if (rust.content.includes('discriminator') && rust.content.includes('len()')) {
    const wrongLength = /discriminator[\s\S]*?(?:4|16|32)\s*\)/;
    if (wrongLength.test(rust.content)) {
      findings.push({
        id: 'SOL079',
        severity: 'medium',
        title: 'Non-Standard Discriminator Length',
        description: 'Discriminator not using standard 8-byte length',
        location: input.path,
        recommendation: 'Use 8-byte discriminators for Anchor compatibility',
      });
    }
  }

  // Check for missing space calculation with discriminator
  if (rust.content.includes('space') && rust.content.includes('init')) {
    if (!rust.content.includes('8 +') && !rust.content.includes('+ 8')) {
      // Check if space might not include discriminator
      const spaceCalc = /space\s*=\s*\d+[^+]/;
      if (spaceCalc.test(rust.content)) {
        findings.push({
          id: 'SOL079',
          severity: 'medium',
          title: 'Space May Not Include Discriminator',
          description: 'Account space calculation may not account for 8-byte discriminator',
          location: input.path,
          recommendation: 'Use space = 8 + sizeof(YourStruct) for Anchor accounts',
        });
      }
    }
  }

  // Check for cross-account type confusion
  if (rust.content.includes('Account<') && rust.content.includes('AccountInfo')) {
    if (rust.content.includes('try_from') && !rust.content.includes('discriminator')) {
      findings.push({
        id: 'SOL079',
        severity: 'high',
        title: 'AccountInfo to Account Without Type Check',
        description: 'Converting AccountInfo to typed Account without discriminator validation',
        location: input.path,
        recommendation: 'Use Account::try_from which validates discriminator automatically',
      });
    }
  }

  return findings;
}
