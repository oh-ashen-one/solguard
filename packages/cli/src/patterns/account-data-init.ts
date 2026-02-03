import type { Finding } from '../commands/audit.js';
import type { PatternInput } from './index.js';

/**
 * SOL124: Account Data Initialization
 * Detects issues with how account data is initialized
 */
export function checkAccountDataInit(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  const rust = input.rust;

  if (!rust || !rust.content) return findings;

  // Check for manual data initialization
  if (rust.content.includes('data.borrow_mut()') && rust.content.includes('copy_from_slice')) {
    if (!rust.content.includes('discriminator')) {
      findings.push({
        id: 'SOL124',
        severity: 'high',
        title: 'Manual Data Init Without Discriminator',
        description: 'Writing account data manually without setting discriminator',
        location: input.path,
        recommendation: 'Write 8-byte discriminator first when manually initializing',
      });
    }
  }

  // Check for partial initialization
  if (rust.content.includes('init') && rust.content.includes('Default::default()')) {
    findings.push({
      id: 'SOL124',
      severity: 'low',
      title: 'Default Initialization',
      description: 'Account initialized with Default - ensure all fields are set',
      location: input.path,
      recommendation: 'Explicitly initialize important fields after Default',
    });
  }

  return findings;
}
