import type { Finding } from '../commands/audit.js';
import type { PatternInput } from './index.js';

/**
 * SOL077: Program Data Authority
 * Detects vulnerabilities in upgradeable program authority handling
 */
export function checkProgramDataAuthority(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  const rust = input.rust;

  if (!rust || !rust.content) return findings;

  // Check for program data account handling
  const hasProgramData = rust.content.includes('ProgramData') || 
                         rust.content.includes('program_data') ||
                         rust.content.includes('UpgradeableLoaderState');

  if (!hasProgramData) return findings;

  // Check for upgrade authority verification
  if (rust.content.includes('upgrade_authority')) {
    if (!rust.content.includes('upgrade_authority.is_signer') &&
        !rust.content.includes('upgrade_authority_address')) {
      findings.push({
        id: 'SOL077',
        severity: 'critical',
        title: 'Upgrade Authority Not Verified',
        description: 'Upgrade authority referenced without signer or address verification',
        location: input.path,
        recommendation: 'Verify upgrade_authority is signer and matches expected address',
      });
    }
  }

  // Check for set_upgrade_authority patterns
  if (rust.content.includes('SetAuthority') || rust.content.includes('set_authority')) {
    if (rust.content.includes('program') && !rust.content.includes('multi_sig')) {
      findings.push({
        id: 'SOL077',
        severity: 'high',
        title: 'Program Authority Change Without Multisig',
        description: 'Program authority change without multi-signature requirement',
        location: input.path,
        recommendation: 'Use multi-sig or timelock for program authority changes',
      });
    }
  }

  // Check for programdata account derivation
  if (rust.content.includes('find_program_address') && 
      rust.content.includes('BPFLoaderUpgradeable')) {
    if (!rust.content.includes('programdata_address')) {
      findings.push({
        id: 'SOL077',
        severity: 'medium',
        title: 'ProgramData Derivation Issue',
        description: 'ProgramData account may not be properly derived',
        location: input.path,
        recommendation: 'Use get_program_data_address helper for ProgramData derivation',
      });
    }
  }

  // Check for close program data patterns
  if (rust.content.includes('close') && hasProgramData) {
    findings.push({
      id: 'SOL077',
      severity: 'high',
      title: 'Program Data Closure Risk',
      description: 'Closing program data account makes program permanently non-upgradeable',
      location: input.path,
      recommendation: 'Ensure program data closure is intentional and irreversible',
    });
  }

  // Check for program buffer handling
  if (rust.content.includes('Buffer') && rust.content.includes('program')) {
    if (!rust.content.includes('buffer_authority')) {
      findings.push({
        id: 'SOL077',
        severity: 'medium',
        title: 'Program Buffer Without Authority Check',
        description: 'Program buffer manipulation without authority verification',
        location: input.path,
        recommendation: 'Verify buffer authority before buffer operations',
      });
    }
  }

  return findings;
}
