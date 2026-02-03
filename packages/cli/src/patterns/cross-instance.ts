import type { Finding } from '../commands/audit.js';
import type { PatternInput } from './index.js';

/**
 * SOL076: Cross-Instance Confusion
 * Detects when multiple program instances may interfere with each other
 */
export function checkCrossInstance(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  const rust = input.rust;

  if (!rust || !rust.content) return findings;

  // Check for global state without program ID binding
  if (rust.content.includes('seeds') && rust.content.includes('find_program_address')) {
    // Check if program ID is included in seeds
    if (!rust.content.includes('program_id') && !rust.content.includes('id()')) {
      const hasGlobalPda = /seeds\s*=\s*\[\s*b"[^"]+"\s*\]/;
      if (hasGlobalPda.test(rust.content)) {
        findings.push({
          id: 'SOL076',
          severity: 'medium',
          title: 'Global PDA Without Program Binding',
          description: 'PDA uses only static seeds - may collide across program versions or forks',
          location: input.path,
          recommendation: 'Include program-specific data in PDA seeds for isolation',
        });
      }
    }
  }

  // Check for hardcoded program IDs
  const hardcodedId = /declare_id!\s*\(\s*"[A-Za-z0-9]{32,44}"\s*\)/;
  if (!hardcodedId.test(rust.content)) {
    if (rust.content.includes('invoke') || rust.content.includes('CpiContext')) {
      findings.push({
        id: 'SOL076',
        severity: 'low',
        title: 'Missing Program ID Declaration',
        description: 'Program ID not declared - may cause issues in multi-instance deployments',
        location: input.path,
        recommendation: 'Use declare_id! macro to bind program to specific address',
      });
    }
  }

  // Check for upgradeable program interactions
  if (rust.content.includes('BpfLoaderUpgradeable') || rust.content.includes('bpf_loader_upgradeable')) {
    if (!rust.content.includes('upgrade_authority')) {
      findings.push({
        id: 'SOL076',
        severity: 'high',
        title: 'Upgradeable Program Interaction Without Authority Check',
        description: 'Interacting with upgradeable program without verifying authority',
        location: input.path,
        recommendation: 'Verify program upgrade authority before trusting program state',
      });
    }
  }

  // Check for cross-program state assumptions
  if (rust.content.includes('external_program') || rust.content.includes('other_program')) {
    if (!rust.content.includes('check_id') && !rust.content.includes('key() ==')) {
      findings.push({
        id: 'SOL076',
        severity: 'high',
        title: 'External Program Trust',
        description: 'External program referenced without explicit ID verification',
        location: input.path,
        recommendation: 'Verify external program ID matches expected constant',
      });
    }
  }

  return findings;
}
