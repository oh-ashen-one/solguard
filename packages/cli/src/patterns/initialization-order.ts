import type { Finding } from '../commands/audit.js';
import type { PatternInput } from './index.js';

/**
 * SOL100: Initialization Order Dependencies
 * Detects issues with account initialization sequencing
 */
export function checkInitializationOrder(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  const rust = input.rust;

  if (!rust || !rust.content) return findings;

  // Check for multiple init accounts in same instruction
  const initCount = (rust.content.match(/#\[account\([^)]*init/g) || []).length;
  if (initCount >= 2) {
    findings.push({
      id: 'SOL100',
      severity: 'medium',
      title: 'Multiple Account Initialization',
      description: `${initCount} accounts initialized in same instruction - verify ordering`,
      location: input.path,
      recommendation: 'Ensure initialization order matches dependency requirements',
    });
  }

  // Check for circular dependencies
  if (rust.content.includes('has_one') && rust.content.includes('init')) {
    // Check if has_one points to another init account
    const hasOneOnInit = /#\[account\([^)]*init[^)]*has_one/;
    if (hasOneOnInit.test(rust.content)) {
      findings.push({
        id: 'SOL100',
        severity: 'high',
        title: 'has_one on Initializing Account',
        description: 'has_one constraint on account being initialized - may fail',
        location: input.path,
        recommendation: 'has_one should reference already-existing accounts',
      });
    }
  }

  // Check for initialization that depends on uninitialized state
  if (rust.content.includes('init') && rust.content.includes('.data')) {
    const accessBeforeInit = /\.data[\s\S]*?#\[account\([^)]*init/;
    if (accessBeforeInit.test(rust.content)) {
      findings.push({
        id: 'SOL100',
        severity: 'high',
        title: 'Data Access Before Initialization',
        description: 'Accessing account data that may not be initialized yet',
        location: input.path,
        recommendation: 'Ensure accounts are initialized before accessing their data',
      });
    }
  }

  // Check for config/admin account initialization
  if (rust.content.includes('init') && 
      (rust.content.includes('config') || rust.content.includes('admin') || rust.content.includes('global'))) {
    if (!rust.content.includes('only_once') && !rust.content.includes('initialized')) {
      findings.push({
        id: 'SOL100',
        severity: 'high',
        title: 'Global Config Without One-Time Init Guard',
        description: 'Global/config account may be re-initializable',
        location: input.path,
        recommendation: 'Use PDA with program-controlled seeds for global config',
      });
    }
  }

  return findings;
}
