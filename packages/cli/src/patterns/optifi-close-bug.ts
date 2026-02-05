// SOL742: OptiFi Program Close Bug (Aug 2022 - $661K locked forever)
// Based on the OptiFi incident where a program was accidentally closed, locking funds

import type { ParsedRust } from '../parsers/rust.js';
import type { Finding } from '../commands/audit.js';
import type { PatternInput } from './index.js';

/**
 * OptiFi Program Close Bug Patterns (August 2022)
 * 
 * OptiFi accidentally executed a `solana program close` command on their mainnet
 * program, causing $661,000 in user funds to be permanently locked. The program
 * was set to upgradeable but was closed by mistake, leaving no way to recover funds.
 * 
 * Key vulnerabilities:
 * 1. Accidental program closure risk
 * 2. Missing safeguards on upgrade authority actions
 * 3. No recovery mechanisms for closed programs
 * 4. Upgradeable programs with direct close access
 */

export function checkOptiFiCloseBug(parsed: ParsedRust): Finding[] {
  const findings: Finding[] = [];

  // Check for program close/shutdown patterns
  const closePatterns = [
    /close_program|program_close|shutdown/i,
    /upgrade_authority.*close|close.*upgrade/i,
    /terminate_program|disable_program/i,
  ];

  for (const func of parsed.functions) {
    const content = func.content.toLowerCase();
    
    const hasClose = closePatterns.some(p => p.test(content));
    
    if (hasClose) {
      // Check for safeguards
      if (!/multisig|timelock|confirm.*close|delay/i.test(content)) {
        findings.push({
          id: 'SOL675',
          severity: 'critical',
          title: 'OptiFi-style Program Close Without Safeguard',
          description: `Function '${func.name}' may allow program closure without safety mechanisms`,
          location: func.location,
          recommendation: 'Implement multisig requirements and timelocks for program closure. Consider making programs non-closeable after deployment.',
        });
      }
    }
  }

  // Check for upgrade authority patterns
  const upgradePatterns = [
    /upgrade_authority|program_authority/i,
    /set_authority|change_authority/i,
    /buffer.*authority/i,
  ];

  for (const func of parsed.functions) {
    const content = func.content.toLowerCase();
    
    const handlesUpgrade = upgradePatterns.some(p => p.test(content));
    
    if (handlesUpgrade) {
      // Check for authority transfer safeguards
      if (!/two_step|pending|accept.*authority/i.test(content)) {
        findings.push({
          id: 'SOL676',
          severity: 'high',
          title: 'Unsafe Upgrade Authority Transfer',
          description: `Function '${func.name}' transfers upgrade authority without two-step process`,
          location: func.location,
          recommendation: 'Use two-step authority transfers: propose, then accept. This prevents accidental transfers to wrong addresses.',
        });
      }
    }
  }

  // Check for fund recovery mechanisms
  const fundPatterns = [
    /user_deposit|stake_pool|treasury/i,
    /vault|escrow|locked_fund/i,
  ];

  for (const func of parsed.functions) {
    const content = func.content.toLowerCase();
    
    const handlesFunds = fundPatterns.some(p => p.test(content));
    
    if (handlesFunds) {
      // Check for emergency recovery
      if (!/emergency_withdraw|recovery|rescue/i.test(content)) {
        findings.push({
          id: 'SOL677',
          severity: 'medium',
          title: 'No Emergency Fund Recovery Mechanism',
          description: `Function '${func.name}' handles user funds without visible emergency recovery path`,
          location: func.location,
          recommendation: 'Implement emergency withdrawal mechanisms that work even if main program logic fails.',
        });
      }
    }
  }

  return findings;
}

// Check for program immutability considerations
export function checkProgramImmutability(parsed: ParsedRust): Finding[] {
  const findings: Finding[] = [];

  // Look for upgradeable program markers
  const upgradeablePatterns = [
    /upgradeable|bpf_upgradeable/i,
    /set_upgrade_authority|program_data/i,
  ];

  for (const func of parsed.functions) {
    const content = func.content.toLowerCase();
    
    const isUpgradeable = upgradeablePatterns.some(p => p.test(content));
    
    if (isUpgradeable) {
      findings.push({
        id: 'SOL678',
        severity: 'info',
        title: 'Program Upgradeability Detected',
        description: `Function '${func.name}' indicates program is upgradeable`,
        location: func.location,
        recommendation: 'Document upgrade procedures. Consider multisig upgrade authority. Evaluate whether program should be immutable after stability period.',
      });
    }
  }

  return findings;
}

// Export combined check
export function checkOptiFiStyleBugs(input: PatternInput): Finding[] {
  if (!input.rust) return [];
  return [
    ...checkOptiFiCloseBug(input.rust),
    ...checkProgramImmutability(input.rust),
  ];
}
