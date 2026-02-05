import type { Finding } from '../commands/audit.js';
import type { PatternInput } from './index.js';

/**
 * SOL312: Program Upgrade Security
 * Detects vulnerabilities in upgradeable program patterns
 * Based on Solana program security best practices
 */
export function checkProgramUpgradeSecurity(input: PatternInput): Finding[] {
  const findings: Finding[] = [];

  if (input.rust?.content) {
    const content = input.rust.content;
    const lines = content.split('\n');

    // Check for upgrade authority patterns
    const hasUpgrade = /upgrade|migrate|bpf_loader|programdata/i.test(content);

    if (hasUpgrade) {
      // Check for upgrade authority validation
      for (let i = 0; i < lines.length; i++) {
        const line = lines[i];

        if (line.includes('upgrade') && !line.includes('//')) {
          const contextLines = lines.slice(i, Math.min(i + 10, lines.length)).join('\n');
          
          if (!contextLines.includes('upgrade_authority') && !contextLines.includes('program_data')) {
            findings.push({
              id: 'SOL312',
              title: 'Missing Upgrade Authority Check',
              severity: 'critical',
              description: 'Program upgrades must validate the upgrade authority.',
              location: { file: input.path, line: i + 1 },
              suggestion: 'Verify authority: #[account(constraint = program_data.upgrade_authority_address == Some(authority.key()))]',
              cwe: 'CWE-863',
            });
            break;
          }
        }
      }
    }

    // Check for data migration handling
    if (content.includes('migrate') || content.includes('version')) {
      // Check for version tracking
      if (!content.includes('PROGRAM_VERSION') && !content.includes('data_version') && !content.includes('schema_version')) {
        findings.push({
          id: 'SOL312',
          title: 'No Data Version Tracking',
          severity: 'high',
          description: 'Upgradeable programs should track data schema versions for safe migrations.',
          location: { file: input.path, line: 1 },
          suggestion: 'Add versioning: pub const PROGRAM_VERSION: u8 = 1; // Increment on data structure changes',
          cwe: 'CWE-669',
        });
      }

      // Check for migration validation
      if (content.includes('migrate') && !content.includes('old_version') && !content.includes('from_version')) {
        findings.push({
          id: 'SOL312',
          title: 'Unchecked Data Migration',
          severity: 'high',
          description: 'Migrations should validate source version before transforming data.',
          location: { file: input.path, line: 1 },
          suggestion: 'Validate version: require!(account.version == EXPECTED_OLD_VERSION, InvalidVersion)',
          cwe: 'CWE-20',
        });
      }
    }

    // Check for timelock on upgrades
    if (content.includes('upgrade') && !content.includes('timelock') && !content.includes('delay')) {
      findings.push({
        id: 'SOL312',
        title: 'No Upgrade Timelock',
        severity: 'medium',
        description: 'Consider adding timelock to upgrades for user protection.',
        location: { file: input.path, line: 1 },
        suggestion: 'Add timelock: require!(clock.unix_timestamp >= upgrade_request.execute_after, TimelockNotExpired)',
        cwe: 'CWE-269',
      });
    }

    // Check for immutability option
    if (!content.includes('set_upgrade_authority') && !content.includes('make_immutable')) {
      if (content.includes('upgrade_authority') || content.includes('BpfLoaderUpgradeable')) {
        findings.push({
          id: 'SOL312',
          title: 'No Immutability Path',
          severity: 'info',
          description: 'Consider providing a path to make the program immutable once stable.',
          location: { file: input.path, line: 1 },
          suggestion: 'Add immutability: set_upgrade_authority(None) // Makes program permanent',
          cwe: 'CWE-269',
        });
      }
    }

    // Check for programdata account validation
    if (content.includes('ProgramData') || content.includes('programdata')) {
      for (let i = 0; i < lines.length; i++) {
        if (lines[i].includes('programdata') || lines[i].includes('ProgramData')) {
          const contextLines = lines.slice(i, Math.min(i + 8, lines.length)).join('\n');
          if (!contextLines.includes('program_id') && !contextLines.includes('key()')) {
            findings.push({
              id: 'SOL312',
              title: 'Unvalidated ProgramData Account',
              severity: 'critical',
              description: 'ProgramData account must be derived from the correct program ID.',
              location: { file: input.path, line: i + 1 },
              suggestion: 'Derive correctly: let (programdata_key, _) = Pubkey::find_program_address(&[program_id.as_ref()], &bpf_loader_upgradeable::ID)',
              cwe: 'CWE-346',
            });
            break;
          }
        }
      }
    }

    // Check for buffer account security
    if (content.includes('buffer') && content.includes('upgrade')) {
      if (!content.includes('buffer_authority')) {
        findings.push({
          id: 'SOL312',
          title: 'Missing Buffer Authority Check',
          severity: 'high',
          description: 'Upgrade buffers must validate buffer authority.',
          location: { file: input.path, line: 1 },
          suggestion: 'Verify buffer: require!(buffer.authority == Some(deployer.key()), InvalidBufferAuthority)',
          cwe: 'CWE-863',
        });
      }
    }

    // Check for multisig upgrade authority
    if (content.includes('upgrade_authority') && !content.includes('multisig') && !content.includes('threshold')) {
      findings.push({
        id: 'SOL312',
        title: 'Single-Key Upgrade Authority',
        severity: 'medium',
        description: 'Consider using multisig for upgrade authority to reduce single point of failure.',
        location: { file: input.path, line: 1 },
        suggestion: 'Use multisig: Squads or custom multisig for upgrade authority',
        cwe: 'CWE-269',
      });
    }

    // Check for emergency procedures
    if (content.includes('upgrade') && !content.includes('emergency') && !content.includes('pause')) {
      findings.push({
        id: 'SOL312',
        title: 'No Emergency Upgrade Path',
        severity: 'low',
        description: 'Consider emergency upgrade procedures for critical security patches.',
        location: { file: input.path, line: 1 },
        suggestion: 'Add emergency path: Emergency multisig with shorter timelock for security patches',
        cwe: 'CWE-693',
      });
    }
  }

  return findings;
}
