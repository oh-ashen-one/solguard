import type { Finding } from '../commands/audit.js';
import type { PatternInput } from './index.js';

/**
 * SOL136: Supply Chain Attack Patterns (Web3.js Attack - $160K)
 * 
 * Detects patterns that could indicate supply chain vulnerabilities,
 * including unsafe dependency usage and potential backdoors.
 */
export function checkSupplyChainAttack(input: PatternInput): Finding[] {
  const findings: Finding[] = [];

  if (!input.rust || !input.rust.files) return findings;

  for (const file of input.rust.files) {
    const lines = file.lines;

    lines.forEach((line, index) => {
      const lineNum = index + 1;
      const lineLower = line.toLowerCase();

      // Pattern 1: Hardcoded external addresses that could be malicious
      if (line.includes('Pubkey::') && (line.includes('from_str') || line.includes('new_from_array'))) {
        // Check if it's a well-known program ID
        if (!line.includes('11111111111111111111111111111111') && // System program
            !line.includes('TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA') && // Token program
            !line.includes('ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL')) { // ATA program
          findings.push({
            id: `SOL136-${findings.length + 1}`,
            pattern: 'Supply Chain Attack Vector',
            severity: 'medium',
            title: 'Hardcoded external pubkey',
            description: 'Hardcoded public key that is not a well-known program. Could be a backdoor address inserted through compromised build.',
            location: { file: file.path, line: lineNum },
            suggestion: 'Verify all hardcoded addresses. Use constants from official SDKs where possible.',
          });
        }
      }

      // Pattern 2: Environment variable usage for sensitive data
      if (lineLower.includes('env::var') || lineLower.includes('std::env')) {
        if (lineLower.includes('key') || lineLower.includes('secret') || lineLower.includes('private')) {
          findings.push({
            id: `SOL136-${findings.length + 1}`,
            pattern: 'Supply Chain Attack Vector',
            severity: 'critical',
            title: 'Sensitive data from environment variables',
            description: 'Private keys or secrets loaded from environment. Compromised build process could exfiltrate these.',
            location: { file: file.path, line: lineNum },
            suggestion: 'Never use private keys in on-chain programs. Use PDAs and program-derived signing.',
          });
        }
      }

      // Pattern 3: External HTTP/network calls (should not exist in on-chain code)
      if (lineLower.includes('reqwest') || lineLower.includes('http::') || 
          lineLower.includes('tcp') || lineLower.includes('fetch')) {
        findings.push({
          id: `SOL136-${findings.length + 1}`,
          pattern: 'Supply Chain Attack Vector',
          severity: 'critical',
          title: 'Network calls in on-chain code',
          description: 'Network/HTTP calls detected. On-chain programs cannot make external calls. This is either dead code or indicates compromise.',
          location: { file: file.path, line: lineNum },
          suggestion: 'Remove network code from on-chain programs. Use oracles for external data.',
        });
      }

      // Pattern 4: File system operations
      if (lineLower.includes('std::fs') || lineLower.includes('file::') || 
          lineLower.includes('read_to_string') || lineLower.includes('write_all')) {
        findings.push({
          id: `SOL136-${findings.length + 1}`,
          pattern: 'Supply Chain Attack Vector',
          severity: 'high',
          title: 'File system operations detected',
          description: 'File system operations in program code. Could indicate backdoor attempting to read/write local files.',
          location: { file: file.path, line: lineNum },
          suggestion: 'Remove file system code. On-chain programs should not access the file system.',
        });
      }

      // Pattern 5: Suspicious base64/encoding that could hide malicious payloads
      if ((lineLower.includes('base64') || lineLower.includes('decode')) && 
          line.includes('"') && line.length > 100) {
        findings.push({
          id: `SOL136-${findings.length + 1}`,
          pattern: 'Supply Chain Attack Vector',
          severity: 'medium',
          title: 'Long encoded string detected',
          description: 'Large encoded string found. Could be obfuscated malicious code. Review carefully.',
          location: { file: file.path, line: lineNum },
          suggestion: 'Decode and review all base64/encoded strings for malicious content.',
        });
      }
    });
  }

  return findings;
}
