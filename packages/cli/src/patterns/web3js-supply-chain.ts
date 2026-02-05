import type { Finding } from '../commands/audit.js';
import type { ParsedIdl } from '../parsers/idl.js';
import type { ParsedRust } from '../parsers/rust.js';

/**
 * SOL233: Web3.js Supply Chain Attack Detection
 * Detects patterns that could indicate supply chain attacks via compromised npm packages
 * Reference: December 2024 Web3.js supply chain attack affecting @solana/web3.js
 */
export function checkWeb3jsSupplyChain(idl: ParsedIdl | null, rust: ParsedRust | null): Finding[] {
  const findings: Finding[] = [];

  if (rust) {
    // Check for dynamic package loading that could be exploited
    for (const fn of rust.functions) {
      const content = fn.body.toLowerCase();
      
      // Pattern: Dynamic require/import patterns
      if (content.includes('std::process::command') && 
          (content.includes('npm') || content.includes('cargo'))) {
        findings.push({
          id: 'SOL233',
          severity: 'high',
          title: 'Potential Supply Chain Attack Vector',
          description: 'Dynamic package installation detected. This pattern could be exploited if a dependency is compromised.',
          location: `Function: ${fn.name}`,
          recommendation: 'Pin exact versions of all dependencies. Use lock files. Verify package integrity with checksums.',
        });
      }

      // Check for suspicious post-install patterns
      if (content.includes('build.rs') || content.includes('build_script')) {
        if (content.includes('std::env::var') && content.includes('http')) {
          findings.push({
            id: 'SOL233',
            severity: 'critical',
            title: 'Network Access in Build Script',
            description: 'Build script appears to make network requests. This is a common supply chain attack vector.',
            location: `Function: ${fn.name}`,
            recommendation: 'Build scripts should not make network requests. Audit all build-time dependencies.',
          });
        }
      }

      // Check for environment variable exfiltration
      if (content.includes('solana_sdk') || content.includes('private_key') || content.includes('keypair')) {
        if (content.includes('std::env::vars') || content.includes('env::var_os')) {
          findings.push({
            id: 'SOL233',
            severity: 'critical',
            title: 'Environment Variable Access Near Key Material',
            description: 'Code accesses environment variables near keypair/private key handling. Could indicate key exfiltration.',
            location: `Function: ${fn.name}`,
            recommendation: 'Audit all code paths that access environment variables. Keys should be handled through secure enclaves.',
          });
        }
      }
    }

    // Check Cargo.toml patterns
    const fullContent = rust.rawContent || '';
    
    // Detect version ranges that could be exploited
    if (fullContent.includes('solana-sdk = "^') || fullContent.includes('anchor-lang = "^')) {
      findings.push({
        id: 'SOL233',
        severity: 'medium',
        title: 'Unpinned Dependency Version',
        description: 'Major version ranges (^) detected for critical Solana dependencies. A compromised minor release could affect your program.',
        location: 'Cargo.toml',
        recommendation: 'Pin exact versions: solana-sdk = "=1.18.0" instead of "^1.18". Use Cargo.lock.',
      });
    }

    // Check for git dependencies without commit hash
    if (fullContent.includes('git = "https://github.com') && !fullContent.includes('rev = "')) {
      findings.push({
        id: 'SOL233',
        severity: 'high',
        title: 'Git Dependency Without Pinned Commit',
        description: 'Git dependency detected without pinned commit hash. Repository could be modified maliciously.',
        location: 'Cargo.toml',
        recommendation: 'Always pin git dependencies to a specific commit: git = "...", rev = "abc123"',
      });
    }
  }

  return findings;
}
