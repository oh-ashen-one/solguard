import type { Finding } from '../commands/audit.js';
import type { PatternInput } from './index.js';

/**
 * SOL315: NPM Supply Chain Attack Detection
 * Detects patterns associated with malicious npm packages
 * Real-world: January 2025 Solana NPM package compromise (wallet key theft via Gmail SMTP)
 */
export function checkNpmSupplyChain(input: PatternInput): Finding[] {
  const findings: Finding[] = [];

  // Check JavaScript/TypeScript files
  if (input.path?.match(/\.(js|ts|mjs|cjs)$/)) {
    const content = input.rust?.content || '';
    const lines = content.split('\n');

    // Check for suspicious network operations
    for (let i = 0; i < lines.length; i++) {
      const line = lines[i];

      // SMTP exfiltration (exact pattern from 2025 attack)
      if (line.includes('smtp') || line.includes('nodemailer') || line.includes('sendmail')) {
        if (content.includes('privateKey') || content.includes('secret') || content.includes('mnemonic')) {
          findings.push({
            id: 'SOL315',
            title: 'SMTP Credential Exfiltration Pattern',
            severity: 'critical',
            description: 'Email sending combined with key/secret access matches known supply chain attack.',
            location: { file: input.path, line: i + 1 },
            suggestion: 'URGENT: Review package for malicious key exfiltration. Check npm package integrity.',
            cwe: 'CWE-506',
          });
        }
      }

      // Arbitrary HTTP posts with sensitive data
      if ((line.includes('fetch') || line.includes('axios') || line.includes('request')) && 
          line.includes('POST')) {
        const contextLines = lines.slice(Math.max(0, i - 10), Math.min(i + 10, lines.length)).join('\n');
        if (contextLines.includes('privateKey') || contextLines.includes('secretKey') || 
            contextLines.includes('mnemonic') || contextLines.includes('seed')) {
          findings.push({
            id: 'SOL315',
            title: 'Network Exfiltration of Keys',
            severity: 'critical',
            description: 'HTTP POST with private key access detected. Potential key theft.',
            location: { file: input.path, line: i + 1 },
            suggestion: 'URGENT: This may be malicious. Review all network calls and key access patterns.',
            cwe: 'CWE-200',
          });
        }
      }

      // Suspicious base64 encoding of keys
      if ((line.includes('btoa') || line.includes('Buffer.from') || line.includes('base64')) &&
          (content.includes('privateKey') || content.includes('secretKey'))) {
        findings.push({
          id: 'SOL315',
          title: 'Base64 Key Encoding',
          severity: 'high',
          description: 'Base64 encoding of keys is a common exfiltration preparation step.',
          location: { file: input.path, line: i + 1 },
          suggestion: 'Review why keys are being encoded. This may be preparation for exfiltration.',
          cwe: 'CWE-312',
        });
      }

      // Eval with external input
      if (line.includes('eval(') || line.includes('Function(') || line.includes('vm.runInContext')) {
        findings.push({
          id: 'SOL315',
          title: 'Dynamic Code Execution',
          severity: 'critical',
          description: 'Dynamic code execution can hide malicious payloads.',
          location: { file: input.path, line: i + 1 },
          suggestion: 'Remove eval/Function calls. They are commonly used in supply chain attacks.',
          cwe: 'CWE-94',
        });
      }

      // Obfuscated code indicators
      if (line.match(/\\x[0-9a-f]{2}/gi) && line.length > 200) {
        findings.push({
          id: 'SOL315',
          title: 'Obfuscated Code Detected',
          severity: 'high',
          description: 'Hex-escaped strings in long lines indicate obfuscation.',
          location: { file: input.path, line: i + 1 },
          suggestion: 'Deobfuscate and review. Legitimate code rarely uses heavy obfuscation.',
          cwe: 'CWE-506',
        });
      }

      // Process.env access with keys
      if (line.includes('process.env') && 
          (line.includes('KEY') || line.includes('SECRET') || line.includes('PRIVATE'))) {
        const contextLines = lines.slice(i, Math.min(i + 5, lines.length)).join('\n');
        if (contextLines.includes('http') || contextLines.includes('fetch') || contextLines.includes('send')) {
          findings.push({
            id: 'SOL315',
            title: 'Environment Key Exfiltration Risk',
            severity: 'high',
            description: 'Environment variables containing keys accessed near network code.',
            location: { file: input.path, line: i + 1 },
            suggestion: 'Ensure environment keys are not being sent externally.',
            cwe: 'CWE-200',
          });
        }
      }

      // Typosquatting indicators in imports
      if (line.includes('require(') || line.includes('import ')) {
        const suspiciousPackages = [
          'soIana', 'so1ana', 'solanaa', 'solanna', // Typosquats
          'web3-solana', 'solana-web3-js', // Fake packages
          '@solana-labs', '@soIana', // Scope typosquats
        ];
        for (const pkg of suspiciousPackages) {
          if (line.includes(pkg)) {
            findings.push({
              id: 'SOL315',
              title: 'Potential Typosquat Package',
              severity: 'critical',
              description: `Package "${pkg}" may be a typosquat of legitimate Solana packages.`,
              location: { file: input.path, line: i + 1 },
              suggestion: 'Verify package name. Use official @solana/web3.js from npmjs.com/package/@solana/web3.js',
              cwe: 'CWE-829',
            });
          }
        }
      }
    }

    // Check for postinstall scripts
    if (input.path?.includes('package.json')) {
      if (content.includes('postinstall') || content.includes('preinstall')) {
        findings.push({
          id: 'SOL315',
          title: 'Install Script Detected',
          severity: 'medium',
          description: 'Package has install scripts which can execute arbitrary code.',
          location: { file: input.path, line: 1 },
          suggestion: 'Review postinstall/preinstall scripts carefully. Consider using --ignore-scripts.',
          cwe: 'CWE-829',
        });
      }
    }
  }

  return findings;
}
