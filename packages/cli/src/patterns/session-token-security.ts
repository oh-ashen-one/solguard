import type { Finding } from '../commands/audit.js';
import type { PatternInput } from './index.js';

/**
 * SOL177: Session Token Security
 * 
 * Detects insecure session token handling that could lead to
 * session hijacking or replay attacks.
 * 
 * Real-world exploit: Thunder Terminal - session tokens compromised
 * via third-party vulnerability.
 */
export function checkSessionTokenSecurity(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  const { rust, path } = input;

  if (!rust) return findings;

  const riskyPatterns = [
    { pattern: /session_token\s*=.*user_input/i, desc: 'Session token from user input' },
    { pattern: /bearer\s+token.*unvalidated/i, desc: 'Unvalidated bearer token' },
    { pattern: /jwt.*without.*verify/i, desc: 'JWT without verification' },
    { pattern: /token.*expire.*never/i, desc: 'Non-expiring token' },
    { pattern: /session.*store.*plain/i, desc: 'Plaintext session storage' },
    { pattern: /cookie.*httponly.*false/i, desc: 'Cookies without HttpOnly' },
  ];

  const lines = rust.content.split('\n');
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    for (const { pattern, desc } of riskyPatterns) {
      if (pattern.test(line)) {
        findings.push({
          id: 'SOL177',
          severity: 'critical',
          title: 'Session Token Security Issue',
          description: `Detected: ${desc}. Session tokens must be securely generated, validated, and stored.`,
          location: { file: path, line: i + 1 },
          recommendation: 'Implement secure session management: short expiry, secure storage, proper validation, and rotation.',
        });
      }
    }
  }

  return findings;
}
