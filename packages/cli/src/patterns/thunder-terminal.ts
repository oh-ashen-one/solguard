import type { Finding } from '../commands/audit.js';
import type { ParsedIdl } from '../parsers/idl.js';
import type { ParsedRust } from '../parsers/rust.js';

/**
 * SOL249: Thunder Terminal-style Infrastructure Attack
 * Detects vulnerabilities in trading terminals and infrastructure
 * Reference: Thunder Terminal exploit (December 2023) - MongoDB injection attack
 */
export function checkThunderTerminal(idl: ParsedIdl | null, rust: ParsedRust | null): Finding[] {
  const findings: Finding[] = [];

  if (rust) {
    for (const fn of rust.functions) {
      const content = fn.body.toLowerCase();

      // Check for database interaction patterns
      if (content.includes('mongodb') || content.includes('database') || 
          content.includes('db.') || content.includes('query')) {
        // Check for injection vulnerability
        if (content.includes('format!') || content.includes('concat') || 
            content.includes('+') && content.includes('string')) {
          findings.push({
            id: 'SOL249',
            severity: 'critical',
            title: 'Potential Database Injection',
            description: 'Database query built with string concatenation. Thunder Terminal was exploited via MongoDB injection.',
            location: `Function: ${fn.name}`,
            recommendation: 'Use parameterized queries. Never concatenate user input into database queries.',
          });
        }

        // Check for input sanitization
        if (!content.includes('sanitize') && !content.includes('validate') && 
            !content.includes('escape')) {
          findings.push({
            id: 'SOL249',
            severity: 'high',
            title: 'Database Input Not Sanitized',
            description: 'Database operations without input sanitization. Injection attacks possible.',
            location: `Function: ${fn.name}`,
            recommendation: 'Sanitize all inputs before database operations. Use ORM with parameterized queries.',
          });
        }
      }

      // Check for session token handling
      if (content.includes('session') || content.includes('token') || content.includes('jwt')) {
        if (!content.includes('expire') && !content.includes('ttl') && !content.includes('timeout')) {
          findings.push({
            id: 'SOL249',
            severity: 'high',
            title: 'Session Without Expiration',
            description: 'Session tokens may not expire. Stolen sessions remain valid indefinitely.',
            location: `Function: ${fn.name}`,
            recommendation: 'Implement session expiration. Force re-authentication for sensitive operations.',
          });
        }

        // Check for session storage
        if (content.includes('localstorage') || content.includes('cookie')) {
          if (!content.includes('httponly') && !content.includes('secure')) {
            findings.push({
              id: 'SOL249',
              severity: 'high',
              title: 'Insecure Session Storage',
              description: 'Session stored without security flags. XSS attacks could steal sessions.',
              location: `Function: ${fn.name}`,
              recommendation: 'Use HttpOnly, Secure, SameSite flags for session cookies. Avoid localStorage for sensitive data.',
            });
          }
        }
      }

      // Check for API authentication
      if (content.includes('api') || content.includes('endpoint') || content.includes('route')) {
        if (!content.includes('auth') && !content.includes('verify') && 
            !content.includes('middleware')) {
          findings.push({
            id: 'SOL249',
            severity: 'high',
            title: 'API Endpoint Without Authentication',
            description: 'API endpoint may lack authentication. Unauthorized access to user data possible.',
            location: `Function: ${fn.name}`,
            recommendation: 'Implement authentication middleware for all sensitive endpoints.',
          });
        }
      }

      // Check for rate limiting
      if (content.includes('request') || content.includes('api') || content.includes('endpoint')) {
        if (!content.includes('rate_limit') && !content.includes('throttle') && 
            !content.includes('limit')) {
          findings.push({
            id: 'SOL249',
            severity: 'medium',
            title: 'No Rate Limiting',
            description: 'API lacks rate limiting. Brute force attacks and DoS possible.',
            location: `Function: ${fn.name}`,
            recommendation: 'Implement rate limiting (e.g., 100 req/min). Add captcha for authentication endpoints.',
          });
        }
      }

      // Check for error handling that leaks info
      if (content.includes('error') || content.includes('catch') || content.includes('exception')) {
        if (content.includes('stack') || content.includes('traceback') || 
            content.includes('debug')) {
          findings.push({
            id: 'SOL249',
            severity: 'medium',
            title: 'Verbose Error Messages',
            description: 'Error messages may contain stack traces. Information disclosure to attackers.',
            location: `Function: ${fn.name}`,
            recommendation: 'Log detailed errors server-side only. Return generic messages to clients.',
          });
        }
      }

      // Check for CORS configuration
      if (content.includes('cors') || content.includes('access-control')) {
        if (content.includes('*') || content.includes('any')) {
          findings.push({
            id: 'SOL249',
            severity: 'high',
            title: 'Permissive CORS Policy',
            description: 'CORS allows all origins. Malicious sites can make authenticated requests.',
            location: `Function: ${fn.name}`,
            recommendation: 'Whitelist specific allowed origins. Never use wildcard for authenticated endpoints.',
          });
        }
      }

      // Check for withdrawal address validation
      if (content.includes('withdraw') && content.includes('address')) {
        if (!content.includes('whitelist') && !content.includes('confirm') && 
            !content.includes('2fa')) {
          findings.push({
            id: 'SOL249',
            severity: 'high',
            title: 'Withdrawal Without Address Verification',
            description: 'Withdrawals to arbitrary addresses without verification. Account takeover = fund loss.',
            location: `Function: ${fn.name}`,
            recommendation: 'Whitelist withdrawal addresses with confirmation delay. Require 2FA for new addresses.',
          });
        }
      }

      // Check for logging sensitive data
      if (content.includes('log') || content.includes('print') || content.includes('console')) {
        if (content.includes('password') || content.includes('key') || 
            content.includes('secret') || content.includes('token')) {
          findings.push({
            id: 'SOL249',
            severity: 'critical',
            title: 'Sensitive Data in Logs',
            description: 'Sensitive data may be logged. Log aggregation services could expose secrets.',
            location: `Function: ${fn.name}`,
            recommendation: 'Never log passwords, keys, or tokens. Sanitize all log output.',
          });
        }
      }
    }
  }

  return findings;
}
