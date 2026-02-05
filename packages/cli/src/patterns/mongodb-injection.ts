import type { Finding } from '../commands/audit.js';
import type { PatternInput } from './index.js';

/**
 * SOL176: MongoDB/Database Injection Vulnerability
 * 
 * Detects potential database injection vulnerabilities in backend
 * services that interact with Solana programs.
 * 
 * Real-world exploit: Thunder Terminal - MongoDB flaw led to session
 * token compromise and $240K stolen.
 */
export function checkMongodbInjection(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  const { rust, path } = input;

  if (!rust) return findings;

  const mongoPatterns = [
    /mongodb/i,
    /nosql/i,
    /\.find\s*\(/,
    /\.insert\s*\(/,
    /\.update\s*\(/,
    /query.*user_input/i,
    /unsafe_query/i,
    /raw_query/i,
  ];

  const lines = rust.content.split('\n');
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    for (const pattern of mongoPatterns) {
      if (pattern.test(line)) {
        // Check if there's input sanitization nearby
        const context = lines.slice(Math.max(0, i - 5), i + 5).join('\n');
        if (!context.includes('sanitize') && !context.includes('escape') && !context.includes('validate')) {
          findings.push({
            id: 'SOL176',
            severity: 'high',
            title: 'Database Injection Risk',
            description: 'Potential database query construction without proper input sanitization. Backend services should sanitize all user inputs before database queries.',
            location: { file: path, line: i + 1 },
            recommendation: 'Use parameterized queries and sanitize all user inputs. Implement strict input validation.',
          });
          break;
        }
      }
    }
  }

  return findings;
}
