import type { Finding } from '../commands/audit.js';
import type { PatternInput } from './index.js';

/**
 * SOL143: Intent-Based Protocol Security
 * Detects vulnerabilities in intent/solver protocols
 * 
 * Intent systems (like CoW Protocol) have unique risks:
 * - Solver collusion
 * - Intent front-running
 * - Execution guarantees
 */
export function checkIntentBased(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  const rust = input.rust;
  if (!rust) return findings;

  const content = rust.content;
  const lines = content.split('\n');

  lines.forEach((line, i) => {
    // Check for intent submission
    if (/submit.*intent|create.*intent|user.*intent/i.test(line)) {
      const nearbyContent = lines.slice(Math.max(0, i - 15), Math.min(lines.length, i + 15)).join('\n');
      
      // Check for intent privacy
      if (!/encrypt|private|commit.*reveal|sealed/i.test(nearbyContent)) {
        findings.push({
          id: 'SOL143',
          name: 'Intent Not Private',
          severity: 'high',
          message: 'Visible intents can be front-run by malicious solvers',
          location: `${input.path}:${i + 1}`,
          snippet: line.trim(),
          fix: 'Use commit-reveal or encrypted intents to prevent front-running',
        });
      }

      // Check for expiration
      if (!/expir|deadline|valid_until|ttl/i.test(nearbyContent)) {
        findings.push({
          id: 'SOL143',
          name: 'Intent No Expiration',
          severity: 'medium',
          message: 'Intents without expiration can be executed at unfavorable times',
          location: `${input.path}:${i + 1}`,
          snippet: line.trim(),
          fix: 'Add deadline/expiration to all intents',
        });
      }
    }

    // Check for solver selection
    if (/solver|filler|executor.*select/i.test(line)) {
      const nearbyContent = lines.slice(Math.max(0, i - 20), Math.min(lines.length, i + 20)).join('\n');
      
      // Check for solver bonding
      if (!/bond|stake|collateral.*solver/i.test(nearbyContent)) {
        findings.push({
          id: 'SOL143',
          name: 'Solver Not Bonded',
          severity: 'high',
          message: 'Unbonded solvers can fail to execute without penalty',
          location: `${input.path}:${i + 1}`,
          snippet: line.trim(),
          fix: 'Require solvers to post bond that is slashed for non-execution',
        });
      }

      // Check for competition
      if (!/auction|compete|bid|best.*price/i.test(nearbyContent)) {
        findings.push({
          id: 'SOL143',
          name: 'No Solver Competition',
          severity: 'medium',
          message: 'Single solver selection can lead to poor execution',
          location: `${input.path}:${i + 1}`,
          snippet: line.trim(),
          fix: 'Implement solver auction for competitive execution',
        });
      }
    }

    // Check for execution verification
    if (/execute.*intent|fill.*order|settle.*intent/i.test(line)) {
      const nearbyContent = lines.slice(Math.max(0, i - 10), Math.min(lines.length, i + 10)).join('\n');
      
      // Check output validation
      if (!/verify.*output|check.*received|min.*out/i.test(nearbyContent)) {
        findings.push({
          id: 'SOL143',
          name: 'Intent Execution Not Verified',
          severity: 'critical',
          message: 'Intent execution without output verification can cheat users',
          location: `${input.path}:${i + 1}`,
          snippet: line.trim(),
          fix: 'Verify user receives at least min_output_amount specified in intent',
        });
      }
    }

    // Check for batch execution
    if (/batch.*intent|aggregate.*order|multi.*fill/i.test(line)) {
      findings.push({
        id: 'SOL143',
        name: 'Batch Execution Risk',
        severity: 'medium',
        message: 'Batched intents can hide cross-user MEV extraction',
        location: `${input.path}:${i + 1}`,
        snippet: line.trim(),
        fix: 'Ensure batch execution benefits all users fairly (surplus sharing)',
      });
    }
  });

  return findings;
}
