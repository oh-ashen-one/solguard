import type { Finding } from '../commands/audit.js';
import type { PatternInput } from './index.js';

/**
 * SOL037: State Initialization Issues
 * Problems with initial state values and defaults.
 */
export function checkStateInitialization(input: PatternInput): Finding[] {
  const findings: Finding[] = [];

  if (!input.rust || !input.rust.files) return findings;

  for (const file of input.rust.files) {
    const lines = file.lines;

    lines.forEach((line, index) => {
      const lineNum = index + 1;

      // Pattern 1: Init without setting all critical fields
      if (line.includes('pub fn initialize') || line.includes('pub fn init')) {
        const fnEnd = Math.min(lines.length, index + 50);
        const fnBody = lines.slice(index, fnEnd).join('\n');

        // Check for common fields that should be initialized
        const criticalFields = ['admin', 'authority', 'owner', 'paused', 'version'];
        const missingFields = criticalFields.filter(field => 
          !fnBody.includes(`${field}:`) && !fnBody.includes(`${field} =`)
        );

        // Only report if we found the struct but missing common fields
        if (missingFields.length > 0 && fnBody.includes('= ') && fnBody.includes('{')) {
          findings.push({
            id: `SOL037-${findings.length + 1}`,
            pattern: 'State Initialization Issues',
            severity: 'info',
            title: 'Initialize may be missing common fields',
            description: `Consider initializing: ${missingFields.join(', ')}. Review if these are needed.`,
            location: { file: file.path, line: lineNum },
            suggestion: 'Ensure all critical state fields are explicitly initialized.',
          });
        }
      }

      // Pattern 2: Using Default::default() for complex types
      if (line.includes('Default::default()') || line.includes('..Default::default()')) {
        const contextStart = Math.max(0, index - 5);
        const context = lines.slice(contextStart, index + 1).join('\n');

        if (context.includes('Account') || context.includes('State') || context.includes('Config')) {
          findings.push({
            id: `SOL037-${findings.length + 1}`,
            pattern: 'State Initialization Issues',
            severity: 'medium',
            title: 'Complex type using Default::default()',
            description: 'Using Default for state may leave critical fields with unsafe default values.',
            location: { file: file.path, line: lineNum },
            suggestion: 'Explicitly initialize all fields instead of using Default.',
          });
        }
      }

      // Pattern 3: Boolean flags defaulting to false (paused = false)
      if ((line.includes('paused') || line.includes('active') || line.includes('enabled')) &&
          line.includes(': bool')) {
        const structEnd = Math.min(lines.length, index + 3);
        const context = lines.slice(index, structEnd).join('\n');

        if (!context.includes('// ') && !context.includes('/// ')) {
          findings.push({
            id: `SOL037-${findings.length + 1}`,
            pattern: 'State Initialization Issues',
            severity: 'low',
            title: 'Boolean flag without documentation',
            description: 'Boolean flags like paused/active should be documented. Default false may be unexpected.',
            location: { file: file.path, line: lineNum },
            suggestion: 'Document expected default and behavior: /// If true, protocol is paused',
          });
        }
      }

      // Pattern 4: Version field not set or set to 0
      if (line.includes('version') && (line.includes(': u8') || line.includes(': u16'))) {
        const contextEnd = Math.min(lines.length, index + 20);
        const afterContext = lines.slice(index, contextEnd).join('\n');

        if (afterContext.includes('version: 0') || afterContext.includes('version = 0')) {
          findings.push({
            id: `SOL037-${findings.length + 1}`,
            pattern: 'State Initialization Issues',
            severity: 'low',
            title: 'Version initialized to 0',
            description: 'Starting version at 0 is valid but 1 is more conventional and allows 0 = uninitialized.',
            location: { file: file.path, line: lineNum },
            suggestion: 'Consider starting version at 1 to distinguish from uninitialized state.',
          });
        }
      }
    });
  }

  return findings;
}
