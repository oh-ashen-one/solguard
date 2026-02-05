import type { Finding } from '../commands/audit.js';
import type { PatternInput } from './index.js';

export function checkSeedCollision(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  const content = input.rust?.content || '';
  const fileName = input.rust?.filePath || 'unknown';

  // Check for seed patterns
  const seedPatterns = [
    /seeds\s*=\s*\[/g,
    /find_program_address.*\[/g,
    /create_program_address.*\[/g,
  ];

  for (const pattern of seedPatterns) {
    const matches = [...content.matchAll(pattern)];
    for (const match of matches) {
      const contextEnd = Math.min(content.length, match.index! + 500);
      const seedContext = content.substring(match.index!, contextEnd);
      
      // Extract seeds from the context
      const seedMatch = seedContext.match(/\[([^\]]+)\]/);
      if (seedMatch) {
        const seedContent = seedMatch[1];
        
        // Check for literal-only seeds (no dynamic component)
        if (!seedContent.includes('.key()') && !seedContent.includes('.as_ref()') &&
            !seedContent.includes('&') && /^[a-z"'\s,b!]+$/i.test(seedContent)) {
          const lineNumber = content.substring(0, match.index).split('\n').length;
          findings.push({
            id: 'SOL174',
            title: 'PDA With Static-Only Seeds',
            severity: 'high',
            description: 'PDA uses only static/literal seeds. No user differentiation - all users share same PDA.',
            location: { file: fileName, line: lineNumber },
            recommendation: 'Include user pubkey or unique identifier in seeds for user-specific PDAs.',
          });
        }

        // Check for potential collision with short seeds
        if (seedContent.split(',').length < 2 && !seedContent.includes('key')) {
          const lineNumber = content.substring(0, match.index).split('\n').length;
          findings.push({
            id: 'SOL174',
            title: 'PDA With Minimal Seeds',
            severity: 'medium',
            description: 'PDA uses very few seeds. Consider if this could lead to unintended collisions.',
            location: { file: fileName, line: lineNumber },
            recommendation: 'Ensure seeds are sufficiently unique for the use case.',
          });
        }

        // Check for user-controlled seed without length check
        if (seedContent.includes('as_ref()') && !content.includes('len()')) {
          const lineNumber = content.substring(0, match.index).split('\n').length;
          findings.push({
            id: 'SOL174',
            title: 'Variable-Length Seed Without Validation',
            severity: 'high',
            description: 'User-provided seed without length validation. Could cause PDA derivation to fail or collide.',
            location: { file: fileName, line: lineNumber },
            recommendation: 'Validate seed length before use (max 32 bytes per seed).',
          });
        }
      }
    }
  }

  // Check for multi-dimensional PDA patterns
  const multiSeedPatterns = [
    /user.*mint/gi,
    /pool.*token/gi,
    /market.*base.*quote/gi,
  ];

  for (const pattern of multiSeedPatterns) {
    if (pattern.test(content)) {
      // Look for corresponding seed definitions
      const hasProperSeeds = content.includes('user.key()') || content.includes('mint.key()') ||
                             content.includes('pool.key()') || content.includes('market.key()');
      
      if (!hasProperSeeds) {
        findings.push({
          id: 'SOL174',
          title: 'Complex Account Without Proper PDA Seeds',
          severity: 'high',
          description: 'Multi-dimensional account structure without corresponding seed derivation.',
          location: { file: fileName, line: 1 },
          recommendation: 'Include all relevant keys in PDA seeds (user, mint, pool, etc.).',
        });
        break;
      }
    }
  }

  // Check for PDA type confusion
  const accountTypes = content.match(/pub\s+struct\s+(\w+Account|\w+State)/gi) || [];
  if (accountTypes.length > 1) {
    // Multiple account types - check for type differentiation in seeds
    const hasTypeSeed = content.includes('"vault"') || content.includes('"user"') ||
                        content.includes('"pool"') || content.includes('b"');
    
    if (!hasTypeSeed) {
      findings.push({
        id: 'SOL174',
        title: 'Multiple Account Types Without Seed Differentiation',
        severity: 'high',
        description: 'Multiple account types exist but seeds may not differentiate between them.',
        location: { file: fileName, line: 1 },
        recommendation: 'Add type identifier to PDA seeds (e.g., b"vault", b"user") to prevent type confusion.',
      });
    }
  }

  // Check for canonical bump usage
  const bumpPatterns = [
    /bump\s*=\s*bump/g,
    /bump\s*=\s*\w+\.bump/g,
  ];

  let hasBumpStorage = false;
  for (const pattern of bumpPatterns) {
    if (pattern.test(content)) {
      hasBumpStorage = true;
      break;
    }
  }

  // Check for find_program_address without storing bump
  if (content.includes('find_program_address') && !hasBumpStorage) {
    const findMatches = [...content.matchAll(/find_program_address/g)];
    for (const match of findMatches) {
      const lineNumber = content.substring(0, match.index).split('\n').length;
      findings.push({
        id: 'SOL174',
        title: 'PDA Bump Not Stored',
        severity: 'low',
        description: 'find_program_address called but bump not stored. Re-derivation wastes compute.',
        location: { file: fileName, line: lineNumber },
        recommendation: 'Store canonical bump in account and use create_program_address for verification.',
      });
    }
  }

  // Check for non-canonical bump usage
  if (content.includes('create_program_address') && !content.includes('find_program_address')) {
    findings.push({
      id: 'SOL174',
      title: 'Direct PDA Creation Without Canonical Bump',
      severity: 'high',
      description: 'create_program_address used without find_program_address. May use non-canonical bump.',
      location: { file: fileName, line: 1 },
      recommendation: 'Use find_program_address to get canonical bump, or verify stored bump is canonical.',
    });
  }

  // Check for seed concatenation issues
  const concatPattern = /\.extend|\.append|format!\(.*seed/gi;
  const concatMatches = [...content.matchAll(concatPattern)];
  
  for (const match of concatMatches) {
    const contextEnd = Math.min(content.length, match.index! + 300);
    const context = content.substring(match.index!, contextEnd);
    
    if (context.includes('seed') && !context.includes('delimiter') && !context.includes('separator')) {
      const lineNumber = content.substring(0, match.index).split('\n').length;
      findings.push({
        id: 'SOL174',
        title: 'Seed Concatenation Without Delimiter',
        severity: 'high',
        description: 'Seeds concatenated without delimiter. "a" + "bc" == "ab" + "c" could cause collision.',
        location: { file: fileName, line: lineNumber },
        recommendation: 'Use fixed-width encoding or delimiter between concatenated seed components.',
      });
    }
  }

  return findings;
}
