import type { Finding } from '../commands/audit.js';
import type { PatternInput } from './index.js';

export function checkMissingConstraint(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  const content = input.rust?.content || '';
  const fileName = input.rust?.filePath || 'unknown';

  // Check for accounts without has_one constraint where expected
  const structPattern = /#\[derive\(Accounts\)\][\s\S]*?pub\s+struct\s+(\w+)[\s\S]*?\{([\s\S]*?)\}/g;
  const matches = [...content.matchAll(structPattern)];

  for (const match of matches) {
    const structName = match[1];
    const structBody = match[2];
    
    // Check for authority fields without has_one
    if (structBody.includes('authority') && !structBody.includes('has_one = authority')) {
      if (!structBody.includes('#[account(signer') && structBody.includes('authority')) {
        const lineNumber = content.substring(0, match.index).split('\n').length;
        findings.push({
          id: 'SOL154',
          title: 'Missing has_one Constraint for Authority',
          severity: 'critical',
          description: `Struct ${structName} has an authority field but no has_one constraint to validate it. This allows anyone to pass arbitrary authority accounts.`,
          location: { file: fileName, line: lineNumber },
          recommendation: 'Add #[account(has_one = authority)] to the relevant account or explicitly validate the authority relationship.',
        });
      }
    }

    // Check for owner fields without has_one
    if (structBody.includes('owner') && !structBody.includes('has_one = owner') && !structBody.includes('constraint = ')) {
      const lineNumber = content.substring(0, match.index).split('\n').length;
      findings.push({
        id: 'SOL154',
        title: 'Missing has_one Constraint for Owner',
        severity: 'high',
        description: `Struct ${structName} has an owner field but may be missing ownership validation. Without proper constraints, arbitrary owners can be passed.`,
        location: { file: fileName, line: lineNumber },
        recommendation: 'Add #[account(has_one = owner)] or explicit constraint validation.',
      });
    }

    // Check for mint fields without proper constraints
    if (structBody.includes('mint') && !structBody.includes('constraint =') && !structBody.includes('has_one = mint')) {
      if (structBody.includes('token_account') || structBody.includes('TokenAccount')) {
        const lineNumber = content.substring(0, match.index).split('\n').length;
        findings.push({
          id: 'SOL154',
          title: 'Token Account Without Mint Constraint',
          severity: 'high',
          description: `Struct ${structName} has token accounts but may be missing mint validation. Attackers can pass token accounts with different mints.`,
          location: { file: fileName, line: lineNumber },
          recommendation: 'Add constraint = token_account.mint == expected_mint or use has_one = mint.',
        });
      }
    }
  }

  // Check for close constraints without proper destination
  const closePattern = /#\[account\([^)]*close\s*=[^)]*\)/g;
  const closeMatches = [...content.matchAll(closePattern)];
  for (const match of closeMatches) {
    const closeContext = match[0];
    if (!closeContext.includes('@ ') && !closeContext.includes('constraint')) {
      const lineNumber = content.substring(0, match.index).split('\n').length;
      findings.push({
        id: 'SOL154',
        title: 'Account Close Without Validation',
        severity: 'high',
        description: 'Account close constraint used without additional validation. Ensure the close destination is properly validated.',
        location: { file: fileName, line: lineNumber },
        recommendation: 'Add constraint validation to ensure only authorized parties can close accounts and receive lamports.',
      });
    }
  }

  // Check for init constraints without payer validation
  const initPattern = /#\[account\([^)]*init[^)]*\)/g;
  const initMatches = [...content.matchAll(initPattern)];
  for (const match of initMatches) {
    const initContext = match[0];
    if (!initContext.includes('payer')) {
      const lineNumber = content.substring(0, match.index).split('\n').length;
      findings.push({
        id: 'SOL154',
        title: 'Account Init Without Payer',
        severity: 'medium',
        description: 'Account initialization without explicit payer specification.',
        location: { file: fileName, line: lineNumber },
        recommendation: 'Always specify the payer for account initialization: #[account(init, payer = user, ...)]',
      });
    }
  }

  // Check for seeds without bump
  const seedsPattern = /#\[account\([^)]*seeds\s*=\s*\[[^\]]+\][^)]*\)/g;
  const seedsMatches = [...content.matchAll(seedsPattern)];
  for (const match of seedsMatches) {
    const seedsContext = match[0];
    if (!seedsContext.includes('bump')) {
      const lineNumber = content.substring(0, match.index).split('\n').length;
      findings.push({
        id: 'SOL154',
        title: 'PDA Seeds Without Bump',
        severity: 'medium',
        description: 'PDA seeds specified without bump constraint. While Anchor handles this, explicit bump storage is recommended for efficiency.',
        location: { file: fileName, line: lineNumber },
        recommendation: 'Store and specify bump: seeds = [...], bump = account.bump',
      });
    }
  }

  return findings;
}
