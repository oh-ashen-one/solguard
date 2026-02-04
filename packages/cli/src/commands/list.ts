/**
 * List Command
 * 
 * List all vulnerability patterns with details
 */

import chalk from 'chalk';
import { listPatterns, getPatternById } from '../patterns/index.js';

interface ListOptions {
  severity?: string;
  output?: 'terminal' | 'json' | 'markdown';
}

const PATTERN_DESCRIPTIONS: Record<string, string> = {
  SOL001: 'Detects accounts accessed without validating the owner field. An attacker could pass a fake account owned by a different program.',
  SOL002: 'Detects authority/admin accounts that are not declared as Signers. Without signer verification, anyone can claim to be the authority.',
  SOL003: 'Detects arithmetic operations without overflow protection. Rust integers wrap on overflow, leading to unexpected behavior.',
  SOL004: 'Detects Program Derived Addresses used without validating the bump seed. Attackers could use a different bump to bypass validation.',
  SOL005: 'Detects sensitive operations (transfers, state changes) without proper authority checks.',
  SOL006: 'Detects accounts used without checking if they are initialized. Uninitialized accounts may contain garbage or be controlled by attackers.',
  SOL007: 'Detects Cross-Program Invocations without proper verification of the target program or account constraints.',
  SOL008: 'Detects division operations that may lose precision. In financial calculations, this can be exploited for profit.',
  SOL009: 'Detects when multiple accounts of the same type lack constraints ensuring they are different accounts.',
  SOL010: 'Detects improper account closing that allows account revival or rent theft.',
  SOL011: 'Detects state changes after CPI calls where a callback could manipulate state.',
  SOL012: 'Detects invoke() calls where the program_id is user-controlled without validation.',
  SOL013: 'Detects when the same account could be passed as multiple mutable parameters.',
  SOL014: 'Detects account operations that may leave accounts below rent-exempt minimum.',
  SOL015: 'Detects account deserialization without type discriminator validation, allowing type confusion attacks.',
};

const PATTERN_EXAMPLES: Record<string, { vulnerable: string; safe: string }> = {
  SOL002: {
    vulnerable: `// VULNERABLE
pub authority: AccountInfo<'info>,`,
    safe: `// SAFE
pub authority: Signer<'info>,`,
  },
  SOL003: {
    vulnerable: `// VULNERABLE
vault.balance = vault.balance + amount;`,
    safe: `// SAFE
vault.balance = vault.balance.checked_add(amount).unwrap();`,
  },
};

export function listCommand(options: ListOptions = {}) {
  const patterns = listPatterns();
  const format = options.output || 'terminal';
  
  // Filter by severity if specified
  let filtered = patterns;
  if (options.severity) {
    filtered = patterns.filter(p => p.severity === options.severity);
  }
  
  if (format === 'json') {
    const data = filtered.map(p => ({
      ...p,
      description: PATTERN_DESCRIPTIONS[p.id] || '',
      run: undefined,
    }));
    console.log(JSON.stringify(data, null, 2));
    return;
  }
  
  if (format === 'markdown') {
    console.log('# SolShield AI Vulnerability Patterns\n');
    console.log(`Total: ${filtered.length} patterns\n`);
    
    for (const p of filtered) {
      const emoji = p.severity === 'critical' ? '🔴' : p.severity === 'high' ? '🟠' : '🟡';
      console.log(`## ${emoji} ${p.id}: ${p.name}\n`);
      console.log(`**Severity:** ${p.severity}\n`);
      console.log(PATTERN_DESCRIPTIONS[p.id] || 'No description available.\n');
      
      const example = PATTERN_EXAMPLES[p.id];
      if (example) {
        console.log('\n**Example:**\n');
        console.log('```rust');
        console.log(example.vulnerable);
        console.log('```\n');
        console.log('**Fix:**\n');
        console.log('```rust');
        console.log(example.safe);
        console.log('```\n');
      }
    }
    return;
  }
  
  // Terminal format
  console.log('');
  console.log(chalk.bold('  🛡️ SolShield AI Vulnerability Patterns'));
  console.log(chalk.gray('  ─'.repeat(30)));
  console.log('');
  
  const bySeverity = {
    critical: filtered.filter(p => p.severity === 'critical'),
    high: filtered.filter(p => p.severity === 'high'),
    medium: filtered.filter(p => p.severity === 'medium'),
  };
  
  if (bySeverity.critical.length > 0) {
    console.log(chalk.red.bold('  🔴 CRITICAL'));
    console.log('');
    for (const p of bySeverity.critical) {
      console.log(chalk.white(`  ${p.id}: ${p.name}`));
      console.log(chalk.gray(`     ${truncate(PATTERN_DESCRIPTIONS[p.id] || '', 60)}`));
      console.log('');
    }
  }
  
  if (bySeverity.high.length > 0) {
    console.log(chalk.yellow.bold('  🟠 HIGH'));
    console.log('');
    for (const p of bySeverity.high) {
      console.log(chalk.white(`  ${p.id}: ${p.name}`));
      console.log(chalk.gray(`     ${truncate(PATTERN_DESCRIPTIONS[p.id] || '', 60)}`));
      console.log('');
    }
  }
  
  if (bySeverity.medium.length > 0) {
    console.log(chalk.blue.bold('  🟡 MEDIUM'));
    console.log('');
    for (const p of bySeverity.medium) {
      console.log(chalk.white(`  ${p.id}: ${p.name}`));
      console.log(chalk.gray(`     ${truncate(PATTERN_DESCRIPTIONS[p.id] || '', 60)}`));
      console.log('');
    }
  }
  
  console.log(chalk.gray('  ─'.repeat(30)));
  console.log(chalk.dim(`  Total: ${filtered.length} patterns`));
  console.log('');
}

function truncate(str: string, len: number): string {
  if (str.length <= len) return str;
  return str.slice(0, len - 3) + '...';
}
