#!/usr/bin/env node
import { Command } from 'commander';
import chalk from 'chalk';
import { auditCommand } from './commands/audit.js';

const program = new Command();

console.log(chalk.cyan(`
╔═══════════════════════════════════════════╗
║  🛡️  SolGuard - Smart Contract Auditor    ║
║     AI-Powered Security for Solana        ║
╚═══════════════════════════════════════════╝
`));

program
  .name('solguard')
  .description('AI-powered smart contract auditor for Solana')
  .version('0.1.0');

program
  .command('audit')
  .description('Audit an Anchor program for vulnerabilities')
  .argument('<path>', 'Path to program directory or IDL file')
  .option('-o, --output <format>', 'Output format: terminal, json, markdown', 'terminal')
  .option('--no-ai', 'Skip AI explanations')
  .option('-v, --verbose', 'Show detailed output')
  .action(auditCommand);

program
  .command('parse')
  .description('Parse an Anchor IDL file')
  .argument('<idl>', 'Path to IDL JSON file')
  .action(async (idlPath: string) => {
    const { parseIdl } = await import('./parsers/idl.js');
    const result = await parseIdl(idlPath);
    console.log(JSON.stringify(result, null, 2));
  });

program.parse();
