#!/usr/bin/env node
import { Command } from 'commander';
import chalk from 'chalk';
import { auditCommand } from './commands/audit.js';
import { fetchAndAuditCommand, listKnownPrograms } from './commands/fetch.js';
import { certificateCommand } from './commands/certificate.js';
import { watchCommand } from './commands/watch.js';

const program = new Command();

// Only show banner for terminal output
const args = process.argv.slice(2);
const isJsonOutput = args.includes('--output') && args[args.indexOf('--output') + 1] === 'json';
if (!isJsonOutput) {
  console.log(chalk.cyan(`
╔═══════════════════════════════════════════╗
║  🛡️  SolGuard - Smart Contract Auditor    ║
║     AI-Powered Security for Solana        ║
╚═══════════════════════════════════════════╝
`));
}

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

program
  .command('fetch')
  .description('Fetch and audit a program by its on-chain program ID')
  .argument('<program-id>', 'Solana program ID (base58)')
  .option('-r, --rpc <url>', 'RPC endpoint URL')
  .option('-o, --output <format>', 'Output format: terminal, json, markdown', 'terminal')
  .option('--no-ai', 'Skip AI explanations')
  .option('-v, --verbose', 'Show detailed output')
  .action(fetchAndAuditCommand);

program
  .command('programs')
  .description('List known Solana programs')
  .action(listKnownPrograms);

program
  .command('certificate')
  .description('Generate an audit certificate (metadata + SVG)')
  .argument('<path>', 'Path to program directory or Rust file')
  .option('-o, --output <dir>', 'Output directory', '.')
  .option('-p, --program-id <id>', 'Program ID for the certificate')
  .action(certificateCommand);

program
  .command('watch')
  .description('Watch for file changes and auto-audit')
  .argument('<path>', 'Path to program directory')
  .option('-o, --output <format>', 'Output format: terminal, json, markdown', 'terminal')
  .option('--no-ai', 'Skip AI explanations')
  .action(watchCommand);

program.parse();
