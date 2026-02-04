#!/usr/bin/env node
import { Command } from 'commander';
import chalk from 'chalk';
import { auditCommand } from './commands/audit.js';
import { fetchAndAuditCommand, listKnownPrograms } from './commands/fetch.js';
import { certificateCommand } from './commands/certificate.js';
import { watchCommand } from './commands/watch.js';
import { statsCommand } from './commands/stats.js';
import { auditGithub, formatGithubAuditResult } from './commands/github.js';
import { ciCommand } from './commands/ci.js';
import { generateHtmlReport, saveHtmlReport } from './commands/report.js';
import { checkCommand } from './commands/check.js';
import { generateExampleConfig } from './config.js';
import { compareCommand } from './commands/compare.js';
import { listCommand } from './commands/list.js';
import { learnCommand } from './commands/learn.js';

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
  .version('0.1.0', '-v, --version', 'Output version number')
  .option('-V, --verbose-version', 'Show detailed version info')
  .on('option:verbose-version', () => {
    console.log(`SolGuard v0.1.0`);
    console.log(`  Patterns: 15`);
    console.log(`  Commands: 14`);
    console.log(`  Built: 2026-02-02`);
    console.log(`  Node: ${process.version}`);
    console.log(`  Platform: ${process.platform}`);
    console.log(`  https://github.com/oh-ashen-one/solguard`);
    process.exit(0);
  });

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

program
  .command('stats')
  .description('Show SolGuard statistics and capabilities')
  .action(statsCommand);

program
  .command('github')
  .description('Audit a Solana program directly from GitHub')
  .argument('<repo>', 'GitHub repository (owner/repo or URL)')
  .option('-p, --pr <number>', 'Pull request number to audit', parseInt)
  .option('-b, --branch <name>', 'Branch name to audit')
  .option('-o, --output <format>', 'Output format: text, json, markdown', 'text')
  .option('-v, --verbose', 'Show detailed output')
  .action(async (repo: string, options: any) => {
    try {
      const result = await auditGithub(repo, {
        pr: options.pr,
        branch: options.branch,
        output: options.output,
        verbose: options.verbose,
      });
      
      console.log(formatGithubAuditResult(result, options.output));
      
      // Exit with error code if critical findings
      const hasCritical = result.findings.some(f => f.severity === 'critical');
      if (hasCritical) {
        process.exit(1);
      }
    } catch (error) {
      console.error(chalk.red(`Error: ${(error as Error).message}`));
      process.exit(1);
    }
  });

program
  .command('ci')
  .description('Run audit in CI mode (GitHub Actions, etc.)')
  .argument('<path>', 'Path to program directory')
  .option('--fail-on <level>', 'Fail on severity level: critical, high, medium, low, any', 'critical')
  .option('--sarif <file>', 'Output SARIF report for GitHub Code Scanning')
  .option('--summary <file>', 'Write markdown summary to file')
  .action(ciCommand);

program
  .command('list')
  .description('List all vulnerability patterns with details')
  .option('-s, --severity <level>', 'Filter by severity: critical, high, medium')
  .option('-o, --output <format>', 'Output format: terminal, json, markdown', 'terminal')
  .action(listCommand);

program
  .command('compare')
  .description('Compare security between two program versions')
  .argument('<pathA>', 'First version (baseline)')
  .argument('<pathB>', 'Second version (new)')
  .option('-o, --output <format>', 'Output format: terminal, json, markdown', 'terminal')
  .action(compareCommand);

program
  .command('learn')
  .description('Learn about vulnerabilities with official Solana documentation')
  .argument('[query]', 'Pattern ID (SOL001) or topic (pda, cpi, tokens)')
  .option('--urls', 'Show only documentation URLs')
  .option('--brief', 'Show summary only (no full content)')
  .option('--raw', 'Output raw markdown (for piping to LLMs)')
  .action(learnCommand);

program
  .command('init')
  .description('Initialize SolGuard in a project')
  .option('-f, --force', 'Overwrite existing config')
  .action(async (options: any) => {
    const { existsSync, writeFileSync } = await import('fs');
    const configPath = 'solguard.config.json';
    
    if (existsSync(configPath) && !options.force) {
      console.log(chalk.yellow(`Config already exists: ${configPath}`));
      console.log(chalk.dim('Use --force to overwrite'));
      return;
    }
    
    writeFileSync(configPath, generateExampleConfig());
    console.log(chalk.green(`✓ Created ${configPath}`));
    console.log(chalk.dim('Edit the file to customize SolGuard behavior'));
  });

program
  .command('check')
  .description('Quick pass/fail check for scripts and pre-commit hooks')
  .argument('<path>', 'Path to program directory or Rust file')
  .option('--fail-on <level>', 'Fail on severity: critical, high, medium, low, any', 'critical')
  .option('-q, --quiet', 'Suppress output, only use exit code')
  .action(checkCommand);

program
  .command('report')
  .description('Generate HTML audit report')
  .argument('<path>', 'Path to program directory')
  .option('-o, --output <file>', 'Output HTML file', 'solguard-report.html')
  .option('-n, --name <name>', 'Program name for report')
  .action(async (path: string, options: any) => {
    const { existsSync, readdirSync, statSync, readFileSync } = await import('fs');
    const { join, basename } = await import('path');
    const { parseRustFiles } = await import('./parsers/rust.js');
    const { parseIdl } = await import('./parsers/idl.js');
    const { runPatterns } = await import('./patterns/index.js');
    
    if (!existsSync(path)) {
      console.error(chalk.red(`Path not found: ${path}`));
      process.exit(1);
    }
    
    const startTime = Date.now();
    const programName = options.name || basename(path);
    
    // Find Rust files
    function findRustFiles(dir: string): string[] {
      const files: string[] = [];
      const scan = (d: string) => {
        for (const entry of readdirSync(d, { withFileTypes: true })) {
          const full = join(d, entry.name);
          if (entry.isDirectory() && !['node_modules', 'target', '.git'].includes(entry.name)) {
            scan(full);
          } else if (entry.name.endsWith('.rs')) {
            files.push(full);
          }
        }
      };
      scan(dir);
      return files;
    }
    
    const rustFiles = statSync(path).isDirectory() ? findRustFiles(path) : [path];
    
    if (rustFiles.length === 0) {
      console.error(chalk.red('No Rust files found'));
      process.exit(1);
    }
    
    console.log(chalk.cyan(`Scanning ${rustFiles.length} files...`));
    
    // Parse and audit
    const parsed = await parseRustFiles(rustFiles);
    const allFindings: any[] = [];
    
    if (parsed && parsed.files) {
      for (const file of parsed.files) {
        const findings = await runPatterns({
          path: file.path,
          rust: {
            files: [file],
            functions: parsed.functions.filter((f: any) => f.file === file.path),
            structs: parsed.structs.filter((s: any) => s.file === file.path),
            implBlocks: parsed.implBlocks.filter((i: any) => i.file === file.path),
            content: file.content,
          } as any,
          idl: null,
        });
        allFindings.push(...findings);
      }
    }
    
    const duration = Date.now() - startTime;
    
    const summary = {
      critical: allFindings.filter(f => f.severity === 'critical').length,
      high: allFindings.filter(f => f.severity === 'high').length,
      medium: allFindings.filter(f => f.severity === 'medium').length,
      low: allFindings.filter(f => f.severity === 'low').length,
      info: allFindings.filter(f => f.severity === 'info').length,
      total: allFindings.length,
    };
    
    saveHtmlReport({
      programName,
      programPath: path,
      timestamp: new Date().toISOString(),
      findings: allFindings,
      summary,
      passed: summary.critical === 0 && summary.high === 0,
      duration,
    }, options.output);
    
    console.log(chalk.green(`✓ Report saved to ${options.output}`));
    console.log(chalk.dim(`  ${summary.total} findings | ${duration}ms`));
  });

program.parse();
