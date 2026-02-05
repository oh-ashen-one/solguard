#!/usr/bin/env node
/**
 * SolGuard CLI - AI-Powered Smart Contract Security Auditor for Solana
 * 
 * 900+ security patterns covering real-world exploits and common vulnerabilities.
 * 
 * Usage:
 *   solguard audit ./programs/my-vault
 *   solguard check ./programs/my-vault --fail-on high
 *   solguard patterns
 */

import { Command } from 'commander';
import { scan, type ScanOptions } from './sdk.js';
import { checkCommand } from './commands/check.js';
import { listPatterns } from './patterns/index.js';
import chalk from 'chalk';

const program = new Command();

program
  .name('solguard')
  .description('AI-Powered Smart Contract Security Auditor for Solana')
  .version('0.1.0');

// Audit command (full scan with detailed output)
program
  .command('audit')
  .description('Run a full security audit on a Solana program')
  .argument('<path>', 'Path to program directory or Rust file')
  .option('-f, --format <format>', 'Output format (text|json|markdown)', 'text')
  .option('--ai', 'Include AI-powered explanations')
  .option('--fail-on <severity>', 'Exit with error on severity level (critical|high|medium|low|any)', 'critical')
  .action(async (path: string, options: any) => {
    try {
      console.log(chalk.blue('🔍 SolGuard Security Audit'));
      console.log(chalk.gray(`Scanning: ${path}\n`));
      
      const results = await scan(path, {
        format: options.format === 'json' ? 'json' : 'object',
        ai: options.ai,
        failOn: options.failOn,
      } as ScanOptions);
      
      // Display findings
      if (results.findings.length === 0) {
        console.log(chalk.green('✅ No vulnerabilities found!'));
      } else {
        console.log(chalk.yellow(`⚠️  Found ${results.findings.length} potential issues:\n`));
        
        for (const finding of results.findings) {
          const severityColor = 
            finding.severity === 'critical' ? chalk.red :
            finding.severity === 'high' ? chalk.yellow :
            finding.severity === 'medium' ? chalk.cyan :
            chalk.gray;
          
          console.log(`${severityColor(`[${finding.severity.toUpperCase()}]`)} ${finding.id}: ${finding.title}`);
          console.log(chalk.gray(`  └─ ${finding.location.file}${finding.location.line ? `:${finding.location.line}` : ''}`));
          console.log(chalk.gray(`     ${finding.description}`));
          if (finding.suggestion) {
            console.log(chalk.green(`     💡 ${finding.suggestion}`));
          }
          console.log();
        }
      }
      
      // Summary
      console.log(chalk.bold('\n📊 Summary:'));
      console.log(`  ${chalk.red('Critical:')} ${results.summary.critical}`);
      console.log(`  ${chalk.yellow('High:')} ${results.summary.high}`);
      console.log(`  ${chalk.cyan('Medium:')} ${results.summary.medium}`);
      console.log(`  ${chalk.gray('Low:')} ${results.summary.low}`);
      console.log(`  ${chalk.blue('Total:')} ${results.summary.total}`);
      console.log(chalk.gray(`  Duration: ${results.duration}ms\n`));
      
      if (!results.passed) {
        process.exit(1);
      }
    } catch (error: any) {
      console.error(chalk.red(`Error: ${error.message}`));
      process.exit(2);
    }
  });

// Check command (quick pass/fail)
program
  .command('check')
  .description('Quick security check (pass/fail)')
  .argument('<path>', 'Path to program directory')
  .option('--fail-on <severity>', 'Fail on severity level', 'critical')
  .option('-q, --quiet', 'Minimal output')
  .action(async (path: string, options: any) => {
    await checkCommand(path, {
      failOn: options.failOn,
      quiet: options.quiet,
    });
  });

// List patterns command
program
  .command('patterns')
  .description('List all available security patterns')
  .option('--json', 'Output as JSON')
  .option('-s, --severity <severity>', 'Filter by severity')
  .action((options: any) => {
    const patterns = listPatterns();
    
    let filtered = patterns;
    if (options.severity) {
      filtered = patterns.filter(p => p.severity === options.severity);
    }
    
    if (options.json) {
      console.log(JSON.stringify(filtered, null, 2));
    } else {
      console.log(chalk.blue(`\n🛡️  SolGuard Security Patterns (${filtered.length} total)\n`));
      
      const bySeverity = {
        critical: filtered.filter(p => p.severity === 'critical'),
        high: filtered.filter(p => p.severity === 'high'),
        medium: filtered.filter(p => p.severity === 'medium'),
        low: filtered.filter(p => p.severity === 'low'),
        info: filtered.filter(p => p.severity === 'info'),
      };
      
      console.log(chalk.red(`Critical (${bySeverity.critical.length}):`));
      bySeverity.critical.slice(0, 10).forEach(p => console.log(`  ${p.id}: ${p.name}`));
      if (bySeverity.critical.length > 10) console.log(chalk.gray(`  ... and ${bySeverity.critical.length - 10} more`));
      
      console.log(chalk.yellow(`\nHigh (${bySeverity.high.length}):`));
      bySeverity.high.slice(0, 10).forEach(p => console.log(`  ${p.id}: ${p.name}`));
      if (bySeverity.high.length > 10) console.log(chalk.gray(`  ... and ${bySeverity.high.length - 10} more`));
      
      console.log(chalk.cyan(`\nMedium (${bySeverity.medium.length}):`));
      bySeverity.medium.slice(0, 10).forEach(p => console.log(`  ${p.id}: ${p.name}`));
      if (bySeverity.medium.length > 10) console.log(chalk.gray(`  ... and ${bySeverity.medium.length - 10} more`));
      
      console.log(chalk.gray(`\nLow (${bySeverity.low.length}):`));
      bySeverity.low.slice(0, 5).forEach(p => console.log(`  ${p.id}: ${p.name}`));
      if (bySeverity.low.length > 5) console.log(chalk.gray(`  ... and ${bySeverity.low.length - 5} more`));
    }
  });

// Version command
program
  .command('version')
  .description('Show version')
  .action(() => {
    console.log('solguard v0.1.0');
    console.log('689+ security patterns');
  });

program.parse();

// Export SDK for programmatic use
export { scan, type ScanOptions, type ScanResult, type Finding } from './sdk.js';
export { listPatterns, getPatternById } from './patterns/index.js';
