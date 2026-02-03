import chalk from 'chalk';
import ora from 'ora';
import { parseIdl } from '../parsers/idl.js';
import { parseRustFiles } from '../parsers/rust.js';
import { runPatterns } from '../patterns/index.js';
import { explainFindings } from '../ai/explain.js';
import { formatTerminal, formatJson, formatMarkdown } from '../report/index.js';
import { existsSync, readdirSync, statSync } from 'fs';
import { join } from 'path';

export interface AuditOptions {
  output: 'terminal' | 'json' | 'markdown';
  ai: boolean;
  verbose: boolean;
}

export interface Finding {
  id: string;
  pattern: string;
  severity: 'critical' | 'high' | 'medium' | 'low' | 'info';
  title: string;
  description: string;
  location: {
    file: string;
    line?: number;
    column?: number;
  };
  code?: string;
  suggestion?: string;
  aiExplanation?: string;
}

export interface AuditResult {
  programPath: string;
  timestamp: string;
  findings: Finding[];
  summary: {
    critical: number;
    high: number;
    medium: number;
    low: number;
    info: number;
    total: number;
  };
  passed: boolean;
}

export async function auditCommand(path: string, options: AuditOptions) {
  const spinner = ora('Starting audit...').start();
  
  try {
    // Validate path exists
    if (!existsSync(path)) {
      spinner.fail(`Path not found: ${path}`);
      process.exit(1);
    }

    const isDirectory = statSync(path).isDirectory();
    let idlPath: string | null = null;
    let rustFiles: string[] = [];

    if (isDirectory) {
      // Look for IDL in target/idl/ or the directory itself
      const idlDir = join(path, 'target', 'idl');
      if (existsSync(idlDir)) {
        const idlFiles = readdirSync(idlDir).filter(f => f.endsWith('.json'));
        if (idlFiles.length > 0) {
          idlPath = join(idlDir, idlFiles[0]);
        }
      }
      
      // Find all .rs files in programs/ or src/
      const programsDir = join(path, 'programs');
      const srcDir = join(path, 'src');
      
      if (existsSync(programsDir)) {
        rustFiles = findRustFiles(programsDir);
      } else if (existsSync(srcDir)) {
        rustFiles = findRustFiles(srcDir);
      }
    } else if (path.endsWith('.json')) {
      idlPath = path;
    } else if (path.endsWith('.rs')) {
      rustFiles = [path];
    }

    spinner.text = 'Parsing program...';

    // Parse IDL if available
    let idlData = null;
    if (idlPath) {
      spinner.text = `Parsing IDL: ${idlPath}`;
      idlData = await parseIdl(idlPath);
      if (options.verbose) {
        console.log(chalk.gray(`\n  Found ${idlData.instructions.length} instructions`));
      }
    }

    // Parse Rust files
    let rustAst = null;
    if (rustFiles.length > 0) {
      spinner.text = `Parsing ${rustFiles.length} Rust files...`;
      rustAst = await parseRustFiles(rustFiles);
      if (options.verbose) {
        console.log(chalk.gray(`\n  Parsed ${rustFiles.length} files`));
      }
    }

    if (!idlData && !rustAst) {
      spinner.fail('No IDL or Rust files found to audit');
      process.exit(1);
    }

    // Run vulnerability patterns
    spinner.text = 'Scanning for vulnerabilities...';
    const findings = await runPatterns({ idl: idlData, rust: rustAst, path });

    // Get AI explanations if enabled
    if (options.ai && findings.length > 0) {
      spinner.text = 'Generating AI explanations...';
      await explainFindings(findings);
    }

    // Build result
    const result: AuditResult = {
      programPath: path,
      timestamp: new Date().toISOString(),
      findings,
      summary: {
        critical: findings.filter(f => f.severity === 'critical').length,
        high: findings.filter(f => f.severity === 'high').length,
        medium: findings.filter(f => f.severity === 'medium').length,
        low: findings.filter(f => f.severity === 'low').length,
        info: findings.filter(f => f.severity === 'info').length,
        total: findings.length,
      },
      passed: findings.filter(f => ['critical', 'high'].includes(f.severity)).length === 0,
    };

    spinner.stop();

    // Output results
    switch (options.output) {
      case 'json':
        console.log(formatJson(result));
        break;
      case 'markdown':
        console.log(formatMarkdown(result));
        break;
      default:
        console.log(formatTerminal(result));
    }

    // Exit with error code if critical/high findings
    if (!result.passed) {
      process.exit(1);
    }

  } catch (error) {
    spinner.fail(`Audit failed: ${error}`);
    process.exit(1);
  }
}

function findRustFiles(dir: string): string[] {
  const files: string[] = [];
  
  function walk(currentDir: string) {
    const entries = readdirSync(currentDir);
    for (const entry of entries) {
      const fullPath = join(currentDir, entry);
      const stat = statSync(fullPath);
      if (stat.isDirectory() && !entry.startsWith('.') && entry !== 'target') {
        walk(fullPath);
      } else if (entry.endsWith('.rs')) {
        files.push(fullPath);
      }
    }
  }
  
  walk(dir);
  return files;
}
