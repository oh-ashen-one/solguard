/**
 * Compare Command
 * 
 * Compare security posture between two versions of a program
 * Useful for reviewing changes before merging PRs
 */

import { existsSync, readFileSync, readdirSync, statSync } from 'fs';
import { join, relative } from 'path';
import chalk from 'chalk';
import { parseRustFiles } from '../parsers/rust.js';
import { runPatterns } from '../patterns/index.js';
import { diffAudits, formatDiff } from './diff.js';
import type { Finding } from './audit.js';

interface CompareOptions {
  output?: 'terminal' | 'json' | 'markdown';
}

/**
 * Compare two paths and show security diff
 */
export async function compareCommand(
  pathA: string,
  pathB: string,
  options: CompareOptions = {}
) {
  const format = options.output || 'terminal';
  
  // Validate paths
  if (!existsSync(pathA)) {
    console.error(chalk.red(`Path not found: ${pathA}`));
    process.exit(1);
  }
  
  if (!existsSync(pathB)) {
    console.error(chalk.red(`Path not found: ${pathB}`));
    process.exit(1);
  }
  
  console.log(chalk.cyan('Analyzing both versions...'));
  
  // Audit both paths
  const findingsA = await auditPath(pathA);
  const findingsB = await auditPath(pathB);
  
  console.log(chalk.dim(`  Version A: ${findingsA.length} findings`));
  console.log(chalk.dim(`  Version B: ${findingsB.length} findings`));
  console.log('');
  
  // Generate diff
  const diff = diffAudits(findingsA, findingsB);
  
  // Output based on format
  if (format === 'json') {
    console.log(JSON.stringify({
      versionA: pathA,
      versionB: pathB,
      diff,
    }, null, 2));
  } else if (format === 'markdown') {
    console.log(`# Security Comparison\n`);
    console.log(`**Version A:** ${pathA}`);
    console.log(`**Version B:** ${pathB}\n`);
    console.log(formatDiffMarkdown(diff));
  } else {
    console.log(chalk.bold('Security Comparison'));
    console.log(chalk.gray('─'.repeat(50)));
    console.log(`  A: ${pathA}`);
    console.log(`  B: ${pathB}`);
    console.log('');
    console.log(formatDiff(diff));
  }
  
  // Exit code based on whether security improved
  if (diff.added.length > 0) {
    const criticalAdded = diff.added.filter(f => f.severity === 'critical').length;
    if (criticalAdded > 0) {
      console.log(chalk.red(`\n⚠️  ${criticalAdded} new CRITICAL issues introduced!`));
      process.exit(1);
    }
  }
  
  if (diff.summary.improved) {
    console.log(chalk.green('\n✓ Security improved!'));
    process.exit(0);
  } else if (diff.added.length > 0) {
    console.log(chalk.yellow('\n⚠️  New security issues introduced'));
    process.exit(1);
  } else {
    console.log(chalk.blue('\n→ Security unchanged'));
    process.exit(0);
  }
}

/**
 * Audit a path and return findings
 */
async function auditPath(path: string): Promise<Finding[]> {
  const rustFiles = findRustFiles(path);
  
  if (rustFiles.length === 0) {
    return [];
  }
  
  const parsed = await parseRustFiles(rustFiles);
  const findings: Finding[] = [];
  
  if (parsed && parsed.files) {
    for (const file of parsed.files) {
      const fileFindings = await runPatterns({
        path: relative(path, file.path) || file.path,
        rust: {
          files: [file],
          functions: parsed.functions.filter(f => f.file === file.path),
          structs: parsed.structs.filter(s => s.file === file.path),
          implBlocks: parsed.implBlocks.filter(i => i.file === file.path),
          content: file.content,
        } as any,
        idl: null,
      });
      findings.push(...fileFindings);
    }
  }
  
  return findings;
}

/**
 * Find all Rust files in a path
 */
function findRustFiles(path: string): string[] {
  if (statSync(path).isFile()) {
    return path.endsWith('.rs') ? [path] : [];
  }
  
  const files: string[] = [];
  
  function scan(dir: string) {
    for (const entry of readdirSync(dir, { withFileTypes: true })) {
      const full = join(dir, entry.name);
      if (entry.isDirectory() && !['node_modules', 'target', '.git'].includes(entry.name)) {
        scan(full);
      } else if (entry.name.endsWith('.rs')) {
        files.push(full);
      }
    }
  }
  
  scan(path);
  return files;
}

/**
 * Format diff as markdown
 */
function formatDiffMarkdown(diff: ReturnType<typeof diffAudits>): string {
  const lines: string[] = [];
  
  const emoji = diff.summary.improved ? '✅' : diff.added.length > 0 ? '⚠️' : '➖';
  lines.push(`${emoji} **Summary:** ${diff.summary.added} new, ${diff.summary.removed} fixed, ${diff.summary.unchanged} unchanged\n`);
  
  if (diff.added.length > 0) {
    lines.push('## 🔴 New Issues\n');
    for (const f of diff.added) {
      lines.push(`- **[${f.pattern}] ${f.title}** (${f.severity})`);
    }
    lines.push('');
  }
  
  if (diff.removed.length > 0) {
    lines.push('## 🟢 Fixed Issues\n');
    for (const f of diff.removed) {
      lines.push(`- ~~[${f.pattern}] ${f.title}~~ (${f.severity})`);
    }
    lines.push('');
  }
  
  return lines.join('\n');
}
