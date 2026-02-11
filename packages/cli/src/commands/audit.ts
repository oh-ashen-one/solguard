/**
 * Audit Command Types and Runner
 */

import { scan, type ScanResult, type Finding as SdkFinding } from '../sdk.js';
import chalk from 'chalk';
import { getContextNotices, displayContextNotices, displayDisclaimer, type ContextNotices } from '../context-notices.js';

export interface Finding {
  id: string;
  pattern: string;
  title: string;
  severity: 'critical' | 'high' | 'medium' | 'low' | 'info';
  description: string;
  location: { file: string; line?: number } | string;
  recommendation?: string;
  suggestion?: string;
  code?: string;
}

export interface AuditOptions {
  format?: 'text' | 'json' | 'markdown';
  output?: 'terminal' | 'json' | 'markdown';
  failOn?: 'critical' | 'high' | 'medium' | 'low' | 'any';
  ai?: boolean;
  verbose?: boolean;
}

export interface AuditResult {
  path: string;
  programPath: string;
  timestamp: string;
  duration: number;
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

/**
 * Run an audit and return structured results.
 * This is the shared implementation used by watch, fetch, certificate, etc.
 */
export async function auditCommand(path: string, options: AuditOptions = {}): Promise<AuditResult> {
  const result = await scan(path, {
    ai: options.ai,
    failOn: options.failOn || 'critical',
    format: 'object',
  });

  const findings: Finding[] = result.findings.map(f => ({
    id: f.id,
    pattern: f.pattern || f.id,
    title: f.title,
    severity: f.severity,
    description: f.description,
    location: f.location,
    suggestion: f.suggestion,
    code: f.code,
  }));

  const auditResult: AuditResult = {
    path: result.programPath,
    programPath: result.programPath,
    timestamp: result.timestamp,
    duration: result.duration,
    findings,
    summary: result.summary,
    passed: result.passed,
  };

  // Display if output is terminal
  const outputMode = options.output || options.format || 'terminal';
  if (outputMode === 'terminal' || outputMode === 'text') {
    displayAuditResult(auditResult, result.notices);
  } else if (outputMode === 'json') {
    console.log(JSON.stringify({ ...auditResult, notices: result.notices }, null, 2));
  }

  return auditResult;
}

function displayAuditResult(result: AuditResult, notices?: ContextNotices) {
  // Show context-aware notices before findings
  if (notices) {
    displayContextNotices(notices);
  }

  if (result.findings.length === 0) {
    console.log(chalk.green('✅ No vulnerabilities found!'));
  } else {
    console.log(chalk.yellow(`⚠️  Found ${result.findings.length} potential issues:\n`));

    for (const finding of result.findings) {
      const severityColor =
        finding.severity === 'critical' ? chalk.red :
        finding.severity === 'high' ? chalk.yellow :
        finding.severity === 'medium' ? chalk.cyan :
        chalk.gray;

      const loc = typeof finding.location === 'string'
        ? finding.location
        : `${finding.location.file}${finding.location.line ? `:${finding.location.line}` : ''}`;

      console.log(`${severityColor(`[${finding.severity.toUpperCase()}]`)} ${finding.id}: ${finding.title}`);
      console.log(chalk.gray(`  └─ ${loc}`));
      console.log(chalk.gray(`     ${finding.description}`));
      if (finding.suggestion) {
        console.log(chalk.green(`     💡 ${finding.suggestion}`));
      }
      console.log();
    }
  }

  console.log(chalk.bold('\n📊 Summary:'));
  console.log(`  ${chalk.red('Critical:')} ${result.summary.critical}`);
  console.log(`  ${chalk.yellow('High:')} ${result.summary.high}`);
  console.log(`  ${chalk.cyan('Medium:')} ${result.summary.medium}`);
  console.log(`  ${chalk.gray('Low:')} ${result.summary.low}`);
  console.log(`  ${chalk.blue('Total:')} ${result.summary.total}`);
  console.log(chalk.gray(`  Duration: ${result.duration}ms\n`));

  // Always show disclaimer footer
  displayDisclaimer();
}
