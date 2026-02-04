import chalk from 'chalk';
import type { AuditResult, Finding } from '../commands/audit.js';

export function formatTerminal(result: AuditResult): string {
  const lines: string[] = [];
  
  // Header
  lines.push('');
  lines.push(chalk.bold('━'.repeat(60)));
  lines.push(chalk.bold(`  📋 AUDIT REPORT`));
  lines.push(chalk.gray(`  ${result.programPath}`));
  lines.push(chalk.gray(`  ${result.timestamp}`));
  lines.push(chalk.bold('━'.repeat(60)));
  lines.push('');
  
  // Summary
  const { summary } = result;
  lines.push(chalk.bold('  SUMMARY'));
  lines.push('');
  
  if (summary.critical > 0) {
    lines.push(chalk.red(`    🔴 Critical: ${summary.critical}`));
  }
  if (summary.high > 0) {
    lines.push(chalk.redBright(`    🟠 High: ${summary.high}`));
  }
  if (summary.medium > 0) {
    lines.push(chalk.yellow(`    🟡 Medium: ${summary.medium}`));
  }
  if (summary.low > 0) {
    lines.push(chalk.blue(`    🔵 Low: ${summary.low}`));
  }
  if (summary.info > 0) {
    lines.push(chalk.gray(`    ⚪ Info: ${summary.info}`));
  }
  
  lines.push('');
  lines.push(chalk.gray(`    Total: ${summary.total} findings`));
  lines.push('');
  
  // Status
  if (result.passed) {
    lines.push(chalk.green.bold('  ✅ PASSED - No critical or high severity issues'));
  } else {
    lines.push(chalk.red.bold('  ❌ FAILED - Critical or high severity issues found'));
  }
  
  lines.push('');
  lines.push(chalk.bold('━'.repeat(60)));
  lines.push('');
  
  // Findings
  if (result.findings.length > 0) {
    lines.push(chalk.bold('  FINDINGS'));
    lines.push('');
    
    for (const finding of result.findings) {
      lines.push(formatFinding(finding));
      lines.push('');
    }
  }
  
  return lines.join('\n');
}

function formatFinding(finding: Finding): string {
  const lines: string[] = [];
  
  const severityColor = {
    critical: chalk.red,
    high: chalk.redBright,
    medium: chalk.yellow,
    low: chalk.blue,
    info: chalk.gray,
  };
  
  const color = severityColor[finding.severity];
  
  lines.push(color(`  [${finding.id}] ${finding.severity.toUpperCase()}: ${finding.title}`));
  lines.push(chalk.gray(`  └─ ${finding.location.file}${finding.location.line ? `:${finding.location.line}` : ''}`));
  lines.push('');
  lines.push(chalk.white(`     ${finding.description}`));
  
  if (finding.code) {
    lines.push('');
    lines.push(chalk.gray(`     Code: ${finding.code}`));
  }
  
  if (finding.suggestion) {
    lines.push('');
    lines.push(chalk.cyan(`     💡 Fix: ${finding.suggestion.split('\n')[0]}`));
  }
  
  if (finding.aiExplanation) {
    lines.push('');
    lines.push(chalk.magenta(`     🤖 AI: ${finding.aiExplanation}`));
  }
  
  return lines.join('\n');
}

export function formatJson(result: AuditResult): string {
  return JSON.stringify(result, null, 2);
}

export function formatMarkdown(result: AuditResult): string {
  const lines: string[] = [];
  
  lines.push(`# 🛡️ SolShield AI Audit Report`);
  lines.push('');
  lines.push(`**Program:** \`${result.programPath}\``);
  lines.push(`**Date:** ${result.timestamp}`);
  lines.push('');
  
  // Summary
  lines.push('## Summary');
  lines.push('');
  lines.push('| Severity | Count |');
  lines.push('|----------|-------|');
  lines.push(`| 🔴 Critical | ${result.summary.critical} |`);
  lines.push(`| 🟠 High | ${result.summary.high} |`);
  lines.push(`| 🟡 Medium | ${result.summary.medium} |`);
  lines.push(`| 🔵 Low | ${result.summary.low} |`);
  lines.push(`| ⚪ Info | ${result.summary.info} |`);
  lines.push(`| **Total** | **${result.summary.total}** |`);
  lines.push('');
  
  // Status
  if (result.passed) {
    lines.push('### ✅ Status: PASSED');
    lines.push('No critical or high severity issues found.');
  } else {
    lines.push('### ❌ Status: FAILED');
    lines.push('Critical or high severity issues require immediate attention.');
  }
  lines.push('');
  
  // Findings
  if (result.findings.length > 0) {
    lines.push('## Findings');
    lines.push('');
    
    for (const finding of result.findings) {
      const emoji = {
        critical: '🔴',
        high: '🟠',
        medium: '🟡',
        low: '🔵',
        info: '⚪',
      };
      
      lines.push(`### ${emoji[finding.severity]} [${finding.id}] ${finding.title}`);
      lines.push('');
      lines.push(`**Severity:** ${finding.severity.toUpperCase()}`);
      lines.push(`**Location:** \`${finding.location.file}${finding.location.line ? `:${finding.location.line}` : ''}\``);
      lines.push('');
      lines.push(finding.description);
      lines.push('');
      
      if (finding.code) {
        lines.push('**Code:**');
        lines.push('```rust');
        lines.push(finding.code);
        lines.push('```');
        lines.push('');
      }
      
      if (finding.suggestion) {
        lines.push('**Recommendation:**');
        lines.push('```rust');
        lines.push(finding.suggestion);
        lines.push('```');
        lines.push('');
      }
      
      if (finding.aiExplanation) {
        lines.push(`> 🤖 **AI Analysis:** ${finding.aiExplanation}`);
        lines.push('');
      }
    }
  }
  
  lines.push('---');
  lines.push('*Generated by [SolShield AI](https://github.com/oh-ashen-one/solshield)*');
  
  return lines.join('\n');
}
