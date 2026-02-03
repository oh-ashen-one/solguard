/**
 * Audit Diff Command
 * 
 * Compare findings between two audits or audit runs
 */

import type { Finding } from './audit.js';

export interface AuditDiff {
  added: Finding[];
  removed: Finding[];
  unchanged: Finding[];
  summary: {
    added: number;
    removed: number;
    unchanged: number;
    improved: boolean;
  };
}

/**
 * Compare two audit results and show what changed
 */
export function diffAudits(
  oldFindings: Finding[],
  newFindings: Finding[]
): AuditDiff {
  const added: Finding[] = [];
  const removed: Finding[] = [];
  const unchanged: Finding[] = [];
  
  // Create lookup maps by a unique key (pattern + location)
  const oldMap = new Map<string, Finding>();
  const newMap = new Map<string, Finding>();
  
  for (const f of oldFindings) {
    const key = getFindingKey(f);
    oldMap.set(key, f);
  }
  
  for (const f of newFindings) {
    const key = getFindingKey(f);
    newMap.set(key, f);
  }
  
  // Find added (in new but not in old)
  for (const [key, finding] of newMap) {
    if (!oldMap.has(key)) {
      added.push(finding);
    } else {
      unchanged.push(finding);
    }
  }
  
  // Find removed (in old but not in new)
  for (const [key, finding] of oldMap) {
    if (!newMap.has(key)) {
      removed.push(finding);
    }
  }
  
  // Calculate if improved (removed more critical/high than added)
  const severityWeight = {
    critical: 100,
    high: 50,
    medium: 10,
    low: 2,
    info: 1,
  };
  
  const addedScore = added.reduce((sum, f) => sum + (severityWeight[f.severity] || 0), 0);
  const removedScore = removed.reduce((sum, f) => sum + (severityWeight[f.severity] || 0), 0);
  
  return {
    added,
    removed,
    unchanged,
    summary: {
      added: added.length,
      removed: removed.length,
      unchanged: unchanged.length,
      improved: removedScore > addedScore,
    },
  };
}

/**
 * Create a unique key for a finding for comparison
 */
function getFindingKey(finding: Finding): string {
  const location = typeof finding.location === 'string' 
    ? finding.location 
    : `${finding.location.file}:${finding.location.line || 0}`;
  return `${finding.pattern}:${location}`;
}

/**
 * Format diff for terminal output
 */
export function formatDiff(diff: AuditDiff): string {
  const lines: string[] = [];
  
  lines.push('═══════════════════════════════════════════════════════════════');
  lines.push('  AUDIT DIFF');
  lines.push('═══════════════════════════════════════════════════════════════');
  lines.push('');
  
  // Summary
  const emoji = diff.summary.improved ? '✅' : '⚠️';
  lines.push(`${emoji} Summary: ${diff.summary.added} added, ${diff.summary.removed} removed, ${diff.summary.unchanged} unchanged`);
  lines.push('');
  
  // Added findings (bad - new vulnerabilities)
  if (diff.added.length > 0) {
    lines.push('🔴 NEW FINDINGS:');
    for (const f of diff.added) {
      lines.push(`  + [${f.pattern}] ${f.title} (${f.severity})`);
      const loc = typeof f.location === 'string' ? f.location : f.location.file;
      lines.push(`    └─ ${loc}`);
    }
    lines.push('');
  }
  
  // Removed findings (good - fixed vulnerabilities)
  if (diff.removed.length > 0) {
    lines.push('🟢 FIXED:');
    for (const f of diff.removed) {
      lines.push(`  - [${f.pattern}] ${f.title} (${f.severity})`);
    }
    lines.push('');
  }
  
  // Unchanged
  if (diff.unchanged.length > 0) {
    lines.push(`📋 UNCHANGED: ${diff.unchanged.length} findings remain`);
  }
  
  lines.push('');
  lines.push('═══════════════════════════════════════════════════════════════');
  
  return lines.join('\n');
}

/**
 * Format diff as JSON
 */
export function formatDiffJson(diff: AuditDiff): string {
  return JSON.stringify(diff, null, 2);
}

/**
 * Format diff as Markdown
 */
export function formatDiffMarkdown(diff: AuditDiff): string {
  const lines: string[] = [];
  
  lines.push('# Audit Diff Report');
  lines.push('');
  
  const emoji = diff.summary.improved ? '✅' : '⚠️';
  lines.push(`${emoji} **Summary:** ${diff.summary.added} added, ${diff.summary.removed} removed, ${diff.summary.unchanged} unchanged`);
  lines.push('');
  
  if (diff.added.length > 0) {
    lines.push('## 🔴 New Findings');
    lines.push('');
    for (const f of diff.added) {
      lines.push(`- **[${f.pattern}] ${f.title}** (${f.severity})`);
      lines.push(`  - ${f.description}`);
    }
    lines.push('');
  }
  
  if (diff.removed.length > 0) {
    lines.push('## 🟢 Fixed');
    lines.push('');
    for (const f of diff.removed) {
      lines.push(`- ~~[${f.pattern}] ${f.title}~~ (${f.severity})`);
    }
    lines.push('');
  }
  
  if (diff.unchanged.length > 0) {
    lines.push(`## 📋 Unchanged (${diff.unchanged.length})`);
    lines.push('');
    lines.push('These findings remain from the previous audit.');
  }
  
  return lines.join('\n');
}
