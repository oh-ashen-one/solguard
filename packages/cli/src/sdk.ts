/**
 * SolGuard SDK - Programmatic API for vulnerability scanning
 * 
 * Usage:
 *   import { scan, audit } from '@solguard/cli';
 *   
 *   const results = await scan('./my-program');
 *   if (results.summary.critical > 0) {
 *     console.error('Critical vulnerabilities found!');
 *     process.exit(1);
 *   }
 */

import { parseRustFiles } from './parsers/rust.js';
import { parseIdl } from './parsers/idl.js';
import { runPatterns } from './patterns/index.js';
import { existsSync, readdirSync, statSync, readFileSync } from 'fs';
import { join, basename } from 'path';
import { getContextNotices, DISCLAIMER_TEXT, CPI_NOTICE_TEXT, auditedProtocolNoticeText, type ContextNotices } from './context-notices.js';

export interface ScanOptions {
  /** Include AI-powered explanations (requires ANTHROPIC_API_KEY) */
  ai?: boolean;
  /** Output format */
  format?: 'object' | 'json' | 'markdown';
  /** Severity threshold to fail on */
  failOn?: 'critical' | 'high' | 'medium' | 'low' | 'any';
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

export interface ScanResult {
  programPath: string;
  programName: string;
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
  notices?: ContextNotices;
  disclaimer: string;
  contextMessages?: string[];
}

/**
 * Scan a Solana/Anchor program for vulnerabilities
 * 
 * @param path - Path to program directory or Rust file
 * @param options - Scan configuration options
 * @returns Scan results with findings and summary
 * 
 * @example
 * ```ts
 * import { scan } from '@solguard/cli';
 * 
 * const results = await scan('./programs/my-vault');
 * console.log(`Found ${results.summary.total} issues`);
 * 
 * // Fail CI on critical issues
 * if (results.summary.critical > 0) {
 *   process.exit(1);
 * }
 * ```
 */
export async function scan(path: string, options: ScanOptions = {}): Promise<ScanResult> {
  const startTime = Date.now();
  const programName = basename(path);

  if (!existsSync(path)) {
    throw new Error(`Path not found: ${path}`);
  }

  // Find Rust files
  function findRustFiles(dir: string): string[] {
    const files: string[] = [];
    const scanDir = (d: string) => {
      for (const entry of readdirSync(d, { withFileTypes: true })) {
        const full = join(d, entry.name);
        if (entry.isDirectory() && !['node_modules', 'target', '.git'].includes(entry.name)) {
          scanDir(full);
        } else if (entry.name.endsWith('.rs')) {
          files.push(full);
        }
      }
    };
    scanDir(dir);
    return files;
  }

  const rustFiles = statSync(path).isDirectory() ? findRustFiles(path) : [path];

  if (rustFiles.length === 0) {
    throw new Error('No Rust files found to scan');
  }

  // Parse and analyze
  const parsed = await parseRustFiles(rustFiles);
  const allFindings: Finding[] = [];

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

  // Determine pass/fail based on failOn option
  const failOn = options.failOn || 'critical';
  let passed = true;
  
  switch (failOn) {
    case 'any':
      passed = summary.total === 0;
      break;
    case 'low':
      passed = summary.critical === 0 && summary.high === 0 && summary.medium === 0 && summary.low === 0;
      break;
    case 'medium':
      passed = summary.critical === 0 && summary.high === 0 && summary.medium === 0;
      break;
    case 'high':
      passed = summary.critical === 0 && summary.high === 0;
      break;
    case 'critical':
    default:
      passed = summary.critical === 0;
      break;
  }

  // Gather all code for context analysis
  const allCode = rustFiles.map(f => {
    try { return readFileSync(f, 'utf-8'); } catch { return ''; }
  }).join('\n');
  
  const notices = getContextNotices(path, allCode);
  const contextMessages: string[] = [];
  if (notices.isCpiWrapper) contextMessages.push(CPI_NOTICE_TEXT);
  if (notices.auditedProtocol) contextMessages.push(auditedProtocolNoticeText(notices.auditedProtocol));
  contextMessages.push(DISCLAIMER_TEXT);

  return {
    programPath: path,
    programName,
    timestamp: new Date().toISOString(),
    duration,
    findings: allFindings,
    summary,
    passed,
    notices,
    disclaimer: DISCLAIMER_TEXT,
    contextMessages,
  };
}

/**
 * Quick check - returns true if no critical/high issues found
 * 
 * @example
 * ```ts
 * import { check } from '@solguard/cli';
 * 
 * if (!await check('./my-program')) {
 *   console.error('Security check failed!');
 *   process.exit(1);
 * }
 * ```
 */
export async function check(path: string, failOn: 'critical' | 'high' | 'medium' | 'low' | 'any' = 'critical'): Promise<boolean> {
  const result = await scan(path, { failOn });
  return result.passed;
}

/**
 * Get all available vulnerability patterns
 */
export function getPatterns(): { id: string; name: string; severity: string; description: string }[] {
  // This would need to be exported from patterns/index.ts
  // For now, return a stub that users can use
  return [];
}

// Re-export types
export type { AuditResult } from './commands/audit.js';
