/**
 * GitHub Integration Commands
 * 
 * Audit Solana programs directly from GitHub repos or PRs
 */

import { exec } from 'child_process';
import { promisify } from 'util';
import { mkdir, rm, readdir, readFile } from 'fs/promises';
import { join } from 'path';
import { tmpdir } from 'os';
import { runPatterns } from '../patterns/index.js';
import { parseRustFiles } from '../parsers/rust.js';
import { parseIdl } from '../parsers/idl.js';
import type { Finding } from './audit.js';

const execAsync = promisify(exec);

interface GithubAuditOptions {
  pr?: number;
  branch?: string;
  output?: 'json' | 'text' | 'markdown';
  verbose?: boolean;
}

interface GithubAuditResult {
  repo: string;
  ref: string;
  files: number;
  findings: Finding[];
  duration: number;
}

/**
 * Parse GitHub URL into owner/repo format
 */
function parseGithubUrl(input: string): { owner: string; repo: string } | null {
  // Handle full URLs
  const urlMatch = input.match(/github\.com[\/:]([^\/]+)\/([^\/\.\s]+)/);
  if (urlMatch) {
    return { owner: urlMatch[1], repo: urlMatch[2].replace(/\.git$/, '') };
  }
  
  // Handle owner/repo format
  const shortMatch = input.match(/^([^\/]+)\/([^\/]+)$/);
  if (shortMatch) {
    return { owner: shortMatch[1], repo: shortMatch[2] };
  }
  
  return null;
}

/**
 * Clone a repository to a temp directory
 */
async function cloneRepo(
  owner: string, 
  repo: string, 
  options: { pr?: number; branch?: string }
): Promise<string> {
  const tempDir = join(tmpdir(), `SolShield AI-${Date.now()}`);
  await mkdir(tempDir, { recursive: true });
  
  const repoUrl = `https://github.com/${owner}/${repo}.git`;
  
  // Clone with limited depth for speed
  await execAsync(`git clone --depth 1 ${repoUrl} ${tempDir}`, {
    timeout: 60000,
  });
  
  // If PR specified, fetch and checkout that PR
  if (options.pr) {
    await execAsync(
      `git fetch origin pull/${options.pr}/head:pr-${options.pr}`,
      { cwd: tempDir, timeout: 30000 }
    );
    await execAsync(
      `git checkout pr-${options.pr}`,
      { cwd: tempDir }
    );
  } else if (options.branch) {
    await execAsync(
      `git checkout ${options.branch}`,
      { cwd: tempDir }
    );
  }
  
  return tempDir;
}

/**
 * Find all Rust files in a directory recursively
 */
async function findRustFiles(dir: string): Promise<string[]> {
  const files: string[] = [];
  
  async function scan(currentDir: string) {
    const entries = await readdir(currentDir, { withFileTypes: true });
    
    for (const entry of entries) {
      const fullPath = join(currentDir, entry.name);
      
      // Skip common non-source directories
      if (entry.isDirectory()) {
        if (['node_modules', 'target', '.git', 'dist', 'build'].includes(entry.name)) {
          continue;
        }
        await scan(fullPath);
      } else if (entry.name.endsWith('.rs')) {
        files.push(fullPath);
      }
    }
  }
  
  await scan(dir);
  return files;
}

/**
 * Find IDL files
 */
async function findIdlFiles(dir: string): Promise<string[]> {
  const files: string[] = [];
  
  async function scan(currentDir: string) {
    const entries = await readdir(currentDir, { withFileTypes: true });
    
    for (const entry of entries) {
      const fullPath = join(currentDir, entry.name);
      
      if (entry.isDirectory()) {
        if (['node_modules', 'target', '.git'].includes(entry.name)) continue;
        await scan(fullPath);
      } else if (entry.name.endsWith('.json') && 
                 (entry.name.includes('idl') || currentDir.includes('idl'))) {
        files.push(fullPath);
      }
    }
  }
  
  await scan(dir);
  return files;
}

/**
 * Audit a GitHub repository
 */
export async function auditGithub(
  repoInput: string,
  options: GithubAuditOptions = {}
): Promise<GithubAuditResult> {
  const startTime = Date.now();
  
  const parsed = parseGithubUrl(repoInput);
  if (!parsed) {
    throw new Error(`Invalid GitHub repository: ${repoInput}`);
  }
  
  const { owner, repo } = parsed;
  let tempDir: string | null = null;
  
  try {
    // Clone the repository
    if (options.verbose) {
      console.log(`Cloning ${owner}/${repo}...`);
    }
    
    tempDir = await cloneRepo(owner, repo, {
      pr: options.pr,
      branch: options.branch,
    });
    
    // Find all source files
    const rustFiles = await findRustFiles(tempDir);
    const idlFiles = await findIdlFiles(tempDir);
    
    if (options.verbose) {
      console.log(`Found ${rustFiles.length} Rust files, ${idlFiles.length} IDL files`);
    }
    
    // Parse IDLs
    const idls = await Promise.all(
      idlFiles.map(async (f) => {
        try {
          const content = await readFile(f, 'utf-8');
          return { path: f.replace(tempDir! + '/', ''), idl: await parseIdl(content) };
        } catch {
          return null;
        }
      })
    );
    
    // Parse all Rust files together
    const allFindings: Finding[] = [];
    
    try {
      const parsedRust = await parseRustFiles(rustFiles);
      
      // Run patterns on each file
      for (const file of parsedRust.files) {
        const relativePath = file.path.replace(tempDir + '\\', '').replace(tempDir + '/', '');
        
        const findings = await runPatterns({
          path: relativePath,
          rust: {
            files: [file],
            functions: parsedRust.functions.filter(f => f.file === file.path),
            structs: parsedRust.structs.filter(s => s.file === file.path),
            implBlocks: parsedRust.implBlocks.filter(i => i.file === file.path),
            content: file.content,
          },
          idl: idls[0]?.idl || null,
        });
        
        allFindings.push(...findings);
      }
    } catch (error) {
      if (options.verbose) {
        console.warn(`Failed to audit: ${error}`);
      }
    }
    
    const duration = Date.now() - startTime;
    
    return {
      repo: `${owner}/${repo}`,
      ref: options.pr ? `PR #${options.pr}` : options.branch || 'main',
      files: rustFiles.length,
      findings: allFindings,
      duration,
    };
    
  } finally {
    // Clean up temp directory
    if (tempDir) {
      try {
        await rm(tempDir, { recursive: true, force: true });
      } catch {
        // Ignore cleanup errors
      }
    }
  }
}

/**
 * Format audit results for output
 */
export function formatGithubAuditResult(
  result: GithubAuditResult,
  format: 'json' | 'text' | 'markdown' = 'text'
): string {
  if (format === 'json') {
    return JSON.stringify(result, null, 2);
  }
  
  if (format === 'markdown') {
    const lines = [
      `# SolShield AI Audit: ${result.repo}`,
      '',
      `**Ref:** ${result.ref}`,
      `**Files Scanned:** ${result.files}`,
      `**Duration:** ${result.duration}ms`,
      '',
      `## Findings (${result.findings.length})`,
      '',
    ];
    
    if (result.findings.length === 0) {
      lines.push('✅ No vulnerabilities detected!');
    } else {
      // Group by severity
      const bySeverity = new Map<string, Finding[]>();
      for (const f of result.findings) {
        if (!bySeverity.has(f.severity)) {
          bySeverity.set(f.severity, []);
        }
        bySeverity.get(f.severity)!.push(f);
      }
      
      const severityEmoji: Record<string, string> = {
        critical: '🔴',
        high: '🟠',
        medium: '🟡',
        low: '🔵',
        info: '⚪',
      };
      
      for (const [severity, findings] of bySeverity) {
        lines.push(`### ${severityEmoji[severity] || ''} ${severity.toUpperCase()} (${findings.length})`);
        lines.push('');
        
        for (const f of findings) {
          lines.push(`- **[${f.pattern}] ${f.title}**`);
          lines.push(`  - Location: \`${f.location}\``);
          lines.push(`  - ${f.description}`);
          lines.push('');
        }
      }
    }
    
    return lines.join('\n');
  }
  
  // Text format
  const lines = [
    `SolShield AI Audit: ${result.repo} (${result.ref})`,
    `Files: ${result.files} | Duration: ${result.duration}ms`,
    '',
  ];
  
  if (result.findings.length === 0) {
    lines.push('✓ No vulnerabilities detected');
  } else {
    lines.push(`Found ${result.findings.length} issue(s):`);
    lines.push('');
    
    for (const f of result.findings) {
      const emoji = { critical: '🔴', high: '🟠', medium: '🟡', low: '🔵', info: '⚪' }[f.severity] || '';
      lines.push(`${emoji} [${f.pattern}] ${f.title}`);
      lines.push(`   ${f.location}`);
      lines.push(`   ${f.description}`);
      lines.push('');
    }
  }
  
  return lines.join('\n');
}
