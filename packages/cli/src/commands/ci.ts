/**
 * CI Mode for GitHub Actions / GitLab CI / etc.
 * 
 * Outputs structured results suitable for CI environments:
 * - GitHub Actions annotations
 * - Exit codes based on findings
 * - Summary statistics
 */

import { readFileSync, existsSync, readdirSync, statSync, writeFileSync } from 'fs';
import { join } from 'path';
import { parseIdl } from '../parsers/idl.js';
import { parseRustFiles } from '../parsers/rust.js';
import { runPatterns, listPatterns } from '../patterns/index.js';
import type { Finding } from './audit.js';

interface CiOptions {
  failOn?: 'critical' | 'high' | 'medium' | 'low' | 'any';
  sarif?: string;
  summary?: string;
}

interface SarifResult {
  ruleId: string;
  level: 'error' | 'warning' | 'note';
  message: { text: string };
  locations: Array<{
    physicalLocation: {
      artifactLocation: { uri: string };
      region?: { startLine: number };
    };
  }>;
}

/**
 * Run audit in CI mode
 */
export async function ciCommand(path: string, options: CiOptions) {
  const startTime = Date.now();
  
  if (!existsSync(path)) {
    console.error(`::error::Path not found: ${path}`);
    process.exit(1);
  }

  // Find Rust files
  const isDirectory = statSync(path).isDirectory();
  let rustFiles: string[] = [];
  let idlPath: string | null = null;

  if (isDirectory) {
    rustFiles = findRustFilesRecursive(path);
    
    // Look for IDL
    const idlDir = join(path, 'target', 'idl');
    if (existsSync(idlDir)) {
      const idlFiles = readdirSync(idlDir).filter(f => f.endsWith('.json'));
      if (idlFiles.length > 0) {
        idlPath = join(idlDir, idlFiles[0]);
      }
    }
  } else if (path.endsWith('.rs')) {
    rustFiles = [path];
  }

  if (rustFiles.length === 0) {
    console.log('::warning::No Rust files found to audit');
    process.exit(0);
  }

  // Parse IDL if available
  let idl = null;
  if (idlPath) {
    try {
      idl = await parseIdl(idlPath);
    } catch {
      console.log('::warning::Failed to parse IDL');
    }
  }

  // Parse Rust files
  const parsedRust = await parseRustFiles(rustFiles);
  
  // Run all patterns
  const allFindings: Finding[] = [];
  
  for (const file of parsedRust.files) {
    const findings = await runPatterns({
      path: file.path,
      rust: {
        files: [file],
        functions: parsedRust.functions.filter(f => f.file === file.path),
        structs: parsedRust.structs.filter(s => s.file === file.path),
        implBlocks: parsedRust.implBlocks.filter(i => i.file === file.path),
        content: file.content,
      },
      idl,
    });
    
    allFindings.push(...findings);
  }

  const duration = Date.now() - startTime;

  // Output GitHub Actions annotations
  for (const finding of allFindings) {
    const level = finding.severity === 'critical' || finding.severity === 'high' 
      ? 'error' 
      : finding.severity === 'medium' 
        ? 'warning' 
        : 'notice';
    
    const location = typeof finding.location === 'string' 
      ? finding.location 
      : `${finding.location.file}:${finding.location.line || 1}`;
    
    const [file, line] = location.split(':');
    console.log(`::${level} file=${file},line=${line || 1},title=[${finding.pattern}] ${finding.title}::${finding.description}`);
  }

  // Count by severity
  const counts = {
    critical: allFindings.filter(f => f.severity === 'critical').length,
    high: allFindings.filter(f => f.severity === 'high').length,
    medium: allFindings.filter(f => f.severity === 'medium').length,
    low: allFindings.filter(f => f.severity === 'low').length,
    info: allFindings.filter(f => f.severity === 'info').length,
  };

  // Write job summary if GITHUB_STEP_SUMMARY is set
  const summaryPath = process.env.GITHUB_STEP_SUMMARY || options.summary;
  if (summaryPath) {
    const summaryLines = [
      '## 🛡️ SolShield AI Security Audit',
      '',
      `| Severity | Count |`,
      `|----------|-------|`,
      `| 🔴 Critical | ${counts.critical} |`,
      `| 🟠 High | ${counts.high} |`,
      `| 🟡 Medium | ${counts.medium} |`,
      `| 🔵 Low | ${counts.low} |`,
      `| ⚪ Info | ${counts.info} |`,
      '',
      `**Files scanned:** ${rustFiles.length}`,
      `**Duration:** ${duration}ms`,
      `**Patterns:** ${listPatterns().length}`,
      '',
    ];

    if (allFindings.length > 0) {
      summaryLines.push('### Findings');
      summaryLines.push('');
      
      for (const f of allFindings.slice(0, 20)) {
        const emoji = { critical: '🔴', high: '🟠', medium: '🟡', low: '🔵', info: '⚪' }[f.severity] || '';
        summaryLines.push(`- ${emoji} **[${f.pattern}]** ${f.title}`);
        summaryLines.push(`  - ${f.description}`);
      }
      
      if (allFindings.length > 20) {
        summaryLines.push(`- ... and ${allFindings.length - 20} more`);
      }
    } else {
      summaryLines.push('✅ **No vulnerabilities detected!**');
    }

    writeFileSync(summaryPath, summaryLines.join('\n'), { flag: 'a' });
  }

  // Generate SARIF if requested
  if (options.sarif) {
    const sarif = generateSarif(allFindings, path);
    writeFileSync(options.sarif, JSON.stringify(sarif, null, 2));
    console.log(`::notice::SARIF report written to ${options.sarif}`);
  }

  // Print summary
  console.log('\n--- SolShield AI CI Summary ---');
  console.log(`Files: ${rustFiles.length} | Findings: ${allFindings.length} | Duration: ${duration}ms`);
  console.log(`Critical: ${counts.critical} | High: ${counts.high} | Medium: ${counts.medium} | Low: ${counts.low}`);

  // Determine exit code
  const failOn = options.failOn || 'critical';
  let shouldFail = false;
  
  switch (failOn) {
    case 'any':
      shouldFail = allFindings.length > 0;
      break;
    case 'low':
      shouldFail = counts.critical + counts.high + counts.medium + counts.low > 0;
      break;
    case 'medium':
      shouldFail = counts.critical + counts.high + counts.medium > 0;
      break;
    case 'high':
      shouldFail = counts.critical + counts.high > 0;
      break;
    case 'critical':
    default:
      shouldFail = counts.critical > 0;
      break;
  }

  if (shouldFail) {
    console.log(`\n::error::Audit failed: found ${failOn} or higher severity issues`);
    process.exit(1);
  }

  console.log('\n✓ Audit passed');
  process.exit(0);
}

/**
 * Generate SARIF format output for GitHub Code Scanning
 */
function generateSarif(findings: Finding[], basePath: string): object {
  const rules = listPatterns().map(p => ({
    id: p.id,
    name: p.name,
    shortDescription: { text: p.name },
    defaultConfiguration: {
      level: p.severity === 'critical' || p.severity === 'high' ? 'error' : 
             p.severity === 'medium' ? 'warning' : 'note',
    },
  }));

  const results: SarifResult[] = findings.map(f => {
    const location = typeof f.location === 'string' ? f.location : f.location.file;
    const [file, lineStr] = location.split(':');
    const line = parseInt(lineStr) || 1;

    return {
      ruleId: f.pattern,
      level: f.severity === 'critical' || f.severity === 'high' ? 'error' as const : 
             f.severity === 'medium' ? 'warning' as const : 'note' as const,
      message: { text: `${f.title}: ${f.description}` },
      locations: [{
        physicalLocation: {
          artifactLocation: { uri: file },
          region: { startLine: line },
        },
      }],
    };
  });

  return {
    $schema: 'https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json',
    version: '2.1.0',
    runs: [{
      tool: {
        driver: {
          name: 'SolShield AI',
          version: '0.1.0',
          informationUri: 'https://github.com/oh-ashen-one/solshield',
          rules,
        },
      },
      results,
    }],
  };
}

/**
 * Recursively find Rust files
 */
function findRustFilesRecursive(dir: string): string[] {
  const files: string[] = [];
  
  function scan(currentDir: string) {
    const entries = readdirSync(currentDir, { withFileTypes: true });
    
    for (const entry of entries) {
      const fullPath = join(currentDir, entry.name);
      
      if (entry.isDirectory()) {
        if (!['node_modules', 'target', '.git', 'dist', 'build'].includes(entry.name)) {
          scan(fullPath);
        }
      } else if (entry.name.endsWith('.rs')) {
        files.push(fullPath);
      }
    }
  }
  
  scan(dir);
  return files;
}
