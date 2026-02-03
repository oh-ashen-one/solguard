import chalk from 'chalk';
import ora from 'ora';
import { writeFileSync } from 'fs';
import { join } from 'path';
import { auditCommand, type AuditResult } from './audit.js';
import { 
  generateCertificateMetadata, 
  generateCertificateSvg, 
  calculateSeverityScore 
} from '../certificate/metadata.js';

interface CertificateOptions {
  output?: string;
  programId?: string;
}

/**
 * Generate a certificate for an audit
 */
export async function certificateCommand(path: string, options: CertificateOptions) {
  const spinner = ora('Running audit...').start();

  try {
    // Run the audit
    let result: AuditResult;
    
    // Capture audit output
    const originalLog = console.log;
    let jsonOutput = '';
    console.log = (msg: string) => {
      jsonOutput += msg;
    };

    try {
      // Import and run audit internally
      const { parseRustFiles } = await import('../parsers/rust.js');
      const { runPatterns } = await import('../patterns/index.js');
      const { existsSync, statSync, readdirSync } = await import('fs');
      
      if (!existsSync(path)) {
        throw new Error(`Path not found: ${path}`);
      }

      const isDirectory = statSync(path).isDirectory();
      let rustFiles: string[] = [];

      if (isDirectory) {
        const findRustFiles = (dir: string): string[] => {
          const files: string[] = [];
          const entries = readdirSync(dir, { withFileTypes: true });
          for (const entry of entries) {
            const fullPath = join(dir, entry.name);
            if (entry.isDirectory() && !entry.name.startsWith('.') && entry.name !== 'target') {
              files.push(...findRustFiles(fullPath));
            } else if (entry.name.endsWith('.rs')) {
              files.push(fullPath);
            }
          }
          return files;
        };
        
        const srcDir = join(path, 'src');
        const programsDir = join(path, 'programs');
        
        if (existsSync(programsDir)) {
          rustFiles = findRustFiles(programsDir);
        } else if (existsSync(srcDir)) {
          rustFiles = findRustFiles(srcDir);
        } else {
          rustFiles = findRustFiles(path);
        }
      } else if (path.endsWith('.rs')) {
        rustFiles = [path];
      }

      if (rustFiles.length === 0) {
        throw new Error('No Rust files found');
      }

      spinner.text = 'Analyzing code...';
      const rust = await parseRustFiles(rustFiles);
      const findings = await runPatterns({ idl: null, rust, path });

      result = {
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

    } finally {
      console.log = originalLog;
    }

    // Generate certificate
    spinner.text = 'Generating certificate...';
    
    const programId = options.programId || 'Unknown';
    const severityScore = calculateSeverityScore(result);
    const metadata = generateCertificateMetadata(result, programId);
    const svg = generateCertificateSvg(programId, result.passed, result.summary, result.timestamp);

    // Output files
    const outputDir = options.output || '.';
    const metadataPath = join(outputDir, 'certificate-metadata.json');
    const svgPath = join(outputDir, 'certificate.svg');

    writeFileSync(metadataPath, JSON.stringify(metadata, null, 2));
    writeFileSync(svgPath, svg);

    spinner.succeed('Certificate generated!');

    // Display summary
    console.log('');
    console.log(chalk.bold('  Certificate Summary'));
    console.log(chalk.gray('  ─'.repeat(25)));
    console.log('');
    console.log(`  Status: ${result.passed ? chalk.green('✅ PASSED') : chalk.red('❌ FAILED')}`);
    console.log(`  Severity Score: ${chalk.yellow(severityScore + '/100')} ${severityScore === 0 ? '(Perfect!)' : ''}`);
    console.log('');
    console.log(`  Findings:`);
    console.log(`    ${chalk.red('Critical:')} ${result.summary.critical}`);
    console.log(`    ${chalk.yellow('High:')} ${result.summary.high}`);
    console.log(`    ${chalk.blue('Medium:')} ${result.summary.medium}`);
    console.log(`    ${chalk.gray('Low:')} ${result.summary.low}`);
    console.log('');
    console.log(chalk.gray(`  Metadata: ${metadataPath}`));
    console.log(chalk.gray(`  SVG: ${svgPath}`));
    console.log('');

    if (result.passed) {
      console.log(chalk.green('  🎉 This program is ready for NFT certificate minting!'));
    } else {
      console.log(chalk.yellow('  ⚠️  Fix the issues above before minting a certificate.'));
    }
    console.log('');

  } catch (error: any) {
    spinner.fail(`Certificate generation failed: ${error.message}`);
    process.exit(1);
  }
}
