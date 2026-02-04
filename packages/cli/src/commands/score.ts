import chalk from 'chalk';
import ora from 'ora';
import { existsSync, statSync, readdirSync } from 'fs';
import { join } from 'path';

interface ScoreOptions {
  output?: string;
}

interface ScoreResult {
  grade: string;
  score: number;
  breakdown: {
    critical: number;
    high: number;
    medium: number;
    low: number;
    info: number;
  };
  deductions: string[];
  recommendations: string[];
}

/**
 * Calculate a security grade (A-F) for a Solana program
 */
export async function scoreCommand(path: string, options: ScoreOptions) {
  const spinner = ora('Analyzing security posture...').start();

  try {
    // Parse and audit
    const { parseRustFiles } = await import('../parsers/rust.js');
    const { runPatterns } = await import('../patterns/index.js');

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
          if (entry.isDirectory() && !entry.name.startsWith('.') && entry.name !== 'target' && entry.name !== 'node_modules') {
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

    spinner.text = 'Scanning for vulnerabilities...';
    const rust = await parseRustFiles(rustFiles);
    const findings = await runPatterns({ idl: null, rust, path });

    // Calculate breakdown
    const breakdown = {
      critical: findings.filter(f => f.severity === 'critical').length,
      high: findings.filter(f => f.severity === 'high').length,
      medium: findings.filter(f => f.severity === 'medium').length,
      low: findings.filter(f => f.severity === 'low').length,
      info: findings.filter(f => f.severity === 'info').length,
    };

    // Calculate score (100 base, deductions per finding)
    let score = 100;
    const deductions: string[] = [];
    
    // Critical: -25 each (max 100)
    if (breakdown.critical > 0) {
      const penalty = Math.min(breakdown.critical * 25, 100);
      score -= penalty;
      deductions.push(`-${penalty} points: ${breakdown.critical} critical issue(s)`);
    }
    
    // High: -10 each (max 40)
    if (breakdown.high > 0) {
      const penalty = Math.min(breakdown.high * 10, 40);
      score -= penalty;
      deductions.push(`-${penalty} points: ${breakdown.high} high severity issue(s)`);
    }
    
    // Medium: -3 each (max 15)
    if (breakdown.medium > 0) {
      const penalty = Math.min(breakdown.medium * 3, 15);
      score -= penalty;
      deductions.push(`-${penalty} points: ${breakdown.medium} medium issue(s)`);
    }
    
    // Low: -1 each (max 5)
    if (breakdown.low > 0) {
      const penalty = Math.min(breakdown.low * 1, 5);
      score -= penalty;
      deductions.push(`-${penalty} points: ${breakdown.low} low issue(s)`);
    }

    // Ensure score doesn't go below 0
    score = Math.max(0, score);

    // Calculate grade
    let grade: string;
    let gradeColor: (s: string) => string;
    let gradeEmoji: string;
    
    if (score >= 95) {
      grade = 'A+';
      gradeColor = chalk.green;
      gradeEmoji = '🏆';
    } else if (score >= 90) {
      grade = 'A';
      gradeColor = chalk.green;
      gradeEmoji = '✅';
    } else if (score >= 85) {
      grade = 'A-';
      gradeColor = chalk.green;
      gradeEmoji = '✅';
    } else if (score >= 80) {
      grade = 'B+';
      gradeColor = chalk.greenBright;
      gradeEmoji = '👍';
    } else if (score >= 75) {
      grade = 'B';
      gradeColor = chalk.greenBright;
      gradeEmoji = '👍';
    } else if (score >= 70) {
      grade = 'B-';
      gradeColor = chalk.yellow;
      gradeEmoji = '⚠️';
    } else if (score >= 65) {
      grade = 'C+';
      gradeColor = chalk.yellow;
      gradeEmoji = '⚠️';
    } else if (score >= 60) {
      grade = 'C';
      gradeColor = chalk.yellow;
      gradeEmoji = '⚠️';
    } else if (score >= 55) {
      grade = 'C-';
      gradeColor = chalk.yellowBright;
      gradeEmoji = '⚠️';
    } else if (score >= 50) {
      grade = 'D+';
      gradeColor = chalk.redBright;
      gradeEmoji = '❌';
    } else if (score >= 40) {
      grade = 'D';
      gradeColor = chalk.redBright;
      gradeEmoji = '❌';
    } else if (score >= 30) {
      grade = 'D-';
      gradeColor = chalk.red;
      gradeEmoji = '🚨';
    } else {
      grade = 'F';
      gradeColor = chalk.red;
      gradeEmoji = '💀';
    }

    // Generate recommendations
    const recommendations: string[] = [];
    
    if (breakdown.critical > 0) {
      recommendations.push('🚨 URGENT: Fix all critical issues before deployment');
      recommendations.push('   Critical vulnerabilities can result in complete loss of funds');
    }
    
    if (breakdown.high > 0) {
      recommendations.push('⚠️  Address high severity issues as priority');
    }
    
    if (breakdown.medium > 0) {
      recommendations.push('📋 Review and fix medium issues during development');
    }
    
    if (score >= 90 && breakdown.low + breakdown.info > 0) {
      recommendations.push('💡 Consider addressing remaining low/info items for a perfect score');
    }
    
    if (score === 100) {
      recommendations.push('🎉 Perfect score! Ready for production with appropriate testing');
    }

    spinner.succeed('Security analysis complete');

    // Output based on format
    if (options.output === 'json') {
      console.log(JSON.stringify({
        grade,
        score,
        breakdown,
        deductions,
        recommendations,
        filesScanned: rustFiles.length,
        totalFindings: findings.length,
      }, null, 2));
      return;
    }

    // Terminal output
    console.log('');
    console.log(chalk.bold('  🛡️  SolShield AI Security Score'));
    console.log(chalk.gray('  ─'.repeat(25)));
    console.log('');
    
    // Big grade display
    console.log(gradeColor(`
    ╔═══════════════════════════════════╗
    ║                                   ║
    ║       ${gradeEmoji}  GRADE: ${grade.padEnd(2)}              ║
    ║          SCORE: ${String(score).padStart(3)}/100           ║
    ║                                   ║
    ╚═══════════════════════════════════╝
`));

    // Breakdown
    console.log(chalk.bold('  📊 Finding Breakdown'));
    console.log('');
    console.log(`    ${chalk.red('●')} Critical:  ${breakdown.critical}`);
    console.log(`    ${chalk.yellow('●')} High:      ${breakdown.high}`);
    console.log(`    ${chalk.blue('●')} Medium:    ${breakdown.medium}`);
    console.log(`    ${chalk.gray('●')} Low:       ${breakdown.low}`);
    console.log(`    ${chalk.dim('●')} Info:      ${breakdown.info}`);
    console.log('');

    // Deductions
    if (deductions.length > 0) {
      console.log(chalk.bold('  📉 Score Deductions'));
      console.log('');
      for (const d of deductions) {
        console.log(chalk.dim(`    ${d}`));
      }
      console.log('');
    }

    // Recommendations
    if (recommendations.length > 0) {
      console.log(chalk.bold('  💡 Recommendations'));
      console.log('');
      for (const r of recommendations) {
        console.log(`    ${r}`);
      }
      console.log('');
    }

    // Files scanned
    console.log(chalk.gray(`  Files scanned: ${rustFiles.length}`));
    console.log(chalk.gray(`  Total findings: ${findings.length}`));
    console.log('');

    // Exit code based on grade
    if (grade.startsWith('F') || grade.startsWith('D')) {
      process.exit(1);
    }

  } catch (error: any) {
    spinner.fail(`Analysis failed: ${error.message}`);
    process.exit(1);
  }
}
