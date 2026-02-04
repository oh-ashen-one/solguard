import chalk from 'chalk';
import ora from 'ora';
import { existsSync, statSync, readdirSync, writeFileSync } from 'fs';
import { join } from 'path';

interface BadgeOptions {
  output?: string;
  format?: string;
  style?: string;
}

/**
 * Generate a shields.io-compatible badge for README
 */
export async function badgeCommand(path: string, options: BadgeOptions) {
  const spinner = ora('Generating security badge...').start();

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

    const rust = await parseRustFiles(rustFiles);
    const findings = await runPatterns({ idl: null, rust, path });

    // Calculate stats
    const critical = findings.filter(f => f.severity === 'critical').length;
    const high = findings.filter(f => f.severity === 'high').length;
    const medium = findings.filter(f => f.severity === 'medium').length;
    const low = findings.filter(f => f.severity === 'low').length;

    // Determine badge status
    let status: string;
    let color: string;
    
    if (critical > 0) {
      status = 'critical';
      color = 'red';
    } else if (high > 0) {
      status = 'issues';
      color = 'orange';
    } else if (medium > 0) {
      status = 'warnings';
      color = 'yellow';
    } else if (low > 0) {
      status = 'minor';
      color = 'yellowgreen';
    } else {
      status = 'secure';
      color = 'brightgreen';
    }

    // Calculate score
    let score = 100;
    score -= Math.min(critical * 25, 100);
    score -= Math.min(high * 10, 40);
    score -= Math.min(medium * 3, 15);
    score -= Math.min(low * 1, 5);
    score = Math.max(0, score);

    // Determine grade
    let grade: string;
    if (score >= 95) grade = 'A+';
    else if (score >= 90) grade = 'A';
    else if (score >= 85) grade = 'A-';
    else if (score >= 80) grade = 'B+';
    else if (score >= 75) grade = 'B';
    else if (score >= 70) grade = 'B-';
    else if (score >= 65) grade = 'C+';
    else if (score >= 60) grade = 'C';
    else if (score >= 55) grade = 'C-';
    else if (score >= 50) grade = 'D+';
    else if (score >= 40) grade = 'D';
    else if (score >= 30) grade = 'D-';
    else grade = 'F';

    const style = options.style || 'flat';
    
    spinner.succeed('Badge generated!');

    // Generate badge URLs and markdown
    const statusBadge = `https://img.shields.io/badge/SolShield AI-${status}-${color}?style=${style}&logo=data:image/svg+xml;base64,PHN2ZyB4bWxucz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC9zdmciIHZpZXdCb3g9IjAgMCAyNCAyNCI+PHBhdGggZmlsbD0iI2ZmZiIgZD0iTTEyIDFMMiA1djZjMCA1LjU1IDQuMjMgMTAuNzQgMTAgMTIgNS43Ny0xLjI2IDEwLTYuNDUgMTAtMTJWNUwxMiAxem0wIDEwLjk5aC04QzQuNTcgMTMuMiA4LjI4IDE1LjE1IDEyIDE2Ljg0VjEyem0wLTEuOTlWNGw3IDMuMTdWMTFoLTd6Ii8+PC9zdmc+`;
    
    const gradeBadge = `https://img.shields.io/badge/Security%20Grade-${grade}-${color}?style=${style}`;
    const scoreBadge = `https://img.shields.io/badge/Security%20Score-${score}%2F100-${color}?style=${style}`;

    // Output format
    if (options.format === 'json') {
      console.log(JSON.stringify({
        status,
        grade,
        score,
        color,
        badges: {
          status: statusBadge,
          grade: gradeBadge,
          score: scoreBadge,
        },
        markdown: {
          status: `[![SolShield AI](${statusBadge})](https://github.com/oh-ashen-one/solshield)`,
          grade: `[![Security Grade](${gradeBadge})](https://github.com/oh-ashen-one/solshield)`,
          score: `[![Security Score](${scoreBadge})](https://github.com/oh-ashen-one/solshield)`,
        },
        findings: {
          critical,
          high,
          medium,
          low,
        }
      }, null, 2));
      return;
    }

    // Terminal output
    console.log('');
    console.log(chalk.bold('  🏷️  SolShield AI Badges'));
    console.log(chalk.gray('  ─'.repeat(25)));
    console.log('');
    console.log(chalk.bold('  Status Badge:'));
    console.log(chalk.cyan(`  [![SolShield AI](${statusBadge})](https://github.com/oh-ashen-one/solshield)`));
    console.log('');
    console.log(chalk.bold('  Grade Badge:'));
    console.log(chalk.cyan(`  [![Security Grade](${gradeBadge})](https://github.com/oh-ashen-one/solshield)`));
    console.log('');
    console.log(chalk.bold('  Score Badge:'));
    console.log(chalk.cyan(`  [![Security Score](${scoreBadge})](https://github.com/oh-ashen-one/solshield)`));
    console.log('');
    console.log(chalk.gray('  Copy any of the above into your README.md'));
    console.log('');
    
    // Preview
    console.log(chalk.bold('  Preview:'));
    let preview: string;
    if (status === 'secure') {
      preview = chalk.bgGreen.black(` SolShield AI: ${status} `);
    } else if (status === 'minor') {
      preview = chalk.bgYellowBright.black(` SolShield AI: ${status} `);
    } else if (status === 'warnings') {
      preview = chalk.bgYellow.black(` SolShield AI: ${status} `);
    } else if (status === 'issues') {
      preview = chalk.bgRed.white(` SolShield AI: ${status} `);
    } else {
      preview = chalk.bgRedBright.white(` SolShield AI: ${status} `);
    }
    console.log(`  ${preview}  Grade: ${grade}  Score: ${score}/100`);
    console.log('');

    // Save if output specified
    if (options.output) {
      const badgeContent = `# Security Badges

## Status Badge
[![SolShield AI](${statusBadge})](https://github.com/oh-ashen-one/solshield)

## Grade Badge  
[![Security Grade](${gradeBadge})](https://github.com/oh-ashen-one/solshield)

## Score Badge
[![Security Score](${scoreBadge})](https://github.com/oh-ashen-one/solshield)

---

**Audit Summary:**
- Critical: ${critical}
- High: ${high}
- Medium: ${medium}
- Low: ${low}
- Score: ${score}/100
- Grade: ${grade}

*Generated by SolShield AI on ${new Date().toISOString()}*
`;
      writeFileSync(options.output, badgeContent);
      console.log(chalk.green(`  ✓ Saved to ${options.output}`));
      console.log('');
    }

  } catch (error: any) {
    spinner.fail(`Badge generation failed: ${error.message}`);
    process.exit(1);
  }
}
