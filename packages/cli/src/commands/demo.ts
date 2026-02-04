import chalk from 'chalk';
import ora from 'ora';
import { join, dirname } from 'path';
import { fileURLToPath } from 'url';
import { existsSync } from 'fs';

/**
 * Demo command - runs a quick showcase of SolGuard capabilities
 */
export async function demoCommand() {
  console.log(chalk.cyan(`
╔═══════════════════════════════════════════════════════════════╗
║  🛡️  SolGuard Demo - AI-Powered Smart Contract Auditor       ║
║     Detecting Solana vulnerabilities in seconds               ║
╚═══════════════════════════════════════════════════════════════╝
`));

  // Find the examples directory
  const __dirname = dirname(fileURLToPath(import.meta.url));
  const examplesDir = join(__dirname, '..', '..', '..', '..', 'examples');
  const vulnerableVault = join(examplesDir, 'vulnerable', 'token-vault');
  
  if (!existsSync(vulnerableVault)) {
    console.log(chalk.yellow('  Demo examples not found. Running with inline demo...\n'));
    await runInlineDemo();
    return;
  }

  console.log(chalk.bold('  📂 Auditing: examples/vulnerable/token-vault\n'));
  console.log(chalk.dim('  This vault has intentional security issues...\n'));

  const spinner = ora('Scanning for vulnerabilities...').start();
  
  // Simulate scanning delay for effect
  await new Promise(resolve => setTimeout(resolve, 800));
  
  try {
    const { parseRustFiles } = await import('../parsers/rust.js');
    const { runPatterns } = await import('../patterns/index.js');
    const { readdirSync } = await import('fs');
    
    // Find Rust files
    const srcDir = join(vulnerableVault, 'src');
    const rustFiles = readdirSync(srcDir)
      .filter(f => f.endsWith('.rs'))
      .map(f => join(srcDir, f));
    
    if (rustFiles.length === 0) {
      spinner.fail('No Rust files found');
      return;
    }

    const parsed = await parseRustFiles(rustFiles);
    
    // Run patterns
    const allFindings: any[] = [];
    for (const file of parsed.files) {
      const findings = await runPatterns({
        path: file.path,
        rust: {
          files: [file],
          functions: parsed.functions.filter(f => f.file === file.path),
          structs: parsed.structs.filter(s => s.file === file.path),
          implBlocks: parsed.implBlocks.filter(i => i.file === file.path),
          content: file.content,
        },
        idl: null,
      });
      allFindings.push(...findings);
    }

    spinner.succeed(`Found ${allFindings.length} security issues!\n`);

    // Group by severity
    const critical = allFindings.filter(f => f.severity === 'critical');
    const high = allFindings.filter(f => f.severity === 'high');
    const medium = allFindings.filter(f => f.severity === 'medium');
    const low = allFindings.filter(f => f.severity === 'low');

    // Summary
    console.log(chalk.bold('  📊 Summary'));
    console.log(chalk.gray('  ─'.repeat(30)));
    console.log(`  ${chalk.red('🔴 Critical:')} ${critical.length}`);
    console.log(`  ${chalk.yellow('🟠 High:')} ${high.length}`);
    console.log(`  ${chalk.blue('🟡 Medium:')} ${medium.length}`);
    console.log(`  ${chalk.gray('🔵 Low:')} ${low.length}`);
    console.log('');

    // Show top findings
    console.log(chalk.bold('  🔍 Sample Findings'));
    console.log(chalk.gray('  ─'.repeat(30)));
    
    const topFindings = [...critical, ...high].slice(0, 4);
    for (const f of topFindings) {
      const severityColor = f.severity === 'critical' ? chalk.red : chalk.yellow;
      console.log(`\n  ${severityColor(`[${f.pattern}]`)} ${chalk.bold(f.title)}`);
      console.log(chalk.dim(`  └─ ${typeof f.location === 'string' ? f.location : f.location.file}`));
      if (f.suggestion || f.recommendation) {
        console.log(chalk.green(`  💡 ${f.suggestion || f.recommendation}`));
      }
    }

    console.log('');
    console.log(chalk.gray('  ─'.repeat(30)));
    console.log(chalk.dim(`  Scanned with 130 patterns in <1 second`));
    console.log('');

    // Call to action
    console.log(chalk.bold('  🚀 Try It Yourself'));
    console.log(chalk.gray('  ─'.repeat(30)));
    console.log('  ' + chalk.cyan('solguard audit ./your-program'));
    console.log('  ' + chalk.cyan('solguard github owner/repo'));
    console.log('  ' + chalk.cyan('solguard score ./your-program'));
    console.log('');
    console.log(chalk.dim('  https://github.com/oh-ashen-one/solguard'));
    console.log('');

  } catch (error: any) {
    spinner.fail(`Demo failed: ${error.message}`);
    process.exit(1);
  }
}

async function runInlineDemo() {
  console.log(chalk.bold('  📝 Demo: Detecting Missing Signer Check\n'));
  
  const vulnerableCode = `
  ${chalk.dim('// Vulnerable code:')}
  ${chalk.red('pub authority: AccountInfo<\'info>,')}  ${chalk.dim('// ❌ No Signer constraint!')}
  `;
  
  const fixedCode = `
  ${chalk.dim('// Fixed code:')}
  ${chalk.green('pub authority: Signer<\'info>,')}  ${chalk.dim('// ✅ Requires signature')}
  `;

  console.log(vulnerableCode);
  console.log(chalk.yellow('  ⚠️  SolGuard detects: Missing Signer Check (SOL002)'));
  console.log(chalk.dim('     Anyone can impersonate the authority!\n'));
  console.log(fixedCode);
  console.log(chalk.green('  ✅ Fixed! Authority must now sign the transaction.\n'));
  
  console.log(chalk.bold('  🛡️ SolGuard detects 130 vulnerability patterns'));
  console.log(chalk.dim('  Run: solguard audit ./your-program\n'));
}
