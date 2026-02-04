import chalk from 'chalk';
import { watch } from 'fs';
import { join, relative } from 'path';
import { readdirSync, statSync, existsSync } from 'fs';
import { auditCommand } from './audit.js';

interface WatchOptions {
  output?: 'terminal' | 'json' | 'markdown';
  ai?: boolean;
}

/**
 * Watch a directory for changes and auto-audit
 */
export async function watchCommand(path: string, options: WatchOptions) {
  console.log(chalk.cyan('\n  🔍 SolShield AI Watch Mode\n'));
  console.log(chalk.gray(`  Watching: ${path}`));
  console.log(chalk.gray('  Press Ctrl+C to stop\n'));

  // Validate path
  if (!existsSync(path)) {
    console.error(chalk.red(`  Error: Path not found: ${path}`));
    process.exit(1);
  }

  // Find all directories to watch
  const dirsToWatch = new Set<string>();
  
  function findDirs(dir: string) {
    dirsToWatch.add(dir);
    try {
      const entries = readdirSync(dir, { withFileTypes: true });
      for (const entry of entries) {
        if (entry.isDirectory() && !entry.name.startsWith('.') && entry.name !== 'target' && entry.name !== 'node_modules') {
          findDirs(join(dir, entry.name));
        }
      }
    } catch {}
  }

  if (statSync(path).isDirectory()) {
    findDirs(path);
  } else {
    dirsToWatch.add(path);
  }

  // Debounce to avoid multiple audits for rapid changes
  let debounceTimer: NodeJS.Timeout | null = null;
  let lastAuditTime = 0;
  const DEBOUNCE_MS = 1000;

  async function runAudit() {
    const now = Date.now();
    if (now - lastAuditTime < DEBOUNCE_MS) {
      return;
    }
    lastAuditTime = now;

    console.log(chalk.yellow('\n  ─'.repeat(30)));
    console.log(chalk.yellow(`  🔄 Re-auditing at ${new Date().toLocaleTimeString()}`));
    console.log(chalk.yellow('  ─'.repeat(30)));

    try {
      await auditCommand(path, {
        output: options.output || 'terminal',
        ai: options.ai !== false,
        verbose: false,
      });
    } catch (error) {
      // Audit command handles its own errors
    }
  }

  // Initial audit
  console.log(chalk.green('  Running initial audit...\n'));
  await runAudit();

  // Watch for changes
  for (const dir of dirsToWatch) {
    try {
      watch(dir, { recursive: false }, (eventType, filename) => {
        if (!filename) return;
        if (!filename.endsWith('.rs')) return;
        if (filename.startsWith('.')) return;

        console.log(chalk.blue(`\n  📝 Changed: ${relative(path, join(dir, filename))}`));

        // Debounce
        if (debounceTimer) {
          clearTimeout(debounceTimer);
        }
        debounceTimer = setTimeout(runAudit, 500);
      });
    } catch (error) {
      // Ignore watch errors on individual directories
    }
  }

  // Keep process alive
  process.on('SIGINT', () => {
    console.log(chalk.gray('\n\n  👋 Watch mode stopped\n'));
    process.exit(0);
  });

  // Prevent exit
  await new Promise(() => {});
}
