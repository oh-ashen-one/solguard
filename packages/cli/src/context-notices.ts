/**
 * Context-Aware Notices for SolShield Scanner
 * 
 * Adds intelligent notices based on what's being scanned:
 * 1. CPI Wrapper Detection - flags CPI interface crates
 * 2. Known Audited Protocol Detection - flags battle-tested protocols
 * 3. Severity Disclaimer - always appended to results
 */

import chalk from 'chalk';

/** Known audited Solana protocols (org/repo patterns) */
export const KNOWN_AUDITED_PROTOCOLS: { name: string; patterns: string[] }[] = [
  { name: 'Jupiter', patterns: ['jup-ag', 'jupiter-exchange', 'jupiterproject'] },
  { name: 'Kamino', patterns: ['kamino-finance', 'hubbleprotocol'] },
  { name: 'Marinade', patterns: ['marinade-finance', 'marinade'] },
  { name: 'Orca', patterns: ['orca-so'] },
  { name: 'Raydium', patterns: ['raydium-io'] },
  { name: 'Mango v4', patterns: ['blockworks-foundation', 'mango-v4'] },
  { name: 'Pyth', patterns: ['pyth-network', 'pythnet'] },
  { name: 'Metaplex', patterns: ['metaplex-foundation', 'metaplex'] },
  { name: 'Sanctum', patterns: ['sanctumfi', 'sanctum-so'] },
  { name: 'Drift', patterns: ['drift-labs'] },
  { name: 'Phoenix', patterns: ['ellipsis-labs', 'phoenix-dex'] },
  { name: 'Tensor', patterns: ['tensor-hq', 'tensor-foundation'] },
  { name: 'Jito', patterns: ['jito-foundation', 'jito-labs'] },
];

export interface ContextNotices {
  isCpiWrapper: boolean;
  auditedProtocol: string | null;
}

/**
 * Detect if code is a CPI wrapper/interface (thin wrappers around invoke/invoke_signed)
 */
export function detectCpiWrapper(code: string): boolean {
  const lines = code.split('\n');
  const totalLines = lines.length;
  
  // Count CPI-related patterns
  let cpiPatterns = 0;
  let businessLogicPatterns = 0;
  
  const cpiIndicators = [
    /\bcpi::/g,
    /\binvoke\b/g,
    /\binvoke_signed\b/g,
    /\bCpiContext\b/g,
    /\bCpiAccount\b/g,
    /pub\s+fn\s+\w+.*CpiContext/g,
    /instruction::/g,
  ];
  
  const businessLogicIndicators = [
    /\bif\s+.*\{/g,
    /\bmatch\s+/g,
    /\bfor\s+.*\bin\b/g,
    /\bwhile\s+/g,
    /checked_add|checked_sub|checked_mul|checked_div/g,
    /require!\s*\(/g,
    /\.try_borrow_mut/g,
  ];
  
  for (const line of lines) {
    for (const pat of cpiIndicators) {
      pat.lastIndex = 0;
      if (pat.test(line)) cpiPatterns++;
    }
    for (const pat of businessLogicIndicators) {
      pat.lastIndex = 0;
      if (pat.test(line)) businessLogicPatterns++;
    }
  }
  
  // It's a CPI wrapper if:
  // - High ratio of CPI patterns to business logic
  // - OR code contains "cpi" in module/crate name patterns
  const hasCpiModuleName = /mod\s+cpi\b|crate.*cpi|\/cpi\/|_cpi\b/.test(code);
  const highCpiRatio = cpiPatterns > 3 && cpiPatterns > businessLogicPatterns * 2;
  
  return hasCpiModuleName || highCpiRatio;
}

/**
 * Detect if the path/code belongs to a known audited protocol
 */
export function detectAuditedProtocol(path: string, code?: string): string | null {
  const lowerPath = path.toLowerCase();
  
  for (const protocol of KNOWN_AUDITED_PROTOCOLS) {
    for (const pattern of protocol.patterns) {
      if (lowerPath.includes(pattern.toLowerCase())) {
        return protocol.name;
      }
    }
  }
  
  // Also check code comments/metadata for protocol names
  if (code) {
    const lowerCode = code.toLowerCase().substring(0, 2000); // Check first 2KB
    for (const protocol of KNOWN_AUDITED_PROTOCOLS) {
      for (const pattern of protocol.patterns) {
        if (lowerCode.includes(pattern.toLowerCase())) {
          return protocol.name;
        }
      }
    }
  }
  
  return null;
}

/**
 * Analyze code/path and return all applicable notices
 */
export function getContextNotices(path: string, code: string): ContextNotices {
  return {
    isCpiWrapper: detectCpiWrapper(code),
    auditedProtocol: detectAuditedProtocol(path, code),
  };
}

// === Display helpers (CLI) ===

export function displayContextNotices(notices: ContextNotices): void {
  if (notices.isCpiWrapper) {
    console.log(chalk.yellow.bold('\n⚠️  CPI Interface Detected'));
    console.log(chalk.yellow('   This appears to be a cross-program invocation wrapper, not the core program.'));
    console.log(chalk.yellow('   Findings are informational and may not represent actual vulnerabilities.\n'));
  }
  
  if (notices.auditedProtocol) {
    console.log(chalk.green.bold(`\n✅ Known Audited Protocol — ${notices.auditedProtocol}`));
    console.log(chalk.green('   This protocol has undergone professional security audits.'));
    console.log(chalk.green('   Findings are informational and intended for educational purposes.\n'));
  }
}

export function displayDisclaimer(): void {
  console.log(chalk.gray('─'.repeat(70)));
  console.log(chalk.gray('📋 Note: SolShield uses pattern-matching against known vulnerability'));
  console.log(chalk.gray('   signatures. Findings require manual review. Pattern matches in'));
  console.log(chalk.gray('   audited, battle-tested protocols are typically informational.'));
  console.log(chalk.gray('─'.repeat(70)));
}

// === JSON helpers (for API/SDK responses) ===

export const DISCLAIMER_TEXT = '📋 Note: SolShield uses pattern-matching against known vulnerability signatures. Findings require manual review. Pattern matches in audited, battle-tested protocols are typically informational.';
export const CPI_NOTICE_TEXT = '⚠️ CPI Interface Detected — This appears to be a cross-program invocation wrapper, not the core program. Findings are informational and may not represent actual vulnerabilities.';
export function auditedProtocolNoticeText(name: string): string {
  return `✅ Known Audited Protocol — ${name} has undergone professional security audits. Findings are informational and intended for educational purposes.`;
}
