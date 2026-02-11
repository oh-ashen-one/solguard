import { NextRequest, NextResponse } from 'next/server';

// Inline pattern detection - works on serverless without CLI dependency
const PATTERNS = [
  {
    id: 'SOL001',
    title: 'Missing Owner Check',
    severity: 'critical',
    pattern: /AccountInfo[\s\S]*(?![\s\S]*owner\s*==)(?![\s\S]*has_one)/,
    description: 'Account ownership is not verified. Anyone could pass a malicious account.',
    suggestion: 'Add owner validation: require!(account.owner == expected_program, ErrorCode::InvalidOwner);'
  },
  {
    id: 'SOL002',
    title: 'Missing Signer Check',
    severity: 'critical',
    pattern: /\/\/\/\s*CHECK:|AccountInfo.*(?!.*Signer|.*is_signer|.*#\[account\(.*signer)/,
    suggestion: 'Add signer constraint: #[account(signer)] or verify is_signer manually.',
    description: 'Authority account lacks signer verification. Any account could be passed as authority.'
  },
  {
    id: 'SOL003',
    title: 'Integer Overflow',
    severity: 'high',
    pattern: /\b(\w+)\s*[-+*]\s*(\w+)(?!.*checked_|.*saturating_|.*wrapping_)/,
    description: 'Arithmetic operation without overflow protection could wrap around.',
    suggestion: 'Use checked_add(), checked_sub(), or checked_mul() for safe arithmetic.'
  },
  {
    id: 'SOL004',
    title: 'Missing PDA Bump Verification',
    severity: 'high',
    pattern: /find_program_address|create_program_address(?!.*bump|.*seeds)/,
    description: 'PDA derivation without bump seed storage could allow bump manipulation.',
    suggestion: 'Store and verify the canonical bump seed.'
  },
  {
    id: 'SOL005',
    title: 'Authority Bypass',
    severity: 'critical',
    pattern: /authority|admin|owner.*AccountInfo(?!.*constraint|.*has_one)/i,
    description: 'Sensitive authority account without proper constraints.',
    suggestion: 'Add has_one constraint: #[account(has_one = authority)]'
  },
  {
    id: 'SOL007',
    title: 'Unchecked CPI',
    severity: 'high',
    pattern: /invoke(?:_signed)?.*(?!.*program_id\s*==)/,
    description: 'Cross-program invocation without verifying the target program ID.',
    suggestion: 'Verify program_id matches expected value before CPI.'
  },
  {
    id: 'SOL010',
    title: 'Account Closing Vulnerability',
    severity: 'critical',
    pattern: /close\s*=|try_borrow_mut_lamports.*=\s*0(?!.*realloc|.*zero)/,
    description: 'Account closure without proper cleanup could allow revival attacks.',
    suggestion: 'Zero out account data before closing and use close constraint properly.'
  },
  {
    id: 'SOL011',
    title: 'Reentrancy Risk',
    severity: 'high',
    pattern: /invoke(?:_signed)?[\s\S]*?(?:balance|lamports|amount)\s*[+-=]/,
    description: 'State modification after CPI call could enable reentrancy.',
    suggestion: 'Update state before making external calls (checks-effects-interactions).'
  },
  {
    id: 'SOL015',
    title: 'Type Cosplay',
    severity: 'critical',
    pattern: /#\[account\][\s\S]*?pub\s+struct(?![\s\S]*?discriminator|[\s\S]*?DISCRIMINATOR)/,
    description: 'Account struct without discriminator could be confused with other types.',
    suggestion: 'Anchor adds discriminators automatically, but verify for raw Solana programs.'
  },
  {
    id: 'SOL018',
    title: 'Oracle Manipulation',
    severity: 'high',
    pattern: /price|oracle|feed(?!.*staleness|.*confidence|.*twap)/i,
    description: 'Oracle data usage without staleness or confidence checks.',
    suggestion: 'Check oracle staleness, confidence interval, and use TWAP for critical operations.'
  },
  {
    id: 'SOL027',
    title: 'Unsafe Unwrap',
    severity: 'medium',
    pattern: /\.unwrap\(\)|\.expect\(/,
    description: 'Using unwrap() can cause panic. Handle errors gracefully.',
    suggestion: 'Use ? operator or match/if-let for error handling.'
  },
  {
    id: 'SOL029',
    title: 'Signature Verification Bypass',
    severity: 'critical',
    pattern: /verify_signature|ed25519|secp256k1(?!.*require!|.*assert!|.*if\s+!)/i,
    description: 'Signature verification without proper validation. Wormhole lost $326M to this.',
    suggestion: 'Always verify signatures return true and revert on failure.'
  },
  {
    id: 'SOL031',
    title: 'Mint Authority Not Checked',
    severity: 'critical',
    pattern: /mint_to|MintTo(?!.*mint_authority|.*authority\s*==)/i,
    description: 'Minting tokens without verifying mint authority could allow infinite mints.',
    suggestion: 'Verify caller has mint authority before minting.'
  },
  {
    id: 'SOL033',
    title: 'Transfer Without Balance Check',
    severity: 'high',
    pattern: /transfer|Transfer(?!.*balance|.*amount\s*<=|.*sufficient)/i,
    description: 'Token transfer without checking sufficient balance.',
    suggestion: 'Verify sender has sufficient balance before transfer.'
  },
  {
    id: 'SOL035',
    title: 'Unbounded Loop',
    severity: 'medium',
    pattern: /for\s+\w+\s+in\s+\w+(?!.*\.iter\(\)\.take|.*\.len\(\)\s*<|.*MAX_)/,
    description: 'Loop without bounds could consume all compute budget.',
    suggestion: 'Add iteration limits to prevent denial of service.'
  },
  {
    id: 'SOL039',
    title: 'Hardcoded Secret',
    severity: 'critical',
    pattern: /secret|private_key|password|api_key.*=.*["'][a-zA-Z0-9]{16,}["']/i,
    description: 'Hardcoded secret detected. This could be leaked from on-chain code.',
    suggestion: 'Never store secrets in on-chain code. Use environment variables or secure vaults.'
  },
  {
    id: 'SOL042',
    title: 'Arbitrary CPI Target',
    severity: 'critical',
    pattern: /invoke.*program_id(?!.*==|.*require!|.*assert!)/,
    description: 'CPI to arbitrary program without validation. Attacker could redirect calls.',
    suggestion: 'Hardcode expected program IDs or validate against allowlist.'
  }
];

// Context-aware notices
const KNOWN_AUDITED_ORGS_V1 = [
  { name: 'Jupiter', patterns: ['jup-ag', 'jupiter-exchange'] },
  { name: 'Kamino', patterns: ['kamino-finance', 'hubbleprotocol'] },
  { name: 'Marinade', patterns: ['marinade-finance'] },
  { name: 'Orca', patterns: ['orca-so'] },
  { name: 'Raydium', patterns: ['raydium-io'] },
  { name: 'Mango v4', patterns: ['blockworks-foundation'] },
  { name: 'Pyth', patterns: ['pyth-network'] },
  { name: 'Metaplex', patterns: ['metaplex-foundation'] },
  { name: 'Sanctum', patterns: ['sanctumfi'] },
  { name: 'Drift', patterns: ['drift-labs'] },
  { name: 'Phoenix', patterns: ['ellipsis-labs'] },
  { name: 'Tensor', patterns: ['tensor-hq', 'tensor-foundation'] },
  { name: 'Jito', patterns: ['jito-foundation', 'jito-labs'] },
];

const DISCLAIMER_V1 = '📋 Note: SolShield uses pattern-matching against known vulnerability signatures. Findings require manual review. Pattern matches in audited, battle-tested protocols are typically informational.';

function detectCpiWrapperV1(code: string): boolean {
  const cpiIndicators = [/\bcpi::/g, /\bCpiContext\b/g, /\binvoke\b/g, /\binvoke_signed\b/g];
  const businessLogic = [/\bif\s+.*\{/g, /\bmatch\s+/g, /\brequire!\s*\(/g, /checked_/g];
  let cpi = 0, biz = 0;
  for (const p of cpiIndicators) { p.lastIndex = 0; cpi += (code.match(p) || []).length; }
  for (const p of businessLogic) { p.lastIndex = 0; biz += (code.match(p) || []).length; }
  return /mod\s+cpi\b|crate.*cpi|\/cpi\/|_cpi\b/.test(code) || (cpi > 3 && cpi > biz * 2);
}

function detectAuditedProtocolV1(code: string): string | null {
  const text = code.substring(0, 2000).toLowerCase();
  for (const proto of KNOWN_AUDITED_ORGS_V1) {
    for (const pat of proto.patterns) {
      if (text.includes(pat)) return proto.name;
    }
  }
  return null;
}

interface Finding {
  id: string;
  title: string;
  severity: string;
  description: string;
  suggestion: string;
  location: {
    file: string;
    line: number | null;
    snippet: string;
  };
}

function analyzeCode(code: string): Finding[] {
  const findings: Finding[] = [];
  const lines = code.split('\n');
  
  for (const pattern of PATTERNS) {
    const match = code.match(pattern.pattern);
    if (match) {
      // Find line number of match
      let lineNum = 1;
      let charCount = 0;
      const matchIndex = match.index || 0;
      
      for (let i = 0; i < lines.length; i++) {
        charCount += lines[i].length + 1;
        if (charCount > matchIndex) {
          lineNum = i + 1;
          break;
        }
      }
      
      // Get snippet (3 lines around match)
      const startLine = Math.max(0, lineNum - 2);
      const endLine = Math.min(lines.length, lineNum + 2);
      const snippet = lines.slice(startLine, endLine).join('\n');
      
      findings.push({
        id: pattern.id,
        title: pattern.title,
        severity: pattern.severity,
        description: pattern.description,
        suggestion: pattern.suggestion,
        location: {
          file: 'input.rs',
          line: lineNum,
          snippet: snippet.substring(0, 200),
        }
      });
    }
  }
  
  return findings;
}

function calculateSeverityScore(summary: any): number {
  const weights = { critical: 40, high: 25, medium: 10, low: 3, info: 1 };
  let score = 0;
  score += (summary.critical || 0) * weights.critical;
  score += (summary.high || 0) * weights.high;
  score += (summary.medium || 0) * weights.medium;
  score += (summary.low || 0) * weights.low;
  score += (summary.info || 0) * weights.info;
  return Math.min(100, score);
}

/**
 * SolShield Public API for Agents
 * 
 * POST /api/v1/audit
 * 
 * Request body:
 * {
 *   "code": "use anchor_lang::prelude::*; ...",  // Rust source code
 *   "format": "json" | "markdown",               // Optional, default: json
 * }
 */
export async function POST(request: NextRequest) {
  const startTime = Date.now();
  
  try {
    const body = await request.json();
    const { code, format = 'json' } = body;
    
    // Validate input
    if (!code || typeof code !== 'string') {
      return NextResponse.json(
        { success: false, error: 'Code is required and must be a string' },
        { status: 400 }
      );
    }

    if (code.length > 500000) { // 500KB limit
      return NextResponse.json(
        { success: false, error: 'Code exceeds maximum size (500KB)' },
        { status: 400 }
      );
    }

    // Context notices
    const isCpiWrapper = detectCpiWrapperV1(code);
    const auditedProtocol = detectAuditedProtocolV1(code);
    const contextMessages: string[] = [];
    if (isCpiWrapper) contextMessages.push('⚠️ CPI Interface Detected — This appears to be a cross-program invocation wrapper, not the core program. Findings are informational and may not represent actual vulnerabilities.');
    if (auditedProtocol) contextMessages.push(`✅ Known Audited Protocol — ${auditedProtocol} has undergone professional security audits. Findings are informational and intended for educational purposes.`);
    contextMessages.push(DISCLAIMER_V1);

    // Run inline pattern detection
    const findings = analyzeCode(code);
    
    // Calculate summary
    const summary = {
      critical: findings.filter(f => f.severity === 'critical').length,
      high: findings.filter(f => f.severity === 'high').length,
      medium: findings.filter(f => f.severity === 'medium').length,
      low: findings.filter(f => f.severity === 'low').length,
      info: 0,
      total: findings.length,
    };
    
    const severityScore = calculateSeverityScore(summary);
    
    const result = {
      success: true,
      programPath: 'input.rs',
      timestamp: new Date().toISOString(),
      findings,
      summary,
      passed: summary.critical === 0 && summary.high === 0,
      severityScore,
      patternsChecked: PATTERNS.length,
      executionTimeMs: Date.now() - startTime,
      apiVersion: '1.0.0',
      note: 'Web API uses simplified detection. Full CLI has 150+ patterns.',
      isCpiWrapper,
      auditedProtocol,
      contextMessages,
      disclaimer: DISCLAIMER_V1,
    };

    // Format response
    if (format === 'markdown') {
      return new NextResponse(formatAsMarkdown(result), {
        headers: { 'Content-Type': 'text/markdown' },
      });
    }
    
    return NextResponse.json(result);
    
  } catch (error: any) {
    console.error('Audit API error:', error);
    return NextResponse.json(
      { 
        success: false, 
        error: error.message || 'Failed to run audit',
        executionTimeMs: Date.now() - startTime,
      },
      { status: 500 }
    );
  }
}

function formatAsMarkdown(result: any): string {
  const lines = [
    '# 🛡️ SolShield Audit Report',
    '',
    `**Status:** ${result.passed ? '✅ PASSED' : '❌ FAILED'}`,
    `**Date:** ${result.timestamp}`,
    '',
    '## Summary',
    '',
    `| Severity | Count |`,
    `|----------|-------|`,
    `| 🔴 Critical | ${result.summary.critical} |`,
    `| 🟠 High | ${result.summary.high} |`,
    `| 🟡 Medium | ${result.summary.medium} |`,
    `| 🔵 Low | ${result.summary.low} |`,
    '',
  ];

  if (result.findings.length > 0) {
    lines.push('## Findings', '');
    for (const finding of result.findings) {
      lines.push(`### ${finding.id}: ${finding.title}`);
      lines.push(`**Severity:** ${finding.severity.toUpperCase()}`);
      lines.push(`**Location:** ${finding.location.file}:${finding.location.line || '?'}`);
      lines.push('');
      lines.push(finding.description);
      if (finding.suggestion) {
        lines.push('', '**Recommendation:**', '```rust', finding.suggestion, '```');
      }
      lines.push('');
    }
  }

  lines.push('---', '*Generated by SolShield*');
  return lines.join('\n');
}

// Health check endpoint
export async function GET() {
  return NextResponse.json({
    status: 'ok',
    service: 'SolShield Audit API',
    version: '1.0.0',
    patternsAvailable: PATTERNS.length,
    note: 'Web API uses simplified detection. Full CLI has 150+ patterns.',
    endpoints: {
      'POST /api/v1/audit': 'Audit Rust/Anchor code',
    },
  });
}
