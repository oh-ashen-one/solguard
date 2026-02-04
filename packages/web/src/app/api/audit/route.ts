import { NextRequest, NextResponse } from 'next/server';

// Inline pattern detection - works on serverless without CLI dependency
const PATTERNS = [
  {
    id: 'SOL001',
    title: 'Missing Owner Check',
    severity: 'critical',
    pattern: /AccountInfo.*(?!.*owner\s*==)(?!.*has_one)/s,
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
    id: 'SOL035',
    title: 'Unbounded Loop',
    severity: 'medium',
    pattern: /for\s+\w+\s+in\s+\w+(?!.*\.iter\(\)\.take|.*\.len\(\)\s*<|.*MAX_)/,
    description: 'Loop without bounds could consume all compute budget.',
    suggestion: 'Add iteration limits to prevent denial of service.'
  }
];

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

export async function POST(request: NextRequest) {
  const startTime = Date.now();
  
  try {
    const { code } = await request.json();
    
    if (!code || typeof code !== 'string') {
      return NextResponse.json(
        { error: 'Code is required' },
        { status: 400 }
      );
    }

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
    
    const result = {
      success: true,
      programPath: 'input.rs',
      timestamp: new Date().toISOString(),
      findings,
      summary,
      passed: summary.critical === 0 && summary.high === 0,
      patternsChecked: PATTERNS.length,
      executionTimeMs: Date.now() - startTime,
      note: 'Web demo uses simplified detection. Full CLI has 150+ patterns.',
    };
    
    return NextResponse.json(result);
    
  } catch (error: any) {
    console.error('Audit error:', error);
    return NextResponse.json(
      { error: error.message || 'Failed to run audit' },
      { status: 500 }
    );
  }
}
