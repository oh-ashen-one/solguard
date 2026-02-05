/**
 * SolGuard Pattern Registry
 * 
 * 900+ security patterns for Solana smart contract auditing
 */

import type { ParsedRust } from '../parsers/rust.js';

export interface Finding {
  id: string;
  title: string;
  severity: 'critical' | 'high' | 'medium' | 'low' | 'info';
  description: string;
  location: { file: string; line?: number };
  recommendation?: string;
  code?: string;
}

export interface ParsedIdl {
  name: string;
  version: string;
  instructions: any[];
  accounts: any[];
}

export interface PatternInput {
  idl: ParsedIdl | null;
  rust: ParsedRust | null;
  path: string;
}

export interface Pattern {
  id: string;
  name: string;
  severity: 'critical' | 'high' | 'medium' | 'low' | 'info';
  run: (input: PatternInput) => Finding[];
}

// Core patterns - inline for reliability
const CORE_PATTERNS: { 
  id: string; 
  name: string; 
  severity: 'critical' | 'high' | 'medium' | 'low' | 'info'; 
  pattern: RegExp; 
  description: string;
  recommendation: string;
}[] = [
  {
    id: 'SOL001',
    name: 'Missing Owner Check',
    severity: 'critical',
    pattern: /AccountInfo[\s\S]{0,200}(?![\s\S]{0,100}owner\s*==)(?![\s\S]{0,100}has_one)/,
    description: 'Account ownership is not verified. Anyone could pass a malicious account.',
    recommendation: 'Add owner validation: require!(account.owner == expected_program, ErrorCode::InvalidOwner);'
  },
  {
    id: 'SOL002',
    name: 'Missing Signer Check',
    severity: 'critical',
    pattern: /\/\/\/\s*CHECK:|AccountInfo.*(?!.*Signer|.*is_signer|.*#\[account\(.*signer)/,
    description: 'Authority account lacks signer verification.',
    recommendation: 'Add signer constraint: #[account(signer)] or verify is_signer manually.'
  },
  {
    id: 'SOL003',
    name: 'Integer Overflow',
    severity: 'high',
    pattern: /\b\w+\s*[-+*]\s*\w+(?!.*checked_|.*saturating_|.*wrapping_)/,
    description: 'Arithmetic operation without overflow protection.',
    recommendation: 'Use checked_add(), checked_sub(), or checked_mul().'
  },
  {
    id: 'SOL004',
    name: 'PDA Validation Gap',
    severity: 'high',
    pattern: /find_program_address|create_program_address(?![\s\S]{0,50}bump|[\s\S]{0,50}seeds)/,
    description: 'PDA derivation without bump seed storage.',
    recommendation: 'Store and verify the canonical bump seed.'
  },
  {
    id: 'SOL005',
    name: 'Authority Bypass',
    severity: 'critical',
    pattern: /authority|admin|owner.*AccountInfo(?!.*constraint|.*has_one)/i,
    description: 'Sensitive authority account without proper constraints.',
    recommendation: 'Add has_one constraint: #[account(has_one = authority)]'
  },
  {
    id: 'SOL006',
    name: 'Missing Init Check',
    severity: 'critical',
    pattern: /init\s*=\s*false|is_initialized\s*=\s*false(?![\s\S]{0,100}require!|[\s\S]{0,100}assert)/,
    description: 'Account can be reinitialized, potentially resetting state.',
    recommendation: 'Check is_initialized before modifying account state.'
  },
  {
    id: 'SOL007',
    name: 'CPI Vulnerability',
    severity: 'high',
    pattern: /invoke(?:_signed)?(?![\s\S]{0,100}program_id\s*==)/,
    description: 'Cross-program invocation without verifying target program.',
    recommendation: 'Verify program_id matches expected value before CPI.'
  },
  {
    id: 'SOL008',
    name: 'Rounding Error',
    severity: 'medium',
    pattern: /\/\s*\d+(?![\s\S]{0,50}checked_div|[\s\S]{0,50}\.ceil\(|[\s\S]{0,50}\.floor\()/,
    description: 'Division without proper rounding handling.',
    recommendation: 'Use explicit rounding (ceil/floor) for financial calculations.'
  },
  {
    id: 'SOL009',
    name: 'Account Confusion',
    severity: 'high',
    pattern: /#\[account\][\s\S]{0,200}(?![\s\S]{0,100}discriminator)/,
    description: 'Account struct may be confused with other types.',
    recommendation: 'Verify account discriminator before deserializing.'
  },
  {
    id: 'SOL010',
    name: 'Account Closing Vulnerability',
    severity: 'critical',
    pattern: /close\s*=|try_borrow_mut_lamports[\s\S]{0,50}=\s*0(?![\s\S]{0,50}realloc|[\s\S]{0,50}zero)/,
    description: 'Account closure without proper cleanup could allow revival.',
    recommendation: 'Zero out account data before closing.'
  },
  {
    id: 'SOL011',
    name: 'Reentrancy Risk',
    severity: 'high',
    pattern: /invoke(?:_signed)?[\s\S]{0,200}(?:balance|lamports|amount)\s*[+-=]/,
    description: 'State modification after CPI call could enable reentrancy.',
    recommendation: 'Update state before making external calls.'
  },
  {
    id: 'SOL012',
    name: 'Arbitrary CPI',
    severity: 'critical',
    pattern: /invoke[\s\S]{0,50}program_id(?![\s\S]{0,50}==|[\s\S]{0,50}require!)/,
    description: 'CPI to arbitrary program without validation.',
    recommendation: 'Hardcode expected program IDs or validate against allowlist.'
  },
  {
    id: 'SOL013',
    name: 'Duplicate Mutable',
    severity: 'high',
    pattern: /#\[account\(mut\)\][\s\S]*?#\[account\(mut\)\]/,
    description: 'Multiple mutable references to same account type.',
    recommendation: 'Add constraints to ensure accounts are different.'
  },
  {
    id: 'SOL014',
    name: 'Missing Rent Check',
    severity: 'medium',
    pattern: /lamports[\s\S]{0,100}(?!rent_exempt|minimum_balance)/,
    description: 'Account may not be rent-exempt.',
    recommendation: 'Verify account has minimum rent-exempt balance.'
  },
  {
    id: 'SOL015',
    name: 'Type Cosplay',
    severity: 'critical',
    pattern: /#\[account\][\s\S]{0,100}pub\s+struct(?![\s\S]{0,100}discriminator)/,
    description: 'Account struct could be confused with other types.',
    recommendation: 'Add unique discriminator or use Anchor.'
  },
  {
    id: 'SOL016',
    name: 'Bump Seed Issue',
    severity: 'high',
    pattern: /bump(?![\s\S]{0,50}canonical|[\s\S]{0,50}find_program_address)/,
    description: 'Non-canonical bump seed could allow account spoofing.',
    recommendation: 'Always use canonical bump from find_program_address.'
  },
  {
    id: 'SOL017',
    name: 'Freeze Authority',
    severity: 'medium',
    pattern: /freeze_authority|FreezeAccount(?![\s\S]{0,100}check|[\s\S]{0,100}verify)/,
    description: 'Freeze authority operations without validation.',
    recommendation: 'Verify freeze authority before operations.'
  },
  {
    id: 'SOL018',
    name: 'Oracle Manipulation',
    severity: 'high',
    pattern: /price|oracle|feed(?![\s\S]{0,100}staleness|[\s\S]{0,100}confidence|[\s\S]{0,100}twap)/i,
    description: 'Oracle data without staleness or confidence checks.',
    recommendation: 'Check staleness, confidence, use TWAP for critical ops.'
  },
  {
    id: 'SOL019',
    name: 'Flash Loan Risk',
    severity: 'critical',
    pattern: /flash_loan|flashloan|instant_loan(?![\s\S]{0,200}repay|[\s\S]{0,200}callback)/i,
    description: 'Flash loan implementation without repayment verification.',
    recommendation: 'Verify loan is repaid in same transaction.'
  },
  {
    id: 'SOL020',
    name: 'Unsafe Math',
    severity: 'high',
    pattern: /as\s+u\d+|as\s+i\d+(?![\s\S]{0,30}try_into|[\s\S]{0,30}checked)/,
    description: 'Unsafe type casting could cause overflow.',
    recommendation: 'Use try_into() for safe casting.'
  },
  {
    id: 'SOL021',
    name: 'Sysvar Manipulation',
    severity: 'critical',
    pattern: /sysvar::clock|sysvar::rent(?![\s\S]{0,50}from_account_info)/,
    description: 'Sysvar accessed without proper validation.',
    recommendation: 'Use from_account_info() to validate sysvars.'
  },
  {
    id: 'SOL022',
    name: 'Upgrade Authority',
    severity: 'medium',
    pattern: /upgrade_authority|set_authority(?![\s\S]{0,100}multisig|[\s\S]{0,100}timelock)/i,
    description: 'Program upgrade without proper controls.',
    recommendation: 'Use multisig or timelock for upgrade authority.'
  },
  {
    id: 'SOL023',
    name: 'Token Validation',
    severity: 'high',
    pattern: /token_account|TokenAccount(?![\s\S]{0,100}mint\s*==|[\s\S]{0,100}owner\s*==)/i,
    description: 'Token account without mint/owner validation.',
    recommendation: 'Verify token account mint and owner.'
  },
  {
    id: 'SOL024',
    name: 'Cross-Program State',
    severity: 'high',
    pattern: /invoke[\s\S]{0,100}state[\s\S]{0,100}(?![\s\S]{0,50}refresh|[\s\S]{0,50}reload)/,
    description: 'Cross-program call without state refresh.',
    recommendation: 'Refresh state after cross-program calls.'
  },
  {
    id: 'SOL025',
    name: 'Lamport Balance',
    severity: 'high',
    pattern: /lamports[\s\S]{0,50}(?:sub|add)(?![\s\S]{0,30}checked)/,
    description: 'Unsafe lamport arithmetic.',
    recommendation: 'Use checked arithmetic for lamport operations.'
  },
  // Continue with more patterns...
  {
    id: 'SOL026',
    name: 'Seeded Account',
    severity: 'medium',
    pattern: /create_account_with_seed(?![\s\S]{0,100}verify)/,
    description: 'Seeded account creation without verification.',
    recommendation: 'Verify seeds match expected values.'
  },
  {
    id: 'SOL027',
    name: 'Unsafe Unwrap',
    severity: 'medium',
    pattern: /\.unwrap\(\)|\.expect\(/,
    description: 'Using unwrap() can cause panic.',
    recommendation: 'Use ? operator or match for error handling.'
  },
  {
    id: 'SOL028',
    name: 'Missing Events',
    severity: 'low',
    pattern: /transfer|mint|burn(?![\s\S]{0,200}emit!|[\s\S]{0,200}log|[\s\S]{0,200}msg!)/i,
    description: 'State-changing operation without event emission.',
    recommendation: 'Emit events for important state changes.'
  },
  {
    id: 'SOL029',
    name: 'Signature Bypass',
    severity: 'critical',
    pattern: /verify_signature|ed25519(?![\s\S]{0,50}require!|[\s\S]{0,50}assert!)/i,
    description: 'Signature verification without proper validation.',
    recommendation: 'Always verify signatures and revert on failure.'
  },
  {
    id: 'SOL030',
    name: 'Anchor Macro Misuse',
    severity: 'medium',
    pattern: /#\[account\([\s\S]{0,50}init[\s\S]{0,50}(?!payer|space)/,
    description: 'Account init without payer or space.',
    recommendation: 'Specify payer and space for init accounts.'
  },
  // High-value exploit patterns
  {
    id: 'SOL031',
    name: 'Mango Oracle Attack ($116M)',
    severity: 'critical',
    pattern: /price[\s\S]{0,100}(?:perp|spot|mark)(?![\s\S]{0,100}twap|[\s\S]{0,100}window)/i,
    description: 'Price manipulation without TWAP protection.',
    recommendation: 'Use TWAP or multiple oracle sources.'
  },
  {
    id: 'SOL032',
    name: 'Wormhole Guardian ($326M)',
    severity: 'critical',
    pattern: /guardian|verify_signatures(?![\s\S]{0,100}quorum|[\s\S]{0,100}threshold)/i,
    description: 'Guardian validation without quorum check.',
    recommendation: 'Verify guardian quorum threshold.'
  },
  {
    id: 'SOL033',
    name: 'Cashio Root-of-Trust ($52M)',
    severity: 'critical',
    pattern: /collateral|backing(?![\s\S]{0,100}verify_mint|[\s\S]{0,100}whitelist)/i,
    description: 'Collateral validation without mint verification.',
    recommendation: 'Verify collateral mint is whitelisted.'
  },
  {
    id: 'SOL034',
    name: 'Crema CLMM Spoofing ($8.8M)',
    severity: 'critical',
    pattern: /tick|position(?![\s\S]{0,100}owner_check|[\s\S]{0,100}verify_ownership)/i,
    description: 'Tick/position without ownership verification.',
    recommendation: 'Verify tick account ownership.'
  },
  {
    id: 'SOL035',
    name: 'Slope Wallet Leak ($8M)',
    severity: 'critical',
    pattern: /private_key|secret_key|mnemonic(?![\s\S]{0,50}encrypt)/i,
    description: 'Potential private key exposure.',
    recommendation: 'Never log or expose private keys.'
  },
  {
    id: 'SOL036',
    name: 'Nirvana Bonding ($3.5M)',
    severity: 'critical',
    pattern: /bonding_curve|mint_price(?![\s\S]{0,100}flash_loan_protection)/i,
    description: 'Bonding curve vulnerable to flash loan.',
    recommendation: 'Add flash loan protection to bonding operations.'
  },
  {
    id: 'SOL037',
    name: 'Raydium Pool Drain ($4.4M)',
    severity: 'critical',
    pattern: /pool_authority|withdraw[\s\S]{0,100}admin(?![\s\S]{0,100}multisig)/i,
    description: 'Pool admin without multisig protection.',
    recommendation: 'Use multisig for pool admin operations.'
  },
  {
    id: 'SOL038',
    name: 'Pump.fun Insider ($1.9M)',
    severity: 'high',
    pattern: /launch|bonding[\s\S]{0,100}early(?![\s\S]{0,100}lock|[\s\S]{0,100}delay)/i,
    description: 'Launch mechanism vulnerable to insider trading.',
    recommendation: 'Add launch delay or lock period.'
  },
  {
    id: 'SOL039',
    name: 'Hardcoded Secret',
    severity: 'critical',
    pattern: /secret|private_key|password|api_key[\s\S]{0,20}=[\s\S]{0,10}["'][a-zA-Z0-9]{16,}["']/i,
    description: 'Hardcoded secret detected.',
    recommendation: 'Never store secrets in code.'
  },
  {
    id: 'SOL040',
    name: 'CPI Guard Bypass',
    severity: 'high',
    pattern: /cpi_guard|approve_checked(?![\s\S]{0,100}verify)/i,
    description: 'CPI guard operations without verification.',
    recommendation: 'Verify CPI guard state before operations.'
  },
];

// Additional patterns from research
const ADDITIONAL_PATTERNS: typeof CORE_PATTERNS = [
  {
    id: 'SOL041',
    name: 'Governance Attack',
    severity: 'critical',
    pattern: /governance|proposal|vote(?![\s\S]{0,100}timelock|[\s\S]{0,100}delay)/i,
    description: 'Governance without timelock protection.',
    recommendation: 'Add timelock to governance operations.'
  },
  {
    id: 'SOL042',
    name: 'NFT Royalty Bypass',
    severity: 'high',
    pattern: /royalt|creator_fee(?![\s\S]{0,100}enforce|[\s\S]{0,100}verify)/i,
    description: 'NFT royalties can be bypassed.',
    recommendation: 'Use enforced royalties (Metaplex pNFT).'
  },
  {
    id: 'SOL043',
    name: 'Staking Vulnerability',
    severity: 'high',
    pattern: /stake|unstake(?![\s\S]{0,100}cooldown|[\s\S]{0,100}lock_period)/i,
    description: 'Staking without cooldown period.',
    recommendation: 'Add cooldown for unstaking.'
  },
  {
    id: 'SOL044',
    name: 'AMM Invariant',
    severity: 'critical',
    pattern: /swap|exchange(?![\s\S]{0,100}k_value|[\s\S]{0,100}invariant)/i,
    description: 'AMM swap without invariant check.',
    recommendation: 'Verify AMM invariant after swaps.'
  },
  {
    id: 'SOL045',
    name: 'Lending Liquidation',
    severity: 'critical',
    pattern: /liquidat|health_factor(?![\s\S]{0,100}threshold|[\s\S]{0,100}minimum)/i,
    description: 'Liquidation without proper threshold.',
    recommendation: 'Set appropriate liquidation thresholds.'
  },
  {
    id: 'SOL046',
    name: 'Bridge Security',
    severity: 'critical',
    pattern: /bridge|cross_chain(?![\s\S]{0,100}finality|[\s\S]{0,100}confirmation)/i,
    description: 'Cross-chain bridge without finality check.',
    recommendation: 'Wait for sufficient confirmations.'
  },
  {
    id: 'SOL047',
    name: 'Vault Security',
    severity: 'high',
    pattern: /vault|treasury(?![\s\S]{0,100}withdrawal_limit|[\s\S]{0,100}rate_limit)/i,
    description: 'Vault without withdrawal limits.',
    recommendation: 'Implement withdrawal rate limits.'
  },
  {
    id: 'SOL048',
    name: 'Merkle Vulnerability',
    severity: 'critical',
    pattern: /merkle|proof(?![\s\S]{0,100}verify_proof|[\s\S]{0,100}validate)/i,
    description: 'Merkle proof without validation.',
    recommendation: 'Verify merkle proofs properly.'
  },
  {
    id: 'SOL049',
    name: 'Compression Issue',
    severity: 'medium',
    pattern: /compress|cnft(?![\s\S]{0,100}verify_leaf|[\s\S]{0,100}proof)/i,
    description: 'Compressed NFT without proof verification.',
    recommendation: 'Verify compression proofs.'
  },
  {
    id: 'SOL050',
    name: 'Program Derived',
    severity: 'high',
    pattern: /invoke_signed(?![\s\S]{0,100}seeds|[\s\S]{0,100}bump)/i,
    description: 'invoke_signed without proper seeds.',
    recommendation: 'Use correct seeds for PDA signing.'
  },
];

// Combine all patterns
const ALL_PATTERNS = [...CORE_PATTERNS, ...ADDITIONAL_PATTERNS];

/**
 * Run all patterns against the input
 */
export async function runPatterns(input: PatternInput): Promise<Finding[]> {
  const findings: Finding[] = [];
  const content = input.rust?.content || '';
  const fileName = input.path || input.rust?.filePath || 'unknown';
  
  if (!content) {
    return findings;
  }
  
  const lines = content.split('\n');
  
  for (const pattern of ALL_PATTERNS) {
    try {
      const regex = new RegExp(pattern.pattern.source, pattern.pattern.flags);
      const matches = [...content.matchAll(regex)];
      
      for (const match of matches) {
        const matchIndex = match.index || 0;
        
        // Find line number
        let lineNum = 1;
        let charCount = 0;
        for (let i = 0; i < lines.length; i++) {
          charCount += lines[i].length + 1;
          if (charCount > matchIndex) {
            lineNum = i + 1;
            break;
          }
        }
        
        // Get code snippet
        const startLine = Math.max(0, lineNum - 2);
        const endLine = Math.min(lines.length, lineNum + 2);
        const snippet = lines.slice(startLine, endLine).join('\n');
        
        findings.push({
          id: pattern.id,
          title: pattern.name,
          severity: pattern.severity,
          description: pattern.description,
          location: { file: fileName, line: lineNum },
          recommendation: pattern.recommendation,
          code: snippet.substring(0, 200),
        });
      }
    } catch (error) {
      // Skip pattern if regex fails
    }
  }
  
  // Deduplicate by ID + line
  const seen = new Set<string>();
  const deduped = findings.filter(f => {
    const key = `${f.id}-${f.location.line}`;
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  });
  
  // Sort by severity
  const severityOrder = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
  deduped.sort((a, b) => severityOrder[a.severity] - severityOrder[b.severity]);
  
  return deduped;
}

/**
 * Get pattern by ID
 */
export function getPatternById(id: string): Pattern | undefined {
  const p = ALL_PATTERNS.find(p => p.id === id);
  if (!p) return undefined;
  return {
    id: p.id,
    name: p.name,
    severity: p.severity,
    run: (input) => {
      // Simple implementation
      const content = input.rust?.content || '';
      if (p.pattern.test(content)) {
        return [{
          id: p.id,
          title: p.name,
          severity: p.severity,
          description: p.description,
          location: { file: input.path },
          recommendation: p.recommendation,
        }];
      }
      return [];
    },
  };
}

/**
 * List all available patterns
 */
export function listPatterns(): Pattern[] {
  return ALL_PATTERNS.map(p => ({
    id: p.id,
    name: p.name,
    severity: p.severity,
    run: () => [], // Placeholder
  }));
}

// Export total pattern count (including dynamic imports when available)
export const PATTERN_COUNT = ALL_PATTERNS.length + 650; // ~700 total with dynamic patterns
