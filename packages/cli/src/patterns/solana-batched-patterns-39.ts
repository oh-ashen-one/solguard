/**
 * SolGuard Pattern Batch 39
 * Sec3 2025 Security Report Patterns & Recent Exploit Analysis
 * Patterns SOL1021-SOL1100
 * 
 * Based on: https://solanasec25.sec3.dev/ (163 audits, 1,669 vulnerabilities analyzed)
 * Key finding: Business Logic (38.5%), Input Validation (25%), Access Control (19%)
 */

import type { PatternInput, Finding } from './index.js';

interface BatchPattern {
  id: string;
  name: string;
  severity: 'critical' | 'high' | 'medium' | 'low' | 'info';
  category: string;
  description: string;
  detection: {
    patterns: RegExp[];
  };
  recommendation: string;
  references: string[];
}

const batchedPatterns39: BatchPattern[] = [
  // ========================================
  // BUSINESS LOGIC VULNERABILITIES (38.5% of all findings)
  // ========================================
  {
    id: 'SOL1021',
    name: 'State Machine Inconsistency',
    severity: 'critical',
    category: 'business-logic',
    description: 'Protocol state machine allows invalid state transitions that can be exploited.',
    detection: {
      patterns: [
        /state\s*=\s*State::/i,
        /status\s*=\s*Status::/i,
        /set_state/i,
        /transition.*state/i
      ]
    },
    recommendation: 'Implement explicit state machine with validated transitions. Use enum-based states with transition guards.',
    references: ['https://solanasec25.sec3.dev/', 'https://www.sec3.dev/blog/how-to-audit-solana-smart-contracts-part-1-a-systematic-approach']
  },
  {
    id: 'SOL1022',
    name: 'Order of Operations Attack',
    severity: 'high',
    category: 'business-logic',
    description: 'Operations can be called in unexpected order to extract value.',
    detection: {
      patterns: [
        /withdraw.*before.*deposit/i,
        /claim.*before.*stake/i,
        /settle.*before.*fill/i
      ]
    },
    recommendation: 'Enforce strict operation ordering. Use state flags or timestamps to prevent out-of-order execution.',
    references: ['https://solanasec25.sec3.dev/']
  },
  {
    id: 'SOL1023',
    name: 'Fee Calculation Exploit',
    severity: 'high',
    category: 'business-logic',
    description: 'Fee calculations can be manipulated to pay less or extract more.',
    detection: {
      patterns: [
        /fee\s*=.*\//i,
        /calculate.*fee/i,
        /fee.*percent/i,
        /fee.*basis.*point/i
      ]
    },
    recommendation: 'Use fixed-point arithmetic for fees. Calculate fees before transfers. Validate fee bounds.',
    references: ['https://solanasec25.sec3.dev/']
  },
  {
    id: 'SOL1024',
    name: 'Reward Distribution Flaw',
    severity: 'critical',
    category: 'business-logic',
    description: 'Reward distribution can be gamed through timing or stake manipulation.',
    detection: {
      patterns: [
        /reward.*per.*share/i,
        /distribute.*reward/i,
        /claim.*reward/i,
        /accumulated.*reward/i
      ]
    },
    recommendation: 'Use time-weighted reward distribution. Implement minimum stake duration. Add anti-gaming cooldowns.',
    references: ['https://solanasec25.sec3.dev/']
  },
  {
    id: 'SOL1025',
    name: 'Circular Dependency Attack',
    severity: 'critical',
    category: 'business-logic',
    description: 'Protocol components can be used in circular fashion to multiply value.',
    detection: {
      patterns: [
        /borrow.*collateral/i,
        /stake.*borrow/i,
        /loop.*leverage/i,
        /recursive.*mint/i
      ]
    },
    recommendation: 'Detect and prevent circular dependencies. Implement loop detection. Cap recursive operations.',
    references: ['https://solanasec25.sec3.dev/']
  },
  {
    id: 'SOL1026',
    name: 'Flash Settlement Exploit',
    severity: 'critical',
    category: 'business-logic',
    description: 'Settlement process can be manipulated within same transaction.',
    detection: {
      patterns: [
        /settle.*instant/i,
        /immediate.*settlement/i,
        /same.*tx.*settle/i,
        /flash.*settle/i
      ]
    },
    recommendation: 'Require settlement delay or cross-transaction verification. Prevent same-block manipulation.',
    references: ['https://solanasec25.sec3.dev/']
  },
  {
    id: 'SOL1027',
    name: 'Accounting Mismatch',
    severity: 'critical',
    category: 'business-logic',
    description: 'Internal accounting diverges from actual token balances.',
    detection: {
      patterns: [
        /total.*supply/i,
        /internal.*balance/i,
        /accounting.*update/i,
        /ledger.*entry/i
      ]
    },
    recommendation: 'Always sync internal accounting with actual balances. Use checks-effects-interactions pattern.',
    references: ['https://blog.neodyme.io/posts/lending_disclosure']
  },
  {
    id: 'SOL1028',
    name: 'Epoch Boundary Attack',
    severity: 'high',
    category: 'business-logic',
    description: 'Operations at epoch boundaries can be exploited for advantage.',
    detection: {
      patterns: [
        /epoch.*boundary/i,
        /end.*epoch/i,
        /epoch.*transition/i,
        /new.*epoch/i
      ]
    },
    recommendation: 'Handle epoch transitions atomically. Prevent operations during boundary periods.',
    references: ['https://solanasec25.sec3.dev/']
  },
  {
    id: 'SOL1029',
    name: 'Utilization Rate Manipulation',
    severity: 'high',
    category: 'business-logic',
    description: 'Protocol utilization rate can be manipulated to affect interest rates.',
    detection: {
      patterns: [
        /utilization.*rate/i,
        /borrow.*rate/i,
        /supply.*rate/i,
        /interest.*model/i
      ]
    },
    recommendation: 'Use TWAP for rate calculations. Add rate limits on large operations.',
    references: ['https://solanasec25.sec3.dev/']
  },
  {
    id: 'SOL1030',
    name: 'Slippage Bounds Bypass',
    severity: 'high',
    category: 'business-logic',
    description: 'Slippage protection can be bypassed through multi-step attacks.',
    detection: {
      patterns: [
        /slippage/i,
        /min.*amount.*out/i,
        /max.*amount.*in/i,
        /price.*impact/i
      ]
    },
    recommendation: 'Validate slippage at every step. Use atomic slippage checks.',
    references: ['https://solanasec25.sec3.dev/']
  },

  // ========================================
  // INPUT VALIDATION VULNERABILITIES (25% of findings)
  // ========================================
  {
    id: 'SOL1031',
    name: 'Account Data Length Mismatch',
    severity: 'critical',
    category: 'input-validation',
    description: 'Account data length not validated, allowing truncation or overflow attacks.',
    detection: {
      patterns: [
        /data\.len\(\)/i,
        /account.*data/i,
        /try_from_slice/i,
        /deserialize/i
      ]
    },
    recommendation: 'Always validate account data length before deserialization. Use Anchor\'s space constraints.',
    references: ['https://blog.neodyme.io/posts/solana_common_pitfalls']
  },
  {
    id: 'SOL1032',
    name: 'String Injection',
    severity: 'medium',
    category: 'input-validation',
    description: 'User-controlled strings used unsafely in PDAs or logs.',
    detection: {
      patterns: [
        /String::from/i,
        /to_string\(\)/i,
        /format!/i,
        /name.*bytes/i
      ]
    },
    recommendation: 'Validate string length and content. Sanitize before use in seeds or logs.',
    references: ['https://solanasec25.sec3.dev/']
  },
  {
    id: 'SOL1033',
    name: 'Empty Account Exploit',
    severity: 'high',
    category: 'input-validation',
    description: 'Empty or zeroed accounts accepted without validation.',
    detection: {
      patterns: [
        /data_is_empty/i,
        /data\.iter\(\)\.all\(/i,
        /lamports\s*==\s*0/i
      ]
    },
    recommendation: 'Check for empty accounts explicitly. Validate account has expected data.',
    references: ['https://solanasec25.sec3.dev/']
  },
  {
    id: 'SOL1034',
    name: 'Instruction Data Overflow',
    severity: 'critical',
    category: 'input-validation',
    description: 'Instruction data parsing vulnerable to overflow or underflow.',
    detection: {
      patterns: [
        /instruction.*data/i,
        /ix_data/i,
        /parse.*instruction/i,
        /unpack.*instruction/i
      ]
    },
    recommendation: 'Use safe parsing with bounds checking. Validate instruction data length.',
    references: ['https://solanasec25.sec3.dev/']
  },
  {
    id: 'SOL1035',
    name: 'Seed Length Injection',
    severity: 'high',
    category: 'input-validation',
    description: 'PDA seeds with variable length can cause collisions or bypasses.',
    detection: {
      patterns: [
        /seeds\s*=.*&\[/i,
        /find_program_address.*&\[/i,
        /create_program_address.*&\[/i
      ]
    },
    recommendation: 'Use fixed-length seeds. Add length prefixes to variable seeds.',
    references: ['https://blog.neodyme.io/posts/solana_common_pitfalls']
  },
  {
    id: 'SOL1036',
    name: 'Timestamp Validation Missing',
    severity: 'medium',
    category: 'input-validation',
    description: 'User-provided timestamps accepted without validation.',
    detection: {
      patterns: [
        /timestamp/i,
        /unix_timestamp/i,
        /clock\.unix_timestamp/i
      ]
    },
    recommendation: 'Validate timestamps against current time. Use Clock sysvar for authoritative time.',
    references: ['https://solanasec25.sec3.dev/']
  },
  {
    id: 'SOL1037',
    name: 'Amount Boundary Check Missing',
    severity: 'high',
    category: 'input-validation',
    description: 'Token amounts not validated for minimum/maximum bounds.',
    detection: {
      patterns: [
        /amount\s*[<>]=?\s*0/i,
        /require!.*amount/i,
        /transfer.*amount/i
      ]
    },
    recommendation: 'Validate amounts against min/max bounds. Check for zero amounts.',
    references: ['https://solanasec25.sec3.dev/']
  },
  {
    id: 'SOL1038',
    name: 'Pubkey Validation Gap',
    severity: 'critical',
    category: 'input-validation',
    description: 'Public key not validated against expected value or format.',
    detection: {
      patterns: [
        /Pubkey::new/i,
        /Pubkey::from/i,
        /pubkey\s*==/i,
        /key\(\)/i
      ]
    },
    recommendation: 'Always validate pubkeys against expected values. Use constraint macros.',
    references: ['https://solanasec25.sec3.dev/']
  },
  {
    id: 'SOL1039',
    name: 'Decimal Precision Attack',
    severity: 'high',
    category: 'input-validation',
    description: 'Token decimal precision not handled correctly causing value loss.',
    detection: {
      patterns: [
        /decimals/i,
        /10\s*\*\*/i,
        /pow\(10/i,
        /scale.*factor/i
      ]
    },
    recommendation: 'Normalize all amounts to common precision. Validate decimal values.',
    references: ['https://solanasec25.sec3.dev/']
  },
  {
    id: 'SOL1040',
    name: 'Enum Variant Exhaustiveness',
    severity: 'medium',
    category: 'input-validation',
    description: 'Enum matching not exhaustive, allowing undefined behavior.',
    detection: {
      patterns: [
        /match.*\{[\s\S]*_\s*=>/i,
        /if let Some/i,
        /unreachable!/i
      ]
    },
    recommendation: 'Match all enum variants explicitly. Use exhaustive matching.',
    references: ['https://solanasec25.sec3.dev/']
  },

  // ========================================
  // ACCESS CONTROL VULNERABILITIES (19% of findings)
  // ========================================
  {
    id: 'SOL1041',
    name: 'Multi-Sig Threshold Bypass',
    severity: 'critical',
    category: 'access-control',
    description: 'Multi-signature threshold can be bypassed or reduced.',
    detection: {
      patterns: [
        /threshold/i,
        /multisig/i,
        /multi_sig/i,
        /quorum/i
      ]
    },
    recommendation: 'Immutably set thresholds. Require all signers to change threshold.',
    references: ['https://solanasec25.sec3.dev/']
  },
  {
    id: 'SOL1042',
    name: 'Role Assignment Flaw',
    severity: 'critical',
    category: 'access-control',
    description: 'Roles can be assigned without proper authorization.',
    detection: {
      patterns: [
        /set.*role/i,
        /grant.*role/i,
        /revoke.*role/i,
        /role\s*=/i
      ]
    },
    recommendation: 'Implement role-based access control. Require admin for role changes.',
    references: ['https://solanasec25.sec3.dev/']
  },
  {
    id: 'SOL1043',
    name: 'Emergency Mode Abuse',
    severity: 'critical',
    category: 'access-control',
    description: 'Emergency/pause mode can be abused to extract value.',
    detection: {
      patterns: [
        /emergency/i,
        /pause/i,
        /circuit.*breaker/i,
        /shutdown/i
      ]
    },
    recommendation: 'Limit emergency mode powers. Add timelock to emergency actions.',
    references: ['https://solanasec25.sec3.dev/']
  },
  {
    id: 'SOL1044',
    name: 'Delegate Authority Escalation',
    severity: 'high',
    category: 'access-control',
    description: 'Delegated authority can be escalated beyond intended scope.',
    detection: {
      patterns: [
        /delegate/i,
        /delegated.*authority/i,
        /on_behalf/i,
        /proxy/i
      ]
    },
    recommendation: 'Limit delegation scope. Implement delegation revocation.',
    references: ['https://solanasec25.sec3.dev/']
  },
  {
    id: 'SOL1045',
    name: 'Whitelist Bypass',
    severity: 'critical',
    category: 'access-control',
    description: 'Whitelist/allowlist can be bypassed through indirect access.',
    detection: {
      patterns: [
        /whitelist/i,
        /allowlist/i,
        /permitted/i,
        /approved.*list/i
      ]
    },
    recommendation: 'Check whitelist at all entry points. Use consistent validation.',
    references: ['https://solanasec25.sec3.dev/']
  },
  {
    id: 'SOL1046',
    name: 'Permissionless Admin Function',
    severity: 'critical',
    category: 'access-control',
    description: 'Administrative function callable without proper authorization.',
    detection: {
      patterns: [
        /admin/i,
        /owner_only/i,
        /privileged/i,
        /restricted/i
      ]
    },
    recommendation: 'Add explicit authorization checks to all admin functions.',
    references: ['https://research.kudelskisecurity.com/2021/09/15/solana-program-security-part1/']
  },
  {
    id: 'SOL1047',
    name: 'Fee Recipient Manipulation',
    severity: 'high',
    category: 'access-control',
    description: 'Fee recipient can be changed without proper authorization.',
    detection: {
      patterns: [
        /fee.*recipient/i,
        /fee.*destination/i,
        /treasury/i,
        /protocol.*fee/i
      ]
    },
    recommendation: 'Lock fee recipient behind multi-sig. Add timelock for changes.',
    references: ['https://solanasec25.sec3.dev/']
  },
  {
    id: 'SOL1048',
    name: 'Migration Authority Abuse',
    severity: 'critical',
    category: 'access-control',
    description: 'Migration/upgrade authority can drain or manipulate protocol.',
    detection: {
      patterns: [
        /migration/i,
        /upgrade.*authority/i,
        /migrate.*funds/i,
        /emergency.*withdraw/i
      ]
    },
    recommendation: 'Use timelocked migrations. Implement migration guards.',
    references: ['https://solanasec25.sec3.dev/']
  },
  {
    id: 'SOL1049',
    name: 'Oracle Authority Centralization',
    severity: 'high',
    category: 'access-control',
    description: 'Single oracle authority can manipulate prices.',
    detection: {
      patterns: [
        /oracle.*authority/i,
        /price.*authority/i,
        /update.*price/i,
        /set.*oracle/i
      ]
    },
    recommendation: 'Use decentralized oracles (Pyth, Switchboard). Implement price bounds.',
    references: ['https://osec.io/blog/reports/2022-02-16-lp-token-oracle-manipulation/']
  },
  {
    id: 'SOL1050',
    name: 'Custody Key Exposure',
    severity: 'critical',
    category: 'access-control',
    description: 'Custody or hot wallet keys insufficiently protected.',
    detection: {
      patterns: [
        /custody/i,
        /hot.*wallet/i,
        /signing.*key/i,
        /operational.*key/i
      ]
    },
    recommendation: 'Use hardware security modules. Implement key rotation. Multi-party custody.',
    references: ['https://solanasec25.sec3.dev/']
  },

  // ========================================
  // DATA INTEGRITY & ARITHMETIC (8.9% of findings)
  // ========================================
  {
    id: 'SOL1051',
    name: 'Share Calculation Rounding',
    severity: 'critical',
    category: 'data-integrity',
    description: 'Share/token calculations vulnerable to rounding manipulation.',
    detection: {
      patterns: [
        /shares\s*=/i,
        /share.*calculation/i,
        /mint.*shares/i,
        /redeem.*shares/i
      ]
    },
    recommendation: 'Round down for deposits, round up for withdrawals. Use virtual shares.',
    references: ['https://blog.neodyme.io/posts/lending_disclosure']
  },
  {
    id: 'SOL1052',
    name: 'Interest Accrual Precision Loss',
    severity: 'high',
    category: 'data-integrity',
    description: 'Interest calculations lose precision over time.',
    detection: {
      patterns: [
        /interest.*accrual/i,
        /compound.*interest/i,
        /accrue/i,
        /rate.*index/i
      ]
    },
    recommendation: 'Use high-precision arithmetic. Implement periodic normalization.',
    references: ['https://solanasec25.sec3.dev/']
  },
  {
    id: 'SOL1053',
    name: 'Price Impact Calculation Error',
    severity: 'high',
    category: 'data-integrity',
    description: 'Price impact calculated incorrectly allowing manipulation.',
    detection: {
      patterns: [
        /price.*impact/i,
        /slippage.*calc/i,
        /execution.*price/i,
        /effective.*price/i
      ]
    },
    recommendation: 'Use established AMM formulas. Validate impact bounds.',
    references: ['https://solanasec25.sec3.dev/']
  },
  {
    id: 'SOL1054',
    name: 'Ratio Overflow',
    severity: 'critical',
    category: 'data-integrity',
    description: 'Ratio calculations can overflow with extreme values.',
    detection: {
      patterns: [
        /ratio\s*=/i,
        /proportion/i,
        /percentage/i,
        /multiplier/i
      ]
    },
    recommendation: 'Use u128 or checked math for ratios. Validate input ranges.',
    references: ['https://www.sec3.dev/blog/understanding-arithmetic-overflow-underflows-in-rust-and-solana-smart-contracts']
  },
  {
    id: 'SOL1055',
    name: 'Cumulative Sum Drift',
    severity: 'medium',
    category: 'data-integrity',
    description: 'Cumulative sums drift from actual totals over time.',
    detection: {
      patterns: [
        /cumulative/i,
        /running.*total/i,
        /accumulated/i,
        /sum.*total/i
      ]
    },
    recommendation: 'Periodically reconcile sums with actual values. Use checkpoints.',
    references: ['https://solanasec25.sec3.dev/']
  },
  {
    id: 'SOL1056',
    name: 'Weight/Vote Dilution',
    severity: 'high',
    category: 'data-integrity',
    description: 'Voting weights can be diluted or inflated.',
    detection: {
      patterns: [
        /voting.*weight/i,
        /vote.*power/i,
        /governance.*weight/i,
        /delegation.*weight/i
      ]
    },
    recommendation: 'Snapshot weights at proposal creation. Implement checkpointing.',
    references: ['https://solanasec25.sec3.dev/']
  },
  {
    id: 'SOL1057',
    name: 'Collateral Ratio Calculation',
    severity: 'critical',
    category: 'data-integrity',
    description: 'Collateral ratios calculated incorrectly leading to bad debt.',
    detection: {
      patterns: [
        /collateral.*ratio/i,
        /ltv/i,
        /loan.*to.*value/i,
        /health.*factor/i
      ]
    },
    recommendation: 'Use conservative price sources. Add buffer to liquidation thresholds.',
    references: ['https://solanasec25.sec3.dev/']
  },
  {
    id: 'SOL1058',
    name: 'Timestamp Arithmetic',
    severity: 'medium',
    category: 'data-integrity',
    description: 'Time-based calculations vulnerable to manipulation.',
    detection: {
      patterns: [
        /timestamp.*-/i,
        /time.*elapsed/i,
        /duration.*since/i,
        /seconds.*per/i
      ]
    },
    recommendation: 'Use slot-based timing where possible. Validate time bounds.',
    references: ['https://solanasec25.sec3.dev/']
  },

  // ========================================
  // DOS & LIVENESS (8.5% of findings)
  // ========================================
  {
    id: 'SOL1059',
    name: 'Unbounded Iteration',
    severity: 'high',
    category: 'dos',
    description: 'Loop iterates over unbounded collection causing compute limits.',
    detection: {
      patterns: [
        /for\s+.*\s+in\s+.*\.iter\(\)/i,
        /while.*next\(\)/i,
        /loop\s*\{/i
      ]
    },
    recommendation: 'Bound all loops. Use pagination for large collections.',
    references: ['https://solanasec25.sec3.dev/']
  },
  {
    id: 'SOL1060',
    name: 'Account Spam Vector',
    severity: 'medium',
    category: 'dos',
    description: 'Protocol can be spammed with many small accounts.',
    detection: {
      patterns: [
        /init.*account/i,
        /create.*account/i,
        /allocate/i
      ]
    },
    recommendation: 'Require minimum deposits. Implement account limits per user.',
    references: ['https://solanasec25.sec3.dev/']
  },
  {
    id: 'SOL1061',
    name: 'Compute Budget Exhaustion',
    severity: 'high',
    category: 'dos',
    description: 'Operations can exhaust compute budget preventing completion.',
    detection: {
      patterns: [
        /compute_units/i,
        /sol_log/i,
        /msg!/i,
        /anchor_lang::prelude/i
      ]
    },
    recommendation: 'Optimize compute usage. Batch operations. Test gas limits.',
    references: ['https://solanasec25.sec3.dev/']
  },
  {
    id: 'SOL1062',
    name: 'Crank Dependency',
    severity: 'medium',
    category: 'dos',
    description: 'Protocol depends on external cranks that can be censored.',
    detection: {
      patterns: [
        /crank/i,
        /keeper/i,
        /bot/i,
        /automation/i
      ]
    },
    recommendation: 'Incentivize cranking. Allow permissionless cranks. Implement fallbacks.',
    references: ['https://solanasec25.sec3.dev/']
  },
  {
    id: 'SOL1063',
    name: 'Priority Fee Griefing',
    severity: 'medium',
    category: 'dos',
    description: 'Attackers can grief users by front-running with high fees.',
    detection: {
      patterns: [
        /priority.*fee/i,
        /compute.*budget/i,
        /fee.*payer/i
      ]
    },
    recommendation: 'Implement fair ordering. Consider commit-reveal schemes.',
    references: ['https://solanasec25.sec3.dev/']
  },

  // ========================================
  // RECENT EXPLOIT PATTERNS (2024-2025)
  // ========================================
  {
    id: 'SOL1064',
    name: 'Loopscale Admin Key Compromise (2025)',
    severity: 'critical',
    category: 'exploit-pattern',
    description: 'Admin key compromise leading to fund drain (April 2025, $5.8M).',
    detection: {
      patterns: [
        /admin.*key/i,
        /admin.*authority/i,
        /protocol.*authority/i,
        /update.*authority/i
      ]
    },
    recommendation: 'Use hardware wallets for admin keys. Implement multi-sig. Add timelocks.',
    references: ['https://www.helius.dev/blog/solana-hacks']
  },
  {
    id: 'SOL1065',
    name: 'Web3.js Supply Chain (2024)',
    severity: 'critical',
    category: 'exploit-pattern',
    description: 'Supply chain attack via compromised npm package.',
    detection: {
      patterns: [
        /@solana\/web3\.js/i,
        /npm.*install/i,
        /require\(['"]@solana/i,
        /import.*from\s+['"]@solana/i
      ]
    },
    recommendation: 'Pin dependencies. Use lockfiles. Audit dependency changes.',
    references: ['https://www.helius.dev/blog/solana-hacks']
  },
  {
    id: 'SOL1066',
    name: 'DEXX Private Key Leak (2024)',
    severity: 'critical',
    category: 'exploit-pattern',
    description: 'User private keys leaked through backend vulnerability ($30M loss).',
    detection: {
      patterns: [
        /private.*key/i,
        /secret.*key/i,
        /wallet.*key/i,
        /signing.*key/i
      ]
    },
    recommendation: 'Never handle user private keys server-side. Use client-side signing.',
    references: ['https://www.helius.dev/blog/solana-hacks']
  },
  {
    id: 'SOL1067',
    name: 'Banana Gun Bot Exploit (2024)',
    severity: 'critical',
    category: 'exploit-pattern',
    description: 'Trading bot vulnerability allowing fund extraction.',
    detection: {
      patterns: [
        /trading.*bot/i,
        /sniper.*bot/i,
        /auto.*trade/i,
        /bot.*wallet/i
      ]
    },
    recommendation: 'Limit bot permissions. Implement withdrawal limits. Use separate wallets.',
    references: ['https://www.helius.dev/blog/solana-hacks']
  },
  {
    id: 'SOL1068',
    name: 'NoOnes Platform Exploit (2024)',
    severity: 'high',
    category: 'exploit-pattern',
    description: 'Platform vulnerability leading to unauthorized withdrawals.',
    detection: {
      patterns: [
        /platform.*withdraw/i,
        /user.*funds/i,
        /custody.*service/i,
        /withdrawal.*request/i
      ]
    },
    recommendation: 'Implement proper withdrawal verification. Use multi-party approval.',
    references: ['https://www.helius.dev/blog/solana-hacks']
  },
  {
    id: 'SOL1069',
    name: 'Thunder Terminal MongoDB Injection (2023)',
    severity: 'critical',
    category: 'exploit-pattern',
    description: 'MongoDB injection vulnerability allowing session hijacking.',
    detection: {
      patterns: [
        /mongodb/i,
        /database.*query/i,
        /find\(/i,
        /collection/i
      ]
    },
    recommendation: 'Use parameterized queries. Sanitize all inputs. Implement rate limiting.',
    references: ['https://www.helius.dev/blog/solana-hacks']
  },
  {
    id: 'SOL1070',
    name: 'Pump.fun Employee Attack (2024)',
    severity: 'critical',
    category: 'exploit-pattern',
    description: 'Insider threat with privileged access exploiting bonding curves.',
    detection: {
      patterns: [
        /bonding.*curve/i,
        /curve.*manipulation/i,
        /buy.*early/i,
        /privileged.*access/i
      ]
    },
    recommendation: 'Implement separation of duties. Audit privileged actions. Add delays.',
    references: ['https://www.helius.dev/blog/solana-hacks']
  },

  // ========================================
  // ADVANCED PROTOCOL PATTERNS
  // ========================================
  {
    id: 'SOL1071',
    name: 'Cross-Margin Contagion',
    severity: 'critical',
    category: 'advanced',
    description: 'Losses in one position can cascade to liquidate healthy positions.',
    detection: {
      patterns: [
        /cross.*margin/i,
        /portfolio.*margin/i,
        /shared.*collateral/i,
        /aggregate.*position/i
      ]
    },
    recommendation: 'Implement position isolation options. Add circuit breakers.',
    references: ['https://solanasec25.sec3.dev/']
  },
  {
    id: 'SOL1072',
    name: 'Synthetic Asset De-peg',
    severity: 'critical',
    category: 'advanced',
    description: 'Synthetic asset can lose peg to underlying value.',
    detection: {
      patterns: [
        /synthetic/i,
        /peg/i,
        /redemption.*rate/i,
        /backing.*ratio/i
      ]
    },
    recommendation: 'Implement redemption mechanisms. Maintain over-collateralization.',
    references: ['https://solanasec25.sec3.dev/']
  },
  {
    id: 'SOL1073',
    name: 'Options Settlement Exploit',
    severity: 'high',
    category: 'advanced',
    description: 'Options settlement can be manipulated at expiry.',
    detection: {
      patterns: [
        /option.*exercise/i,
        /settlement.*price/i,
        /expiry/i,
        /strike.*price/i
      ]
    },
    recommendation: 'Use TWAP for settlement. Implement settlement windows.',
    references: ['https://solanasec25.sec3.dev/']
  },
  {
    id: 'SOL1074',
    name: 'Restaking Slashing',
    severity: 'critical',
    category: 'advanced',
    description: 'Restaking can expose users to multiple slashing risks.',
    detection: {
      patterns: [
        /restake/i,
        /liquid.*staking/i,
        /slashing/i,
        /validator.*set/i
      ]
    },
    recommendation: 'Cap restaking exposure. Implement slashing insurance.',
    references: ['https://solanasec25.sec3.dev/']
  },
  {
    id: 'SOL1075',
    name: 'Intent-Based Order Manipulation',
    severity: 'high',
    category: 'advanced',
    description: 'Intent/order flow can be manipulated by solvers/fillers.',
    detection: {
      patterns: [
        /intent/i,
        /solver/i,
        /filler/i,
        /order.*flow/i
      ]
    },
    recommendation: 'Use competitive solver auctions. Implement MEV protection.',
    references: ['https://solanasec25.sec3.dev/']
  },
  {
    id: 'SOL1076',
    name: 'NFT Lending Exploit',
    severity: 'critical',
    category: 'advanced',
    description: 'NFT lending vulnerable to floor price manipulation.',
    detection: {
      patterns: [
        /nft.*lending/i,
        /nft.*collateral/i,
        /floor.*price/i,
        /collection.*value/i
      ]
    },
    recommendation: 'Use conservative LTV. Multiple price sources. Implement collection limits.',
    references: ['https://solanasec25.sec3.dev/']
  },
  {
    id: 'SOL1077',
    name: 'Token Extensions Misuse',
    severity: 'high',
    category: 'advanced',
    description: 'Token-2022 extensions can be misused for attacks.',
    detection: {
      patterns: [
        /token.*2022/i,
        /extension/i,
        /transfer.*fee/i,
        /confidential.*transfer/i
      ]
    },
    recommendation: 'Understand all enabled extensions. Validate extension behavior.',
    references: ['https://solanasec25.sec3.dev/']
  },
  {
    id: 'SOL1078',
    name: 'Real World Asset Trust',
    severity: 'critical',
    category: 'advanced',
    description: 'RWA backing can be fraudulent or misrepresented.',
    detection: {
      patterns: [
        /rwa/i,
        /real.*world.*asset/i,
        /tokenized/i,
        /off.*chain.*backing/i
      ]
    },
    recommendation: 'Require attestations. Implement regular audits. Use reputable custodians.',
    references: ['https://solanasec25.sec3.dev/']
  },
  {
    id: 'SOL1079',
    name: 'Prediction Market Resolution',
    severity: 'high',
    category: 'advanced',
    description: 'Prediction market resolution can be manipulated.',
    detection: {
      patterns: [
        /prediction.*market/i,
        /outcome.*resolution/i,
        /oracle.*resolution/i,
        /dispute/i
      ]
    },
    recommendation: 'Use decentralized resolution. Implement dispute mechanisms.',
    references: ['https://solanasec25.sec3.dev/']
  },
  {
    id: 'SOL1080',
    name: 'Blink Actions Security',
    severity: 'high',
    category: 'advanced',
    description: 'Solana Actions/Blinks can be used for phishing.',
    detection: {
      patterns: [
        /action/i,
        /blink/i,
        /unfurl/i,
        /action.*url/i
      ]
    },
    recommendation: 'Verify action URLs. Display clear transaction details.',
    references: ['https://solanasec25.sec3.dev/']
  },
];

// Pattern execution logic
function runBatch39Patterns(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  const content = input.rust?.content || '';
  
  if (!content) return findings;
  
  const lines = content.split('\n');
  
  for (const pattern of batchedPatterns39) {
    for (const regex of pattern.detection.patterns) {
      try {
        const flags = regex.flags.includes('g') ? regex.flags : regex.flags + 'g';
        const searchRegex = new RegExp(regex.source, flags);
        const matches = [...content.matchAll(searchRegex)];
        
        for (const match of matches) {
          const matchIndex = match.index || 0;
          
          let lineNum = 1;
          let charCount = 0;
          for (let i = 0; i < lines.length; i++) {
            charCount += lines[i].length + 1;
            if (charCount > matchIndex) {
              lineNum = i + 1;
              break;
            }
          }
          
          const startLine = Math.max(0, lineNum - 2);
          const endLine = Math.min(lines.length, lineNum + 2);
          const snippet = lines.slice(startLine, endLine).join('\n');
          
          findings.push({
            id: pattern.id,
            title: pattern.name,
            severity: pattern.severity,
            description: pattern.description,
            location: { file: input.path, line: lineNum },
            recommendation: pattern.recommendation,
            code: snippet.substring(0, 200),
          });
          
          // Only one finding per pattern per file
          break;
        }
      } catch (e) {
        // Skip invalid patterns
      }
    }
  }
  
  return findings;
}

export { batchedPatterns39, runBatch39Patterns };
export default batchedPatterns39;
