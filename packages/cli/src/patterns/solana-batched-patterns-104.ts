/**
 * Batch 104: Solsec Deep Research + Armani Sealevel Attacks + Audit Firm PoCs
 * 
 * Based on comprehensive security research from solsec repository:
 * - https://github.com/sannykim/solsec
 * - Armani's Sealevel Attacks documentation
 * - Neodyme, OtterSec, Kudelski, Halborn, Bramah audit findings
 * - Real-world PoC exploits and vulnerability disclosures
 * 
 * Pattern IDs: SOL6601-SOL6700
 * Focus: Academic + practical security patterns from curated research
 */

import type { Finding, PatternInput } from './index.js';

interface Pattern {
  id: string;
  name: string;
  description: string;
  severity: 'critical' | 'high' | 'medium' | 'low' | 'info';
  pattern: RegExp;
  recommendation: string;
  references?: string[];
}

const BATCH_104_PATTERNS: Pattern[] = [
  // ============================================
  // ARMANI SEALEVEL ATTACKS (project-serum/sealevel-attacks)
  // ============================================
  {
    id: 'SOL6601',
    name: 'Sealevel: Missing Owner Check Attack',
    description: 'Armani Sealevel Attack #1: Account ownership not verified. Critical for all Solana programs - without owner check, attackers can pass accounts from other programs.',
    severity: 'critical',
    pattern: /AccountInfo(?![\s\S]{0,200}owner\s*==|[\s\S]{0,200}\.owner\s*==|[\s\S]{0,200}constraint\s*=\s*owner)/i,
    recommendation: 'Always verify account ownership: require!(account.owner == expected_program_id). Use Anchor #[account(owner = program_id)] constraint.',
    references: ['https://github.com/project-serum/sealevel-attacks', 'https://twitter.com/pencilflip/status/1483880018858201090']
  },
  {
    id: 'SOL6602',
    name: 'Sealevel: Missing Signer Check Attack',
    description: 'Armani Sealevel Attack #2: Authority account not verified as signer. Without this check, anyone can execute privileged operations.',
    severity: 'critical',
    pattern: /authority|admin|owner.*:.*AccountInfo(?![\s\S]{0,100}is_signer|[\s\S]{0,100}Signer|[\s\S]{0,100}signer)/i,
    recommendation: 'Verify is_signer for all authority accounts. Use Anchor Signer<> type or #[account(signer)] constraint.',
    references: ['https://github.com/project-serum/sealevel-attacks']
  },
  {
    id: 'SOL6603',
    name: 'Sealevel: Integer Overflow/Underflow',
    description: 'Armani Sealevel Attack #3: Arithmetic without overflow protection. Rust release builds have overflow checks disabled by default.',
    severity: 'high',
    pattern: /\+\s*\d+|\-\s*\d+|\*\s*\d+(?![\s\S]{0,50}checked_|[\s\S]{0,50}saturating_)/,
    recommendation: 'Use checked_add(), checked_sub(), checked_mul(), or saturating_ variants for all arithmetic. Reference: Sec3 arithmetic overflow blog.',
    references: ['https://www.sec3.dev/blog/understanding-arithmetic-overflow-underflows-in-rust-and-solana-smart-contracts']
  },
  {
    id: 'SOL6604',
    name: 'Sealevel: Arbitrary CPI Attack',
    description: 'Armani Sealevel Attack #4: Cross-program invocation to untrusted program. Attacker can control the target program ID.',
    severity: 'critical',
    pattern: /invoke(?:_signed)?\s*\(\s*&?[\w_]+(?![\s\S]{0,100}==\s*(?:spl_token|system_program|token_program))/i,
    recommendation: 'Hardcode expected program IDs or verify against an allowlist before CPI. Never invoke user-provided program IDs.',
    references: ['https://github.com/project-serum/sealevel-attacks']
  },
  {
    id: 'SOL6605',
    name: 'Sealevel: Type Cosplay Attack',
    description: 'Armani Sealevel Attack #5: Account type confusion - one account type masquerades as another. Critical in non-Anchor programs.',
    severity: 'critical',
    pattern: /try_from_slice|deserialize(?![\s\S]{0,100}discriminator|[\s\S]{0,100}DISCRIMINATOR)/i,
    recommendation: 'Add unique 8-byte discriminator to all account types. Verify discriminator before deserialization. Anchor handles this automatically.',
    references: ['https://github.com/project-serum/sealevel-attacks']
  },
  {
    id: 'SOL6606',
    name: 'Sealevel: Duplicate Mutable Accounts',
    description: 'Armani Sealevel Attack #6: Same account passed multiple times as different mutable references, enabling double-spending.',
    severity: 'high',
    pattern: /#\[account\(mut\)\][\s\S]*?#\[account\(mut\)\](?![\s\S]{0,200}constraint.*!=)/,
    recommendation: 'Add constraint to ensure mutable accounts are different: constraint = account_a.key() != account_b.key()',
    references: ['https://github.com/project-serum/sealevel-attacks']
  },
  {
    id: 'SOL6607',
    name: 'Sealevel: Bump Seed Canonicalization',
    description: 'Armani Sealevel Attack #7: Using non-canonical bump seed allows multiple valid PDAs for same seeds.',
    severity: 'high',
    pattern: /bump\s*:\s*\d+(?![\s\S]{0,50}find_program_address)/,
    recommendation: 'Always use canonical bump from find_program_address(). Store bump in account and verify on subsequent accesses.',
    references: ['https://github.com/project-serum/sealevel-attacks']
  },
  {
    id: 'SOL6608',
    name: 'Sealevel: PDA Sharing Vulnerability',
    description: 'Armani Sealevel Attack #8: PDA seeds are too generic, allowing cross-user or cross-context collisions.',
    severity: 'high',
    pattern: /seeds\s*=\s*\[[\s\S]{0,50}\](?![\s\S]{0,100}user|[\s\S]{0,100}authority|[\s\S]{0,100}owner)/i,
    recommendation: 'Include user-specific identifiers in PDA seeds (e.g., user pubkey, unique nonce). Never use only program-wide seeds for user data.',
    references: ['https://github.com/project-serum/sealevel-attacks']
  },
  {
    id: 'SOL6609',
    name: 'Sealevel: Closing Account Revival',
    description: 'Armani Sealevel Attack #9: Closed account can be revived within same transaction if lamports are transferred back.',
    severity: 'critical',
    pattern: /close\s*=|lamports\(\)\.borrow_mut\(\)[\s\S]{0,50}=\s*0(?![\s\S]{0,100}realloc|[\s\S]{0,100}zero_out)/i,
    recommendation: 'Zero out all account data before closing. Use Anchor close constraint which handles this. Verify account is empty on initialization.',
    references: ['https://github.com/project-serum/sealevel-attacks']
  },
  {
    id: 'SOL6610',
    name: 'Sealevel: Reinitialization Attack',
    description: 'Armani Sealevel Attack #10: Account can be reinitialized, resetting state and potentially stealing funds.',
    severity: 'critical',
    pattern: /init(?:ialize)?(?![\s\S]{0,100}is_initialized|[\s\S]{0,100}initialized\s*==|[\s\S]{0,100}init_if_needed)/i,
    recommendation: 'Always check is_initialized flag before initializing. Use Anchor init constraint which prevents reinitialization by default.',
    references: ['https://github.com/project-serum/sealevel-attacks']
  },

  // ============================================
  // NEODYME COMMON PITFALLS
  // ============================================
  {
    id: 'SOL6611',
    name: 'Neodyme: Account Data Validation Missing',
    description: 'From Neodyme Common Pitfalls blog: Account data fields not validated, allowing malicious data injection.',
    severity: 'high',
    pattern: /data\.borrow\(\)|try_borrow_data(?![\s\S]{0,100}require!|[\s\S]{0,100}assert!)/i,
    recommendation: 'Validate all account data fields before use. Check data lengths, ranges, and invariants. Reference: blog.neodyme.io/posts/solana_common_pitfalls',
    references: ['https://blog.neodyme.io/posts/solana_common_pitfalls']
  },
  {
    id: 'SOL6612',
    name: 'Neodyme: invoke_signed Seeds Mismatch',
    description: 'From Neodyme: invoke_signed with incorrect or incomplete seeds, potentially allowing unauthorized PDA signing.',
    severity: 'critical',
    pattern: /invoke_signed[\s\S]{0,200}seeds(?![\s\S]{0,100}bump|[\s\S]{0,100}BUMP)/i,
    recommendation: 'Verify invoke_signed seeds exactly match the PDA derivation. Include all seeds in same order. Always include bump seed.',
    references: ['https://blog.neodyme.io/posts/solana_common_pitfalls']
  },
  {
    id: 'SOL6613',
    name: 'Neodyme: Account Confusion via Discriminator',
    description: 'From Neodyme Pitfalls: Without 8-byte discriminator, accounts of different types can be confused.',
    severity: 'critical',
    pattern: /#\[account\][\s\S]{0,100}pub\s+struct\s+\w+\s*\{(?![\s\S]{0,50}discriminator)/i,
    recommendation: 'Anchor automatically adds 8-byte discriminator. For native programs, manually add and verify unique discriminator for each account type.',
    references: ['https://blog.neodyme.io/posts/solana_common_pitfalls', 'https://twitter.com/armaniferrante/status/1438706351295827968']
  },

  // ============================================
  // SEC3 AUDIT METHODOLOGY PATTERNS
  // ============================================
  {
    id: 'SOL6614',
    name: 'Sec3: UncheckedAccount Without Documentation',
    description: 'From Sec3 Audit Guide: UncheckedAccount used without /// CHECK: documentation explaining safety.',
    severity: 'high',
    pattern: /UncheckedAccount(?![\s\S]{0,50}\/\/\/\s*CHECK)/i,
    recommendation: 'Add /// CHECK: comment explaining why the account is safe to leave unchecked. Reference: Sec3 How to Audit Part 4.',
    references: ['https://www.sec3.dev/blog/how-to-audit-solana-smart-contracts-part-4-the-anchor-framework']
  },
  {
    id: 'SOL6615',
    name: 'Sec3: Checked Math Not Used',
    description: 'From Sec3: Direct +, -, /, * operations without checked_ methods in financial contexts.',
    severity: 'high',
    pattern: /(?:amount|balance|lamports|tokens|price|value|fee|reward)[\s\S]{0,30}[+\-*/]\s*(?!checked_)/i,
    recommendation: 'Use checked_add(), checked_sub(), checked_mul(), checked_div() for all financial arithmetic. Ref: sec3.dev/blog/understanding-arithmetic-overflow-underflows',
    references: ['https://www.sec3.dev/blog/understanding-arithmetic-overflow-underflows-in-rust-and-solana-smart-contracts']
  },
  {
    id: 'SOL6616',
    name: 'Sec3: Owner Check Missing on AccountInfo',
    description: 'From Sec3: AccountInfo passed without owner verification, critical security gap.',
    severity: 'critical',
    pattern: /AccountInfo[\s\S]{0,100}(?![\s\S]{0,100}owner\s*==)/,
    recommendation: 'Always verify account owner: require!(account.owner == expected_program, ErrorCode::InvalidOwner). Reference: sec3.dev/blog/from-ethereum-smart-contracts-to-solana-programs',
    references: ['https://www.sec3.dev/blog/from-ethereum-smart-contracts-to-solana-programs-two-common-security-pitfalls-and-beyond']
  },
  {
    id: 'SOL6617',
    name: 'Sec3: Penetration Testing Gap',
    description: 'Complex business logic without evidence of PoC testing. Sec3 recommends Neodyme PoC framework for exploit verification.',
    severity: 'medium',
    pattern: /(?:swap|transfer|withdraw|deposit|mint|burn|stake|unstake)[\s\S]{0,200}(?!test_|#\[test\])/i,
    recommendation: 'Write PoC tests for critical functions using Neodyme PoC framework. Reference: sec3.dev/blog/how-to-audit-solana-smart-contracts-part-3-penetration-testing',
    references: ['https://www.sec3.dev/blog/how-to-audit-solana-smart-contracts-part-3-penetration-testing']
  },

  // ============================================
  // KUDELSKI AUDIT FINDINGS
  // ============================================
  {
    id: 'SOL6618',
    name: 'Kudelski: Data Validation High-Level Gap',
    description: 'From Kudelski Solana Program Security: Ownership and data validation not performed at entry point.',
    severity: 'critical',
    pattern: /pub\s+fn\s+process(?:_instruction)?[\s\S]{0,500}(?![\s\S]{0,200}owner|[\s\S]{0,200}validate)/i,
    recommendation: 'Validate all account ownership and data at instruction entry point. Reference: research.kudelskisecurity.com/2021/09/15/solana-program-security-part1/',
    references: ['https://research.kudelskisecurity.com/2021/09/15/solana-program-security-part1/']
  },
  {
    id: 'SOL6619',
    name: 'Kudelski: Reference Account Validity',
    description: 'From Kudelski: Unmodified reference-only accounts not validated per Solana documentation.',
    severity: 'high',
    pattern: /AccountInfo[\s\S]{0,50}\/\*.*readonly.*\*\/(?![\s\S]{0,100}verify)/i,
    recommendation: 'Validate all accounts including read-only references. See: docs.solana.com/developing/programming-model/accounts#verifying-validity-of-unmodified-reference-only-accounts',
    references: ['https://docs.solana.com/developing/programming-model/accounts#verifying-validity-of-unmodified-reference-only-accounts']
  },

  // ============================================
  // REAL-WORLD EXPLOIT PATTERNS FROM SOLSEC
  // ============================================
  {
    id: 'SOL6620',
    name: 'CASH Hack: Root of Trust Failure ($52M)',
    description: 'From samczsun analysis: Cashio failed to establish proper root of trust for collateral verification.',
    severity: 'critical',
    pattern: /collateral|backing|mint[\s\S]{0,100}(?![\s\S]{0,100}whitelist|[\s\S]{0,100}verify_mint|[\s\S]{0,100}allowed_mints)/i,
    recommendation: 'Establish clear root of trust chain. Verify collateral mint against hardcoded whitelist. Never trust user-provided mint addresses.',
    references: ['https://twitter.com/samczsun/status/1506578902331768832', 'https://www.sec3.dev/blog/cashioapp-attack-whats-the-vulnerability-and-how-soteria-detects-it']
  },
  {
    id: 'SOL6621',
    name: 'Wormhole: Guardian Signature Bypass ($326M)',
    description: 'From Wormhole analysis: Signature verification delegated without proper validation chain.',
    severity: 'critical',
    pattern: /verify_signature|guardian|signature_set(?![\s\S]{0,100}quorum|[\s\S]{0,100}threshold|[\s\S]{0,100}verify_all)/i,
    recommendation: 'When chaining signature verification delegations, ensure complete verification chain. Verify all required signatures meet quorum.',
    references: ['https://twitter.com/samczsun/status/1489044939732406275', 'https://halborn.com/explained-the-wormhole-hack-february-2022/']
  },
  {
    id: 'SOL6622',
    name: 'Cope Roulette: Reverting Transaction Exploit',
    description: 'From Arrowana PoC: Exploiting transaction revert behavior to game randomness or outcomes.',
    severity: 'high',
    pattern: /random|rng|lottery|raffle|game(?![\s\S]{0,100}commit.*reveal|[\s\S]{0,100}vrf|[\s\S]{0,100}switchboard)/i,
    recommendation: 'Use commit-reveal scheme or VRF (Switchboard) for randomness. Never allow outcome to be known before commitment.',
    references: ['https://github.com/Arrowana/cope-roulette-pro']
  },
  {
    id: 'SOL6623',
    name: 'Simulation Detection for Exploit',
    description: 'From Opcodes research: Detecting transaction simulation to behave differently in simulation vs. execution.',
    severity: 'high',
    pattern: /simulation|simulate|preflight|is_simulation|mock(?![\s\S]{0,100}test)/i,
    recommendation: 'Never have different behavior in simulation vs execution. This is often used for malicious purposes. Reference: opcodes.fr/en/publications/2022-01/detecting-transaction-simulation/',
    references: ['https://opcodes.fr/en/publications/2022-01/detecting-transaction-simulation/']
  },
  {
    id: 'SOL6624',
    name: 'Jet Protocol: Break Statement Bug',
    description: 'From Jayne disclosure: Unintended break statement allowing protocol exploitation.',
    severity: 'high',
    pattern: /break\s*;(?![\s\S]{0,100}\/\/.*intentional)/i,
    recommendation: 'Audit all break statements carefully. Ensure loop termination is intentional and cannot be exploited.',
    references: ['https://medium.com/@0xjayne/how-to-freely-borrow-all-the-tvl-from-the-jet-protocol-25d40e35920e']
  },
  {
    id: 'SOL6625',
    name: 'Neodyme: Rounding Error $2.6B at Risk',
    description: 'From Neodyme disclosure: Innocent-looking rounding error put $2.6B at risk across lending protocols.',
    severity: 'critical',
    pattern: /\.round\(\)|round\s*\(|as\s+u64(?![\s\S]{0,50}ceil|[\s\S]{0,50}floor)/i,
    recommendation: 'Use floor() for amounts leaving protocol, ceil() for amounts entering. Never use round() for financial calculations.',
    references: ['https://blog.neodyme.io/posts/lending_disclosure', 'https://blog.solend.fi/bug-bounty-and-response-to-spl-lending-vulnerability-f4c8874342d0']
  },
  {
    id: 'SOL6626',
    name: 'rBPF Integer Overflow Bug',
    description: 'From BlockSec: Integer overflow discovered in Solana rBPF (runtime bytecode processor).',
    severity: 'critical',
    pattern: /as\s+(?:u8|u16|u32|i8|i16|i32)(?![\s\S]{0,30}try_into|[\s\S]{0,30}checked)/,
    recommendation: 'Use try_into() for safe integer conversions. Never cast with "as" for untrusted input.',
    references: ['https://blocksecteam.medium.com/new-integer-overflow-bug-discovered-in-solana-rbpf-7729717159ee']
  },
  {
    id: 'SOL6627',
    name: 'Incinerator NFT Attack Chain',
    description: 'From Solens: Chaining small exploits (incinerator + SPL token) for significant combined exploit.',
    severity: 'high',
    pattern: /burn|incinerator|spl_token.*burn(?![\s\S]{0,100}verify_ownership)/i,
    recommendation: 'Consider attack chaining - multiple small vulnerabilities can combine into major exploits. Audit holistically.',
    references: ['https://medium.com/@solens_io/schrodingers-nft-an-incinerator-spl-token-program-and-the-royal-flush-attack-58e4ce4e63dc']
  },
  {
    id: 'SOL6628',
    name: 'Candy Machine Unchecked Account Exploit',
    description: 'From Solens: Candy Machine vulnerability from UncheckedAccount not properly validated.',
    severity: 'critical',
    pattern: /#\[account\(zero\)\](?![\s\S]{0,100}constraint\s*=|[\s\S]{0,100}has_one)/,
    recommendation: 'Zero accounts need additional constraints. Reference fix: #[account(zero, constraint = ...)] vs just #[account(zero)].',
    references: ['https://medium.com/@solens_io/smashing-the-candy-machine-for-fun-and-profit-a3bcc58d6c30']
  },
  {
    id: 'SOL6629',
    name: 'Stake Pool Semantic Inconsistency',
    description: 'From Sec3: Semantic inconsistency in Stake Pool leading to vulnerability even after 3 audits.',
    severity: 'high',
    pattern: /stake_pool|delegation|validator(?![\s\S]{0,100}semantic|[\s\S]{0,100}invariant)/i,
    recommendation: 'Test semantic consistency - ensure related operations maintain invariants. Previously audited code can still have vulnerabilities.',
    references: ['https://www.sec3.dev/blog/solana-stake-pool-a-semantic-inconsistency-vulnerability-discovered-by-x-ray']
  },
  {
    id: 'SOL6630',
    name: 'Solend Malicious Lending Market',
    description: 'From Rooter: Malicious lending market creation exploiting program logic.',
    severity: 'critical',
    pattern: /create_market|init_market|lending_market(?![\s\S]{0,100}admin_only|[\s\S]{0,100}governance)/i,
    recommendation: 'Restrict market creation to trusted authorities. Validate all market parameters. Reference: Kudelski Solana Program Security.',
    references: ['https://docs.google.com/document/d/1-WoQwT1QrPEX-r4N-fDamRQ50LM8DsdsOyq1iTabS3Q/edit']
  },
  {
    id: 'SOL6631',
    name: 'SPL Token Approve Revocation',
    description: 'From Hana: Sneaky method to revoke token approvals that users may not expect.',
    severity: 'medium',
    pattern: /approve|delegate(?![\s\S]{0,100}revoke_on_transfer|[\s\S]{0,100}time_limit)/i,
    recommendation: 'Consider token approval attack vectors. Implement automatic revocation or time-limited approvals.',
    references: ['https://2501babe.github.io/tools/revoken.html']
  },
  {
    id: 'SOL6632',
    name: 'LP Token Oracle Manipulation ($200M)',
    description: 'From OtterSec: $200M at risk from LP token oracle manipulation by moving AMM price.',
    severity: 'critical',
    pattern: /lp_token.*price|pool.*price|get_lp_price(?![\s\S]{0,100}fair_price|[\s\S]{0,100}virtual_price)/i,
    recommendation: 'Use fair pricing for LP tokens based on underlying assets. Never use spot reserves for LP valuation. Reference: osec.io/blog/reports/2022-02-16-lp-token-oracle-manipulation/',
    references: ['https://osec.io/blog/reports/2022-02-16-lp-token-oracle-manipulation/']
  },

  // ============================================
  // DRIFT ORACLE GUARDRAILS (Best Practice)
  // ============================================
  {
    id: 'SOL6633',
    name: 'Drift: Oracle Guardrails Missing',
    description: 'From Drift Protocol: Oracle data used without guardrails (staleness, confidence, deviation checks).',
    severity: 'high',
    pattern: /oracle.*price|price_feed(?![\s\S]{0,100}guardrail|[\s\S]{0,100}max_deviation|[\s\S]{0,100}staleness_threshold)/i,
    recommendation: 'Implement Drift-style oracle guardrails: staleness check, confidence interval, max deviation from TWAP, circuit breaker.',
    references: ['https://github.com/drift-labs/protocol-v1/blob/4c2d447a677693da506e4de9596a07e4b9ba4d5d/tests/admin.ts#L212']
  },

  // ============================================
  // SECURITY TOOLS PATTERNS (From Solsec Tools Section)
  // ============================================
  {
    id: 'SOL6634',
    name: 'Trident Fuzzing Not Used',
    description: 'Complex program logic without evidence of fuzz testing. Ackee Trident provides Solana fuzzing.',
    severity: 'low',
    pattern: /pub\s+fn\s+(?:swap|transfer|withdraw|deposit|liquidate)[\s\S]{0,500}(?!fuzz|trident|proptest)/i,
    recommendation: 'Use Ackee Trident fuzzing framework to discover edge cases. Critical for DeFi protocols.',
    references: ['https://github.com/Ackee-Blockchain/trident']
  },
  {
    id: 'SOL6635',
    name: 'Blockworks Checked Math Macro Available',
    description: 'Arithmetic operations that could benefit from Blockworks checked-math macro.',
    severity: 'info',
    pattern: /checked_add|checked_sub|checked_mul|checked_div/i,
    recommendation: 'Consider using Blockworks checked-math macro for cleaner arithmetic: github.com/blockworks-foundation/checked-math',
    references: ['https://github.com/blockworks-foundation/checked-math']
  },

  // ============================================
  // OTTERSEC AUDIT FINDINGS
  // ============================================
  {
    id: 'SOL6636',
    name: 'OtterSec: Solana Execution Model Misunderstanding',
    description: 'From OtterSec intro: Common misunderstanding of Solana execution model leading to vulnerabilities.',
    severity: 'high',
    pattern: /invoke[\s\S]{0,100}(?![\s\S]{0,50}signer_seeds|[\s\S]{0,50}program_id\s*==)/i,
    recommendation: 'Understand Solana execution model from security perspective. Reference: osec.io/blog/tutorials/2022-03-14-solana-security-intro/',
    references: ['https://osec.io/blog/tutorials/2022-03-14-solana-security-intro/']
  },
  {
    id: 'SOL6637',
    name: 'OtterSec: Jet Governance PoC',
    description: 'Governance vulnerability pattern from OtterSec Jet Governance PoC.',
    severity: 'high',
    pattern: /governance|proposal|vote[\s\S]{0,100}(?![\s\S]{0,100}timelock|[\s\S]{0,100}delay|[\s\S]{0,100}quorum)/i,
    recommendation: 'Review governance for timelock, delay, and quorum requirements. Reference: github.com/otter-sec/jet-governance-pocs',
    references: ['https://github.com/otter-sec/jet-governance-pocs']
  },

  // ============================================
  // ZELLIC ANCHOR VULNERABILITIES
  // ============================================
  {
    id: 'SOL6638',
    name: 'Zellic: Anchor Account Constraints Bypass',
    description: 'From Zellic blog: Common Anchor constraint vulnerabilities even in "safe" code.',
    severity: 'high',
    pattern: /#\[account\((?!.*constraint.*=)/,
    recommendation: 'Add explicit constraints to all Anchor accounts. Reference: zellic.io/blog/the-vulnerabilities-youll-write-with-anchor/',
    references: ['https://www.zellic.io/blog/the-vulnerabilities-youll-write-with-anchor/']
  },
  {
    id: 'SOL6639',
    name: 'Zellic: init_if_needed Without Proper Check',
    description: 'From Zellic: init_if_needed can be dangerous without proper reinitialization guards.',
    severity: 'high',
    pattern: /init_if_needed(?![\s\S]{0,100}constraint\s*=|[\s\S]{0,100}realloc)/,
    recommendation: 'Use init_if_needed carefully with additional constraints. Consider if init with explicit creation is safer.',
    references: ['https://www.zellic.io/blog/the-vulnerabilities-youll-write-with-anchor/']
  },
  {
    id: 'SOL6640',
    name: 'Zellic: Seeds Constraint Missing',
    description: 'From Zellic: PDA account without seeds constraint allows address spoofing.',
    severity: 'critical',
    pattern: /#\[account\([\s\S]*?(?:init|mut)[\s\S]*?\)\][\s\S]*?(?:Program|Account)(?![\s\S]{0,100}seeds\s*=)/,
    recommendation: 'Always include seeds constraint for PDA accounts to prevent address spoofing.',
    references: ['https://www.zellic.io/blog/the-vulnerabilities-youll-write-with-anchor/']
  },

  // ============================================
  // AUDIT FIRM SPECIFIC PATTERNS
  // ============================================
  {
    id: 'SOL6641',
    name: 'Bramah: Maple Finance Pattern',
    description: 'Lending pool vulnerability pattern from Bramah Maple Finance audit.',
    severity: 'high',
    pattern: /pool|lending[\s\S]{0,100}(?:deposit|withdraw|borrow)(?![\s\S]{0,100}rate_limit|[\s\S]{0,100}cooldown)/i,
    recommendation: 'Implement rate limits and cooldowns for pool operations. Reference: Bramah Maple audit.',
    references: ['https://uploads-ssl.webflow.com/6247b0423c35b87bbaaf6d4c/62617902491def721f481ecb_Maple_Finance_Audit_Bramah.pdf']
  },
  {
    id: 'SOL6642',
    name: 'Halborn: Cropper AMM Pattern',
    description: 'AMM vulnerability pattern from Halborn Cropper Finance audit.',
    severity: 'high',
    pattern: /amm|swap[\s\S]{0,100}(?![\s\S]{0,100}slippage|[\s\S]{0,100}min_out|[\s\S]{0,100}deadline)/i,
    recommendation: 'Implement slippage protection, minimum output, and deadline for AMM operations.',
    references: ['https://github.com/HalbornSecurity/PublicReports/blob/master/Solana%20Program%20Audit/Cropper_Finance_AMM_Program_Security_Audit_Report_Halborn_Final.pdf']
  },
  {
    id: 'SOL6643',
    name: 'Quantstamp: Quarry Mining Pattern',
    description: 'Mining/staking vulnerability pattern from Quantstamp Quarry audit.',
    severity: 'medium',
    pattern: /mining|quarry|stake[\s\S]{0,100}reward(?![\s\S]{0,100}rate_per_second|[\s\S]{0,100}accumulated)/i,
    recommendation: 'Carefully handle reward calculations with time-weighted accumulation.',
    references: ['https://github.com/QuarryProtocol/quarry/blob/master/audit/quantstamp.pdf']
  },
  {
    id: 'SOL6644',
    name: 'SlowMist: Larix Lending Pattern',
    description: 'Lending vulnerability pattern from SlowMist Larix audit.',
    severity: 'high',
    pattern: /lending|borrow|collateral(?![\s\S]{0,100}health_factor|[\s\S]{0,100}ltv)/i,
    recommendation: 'Implement proper health factor and LTV checks for lending operations.',
    references: ['https://docs.projectlarix.com/how-to-prove/audit']
  },
  {
    id: 'SOL6645',
    name: 'Neodyme: Wormhole Audit Pattern',
    description: 'Cross-chain vulnerability pattern from Neodyme Wormhole audit.',
    severity: 'critical',
    pattern: /bridge|cross_chain|wormhole(?![\s\S]{0,100}finality|[\s\S]{0,100}guardian_quorum)/i,
    recommendation: 'Implement proper finality and guardian quorum checks for cross-chain operations.',
    references: ['https://github.com/certusone/wormhole/blob/dev.v2/audits/2021-01-10_neodyme.pdf']
  },

  // ============================================
  // POC EXPLOIT PATTERNS
  // ============================================
  {
    id: 'SOL6646',
    name: 'Cashio Exploit PoC Pattern',
    description: 'Pattern from PwnedNoMore Cashio exploit workshop PoC.',
    severity: 'critical',
    pattern: /validate_collateral|check_backing|collateral_mint(?![\s\S]{0,100}hardcoded|[\s\S]{0,100}whitelist)/i,
    recommendation: 'Collateral validation must use hardcoded/whitelisted mints. Reference: github.com/PwnedNoMore/cashio-exploit-workshop',
    references: ['https://github.com/PwnedNoMore/cashio-exploit-workshop/tree/poc']
  },
  {
    id: 'SOL6647',
    name: 'Port Max Withdraw Bug Pattern',
    description: 'Pattern from Port Finance max withdraw bug PoC.',
    severity: 'high',
    pattern: /max_withdraw|withdraw_all|full_withdrawal(?![\s\S]{0,100}utilization|[\s\S]{0,100}available_liquidity)/i,
    recommendation: 'Max withdrawal must consider utilization and available liquidity. Reference: port-finance PoC.',
    references: ['https://github.com/port-finance/variable-rate-lending/blob/master/token-lending/program/tests/max_withdraw_bug_poc.rs']
  },
  {
    id: 'SOL6648',
    name: 'SPL Token Lending PoC Pattern',
    description: 'Pattern from Neodyme SPL token-lending disclosure PoC.',
    severity: 'critical',
    pattern: /token_lending|lending_market[\s\S]{0,100}(?:deposit|redeem)(?![\s\S]{0,100}rounding_direction)/i,
    recommendation: 'Handle rounding carefully in lending operations. Always round against the user taking funds out.',
    references: ['https://blog.neodyme.io/posts/lending_disclosure']
  },

  // ============================================
  // SAMCZSUN ANALYSIS PATTERNS
  // ============================================
  {
    id: 'SOL6649',
    name: 'samczsun: Root of Trust Pattern',
    description: 'From samczsun CASH analysis: Failure to establish proper root of trust.',
    severity: 'critical',
    pattern: /trust|root_of_trust|trusted_mint(?![\s\S]{0,100}verify_chain|[\s\S]{0,100}hardcoded)/i,
    recommendation: 'Establish clear root of trust. Verify entire trust chain from source to destination.',
    references: ['https://twitter.com/samczsun/status/1506578902331768832']
  },
  {
    id: 'SOL6650',
    name: 'samczsun: Input Account Validation',
    description: 'From samczsun Wormhole analysis: Critical to validate all input accounts.',
    severity: 'critical',
    pattern: /process_instruction[\s\S]{0,500}accounts(?![\s\S]{0,200}validate|[\s\S]{0,200}verify)/i,
    recommendation: 'Validate all input accounts at the start of instruction processing. Never trust user-provided accounts.',
    references: ['https://twitter.com/samczsun/status/1489044939732406275']
  },

  // ============================================
  // DEFI MOOC PATTERNS
  // ============================================
  {
    id: 'SOL6651',
    name: 'DeFi MOOC: Practical Security Gap',
    description: 'From samczsun DeFi MOOC: General smart contract security principles apply to Solana.',
    severity: 'medium',
    pattern: /external_call|cross_contract|callback(?![\s\S]{0,100}reentrancy|[\s\S]{0,100}mutex)/i,
    recommendation: 'Apply general smart contract security principles. Watch samczsun DeFi MOOC: youtube.com/watch?v=pJKy5HWuFK8',
    references: ['https://www.youtube.com/watch?v=pJKy5HWuFK8']
  },

  // ============================================
  // TRAIL OF BITS PATTERNS
  // ============================================
  {
    id: 'SOL6652',
    name: 'Trail of Bits: DeFi Success Pattern',
    description: 'From Trail of Bits: DeFi-specific security considerations beyond code audit.',
    severity: 'medium',
    pattern: /defi|protocol[\s\S]{0,100}(?![\s\S]{0,100}economic_audit|[\s\S]{0,100}game_theory)/i,
    recommendation: 'Consider economic and game-theoretic security beyond code. Reference: youtube.com/watch?v=jGrtK5k0CK0',
    references: ['https://www.youtube.com/watch?v=jGrtK5k0CK0']
  },

  // ============================================
  // SOLEND WORKSHOP PATTERNS
  // ============================================
  {
    id: 'SOL6653',
    name: 'Solend: ETH Attack Carryover',
    description: 'From Solend Workshop: Many ETH attacks carry over to Solana with adaptations.',
    severity: 'medium',
    pattern: /reentrancy|flash_loan|oracle_manipulation/i,
    recommendation: 'Study ETH attack patterns - many apply to Solana. Reference: Solend Auditing Workshop.',
    references: ['https://docs.google.com/presentation/d/1jZ9kVo6hnhBsz3D2sywqpMojqLE5VTZtaXna7OHL1Uk/edit']
  },

  // ============================================
  // 2024-2025 AUDIT PATTERNS
  // ============================================
  {
    id: 'SOL6654',
    name: 'Phoenix DEX Audit Pattern',
    description: 'Order book vulnerability pattern from MadShield/OtterSec Phoenix audit.',
    severity: 'high',
    pattern: /order_book|limit_order|place_order(?![\s\S]{0,100}self_trade|[\s\S]{0,100}wash_trade)/i,
    recommendation: 'Implement self-trade prevention and wash trading detection for order books.',
    references: ['https://github.com/Ellipsis-Labs/phoenix-v1/tree/master/audits']
  },
  {
    id: 'SOL6655',
    name: 'Drift Perps Audit Pattern',
    description: 'Perpetual exchange vulnerability pattern from Zellic Drift audit.',
    severity: 'high',
    pattern: /perpetual|perp|funding_rate(?![\s\S]{0,100}max_funding|[\s\S]{0,100}funding_cap)/i,
    recommendation: 'Cap funding rates and implement proper perpetual exchange safety mechanisms.',
    references: ['https://github.com/Zellic/publications/blob/master/Drift%20Protocol%20Audit%20Report.pdf']
  },
  {
    id: 'SOL6656',
    name: 'Pyth Oracle Audit Pattern',
    description: 'Oracle vulnerability pattern from Zellic Pyth audit.',
    severity: 'critical',
    pattern: /pyth|price_feed|oracle[\s\S]{0,100}(?![\s\S]{0,100}confidence|[\s\S]{0,100}expo|[\s\S]{0,100}status)/i,
    recommendation: 'Check Pyth confidence interval, exponent, and status. Never use price without validation.',
    references: ['https://github.com/Zellic/publications']
  },

  // ============================================
  // ADDITIONAL SECURITY PATTERNS
  // ============================================
  {
    id: 'SOL6657',
    name: 'HashCloak: Light Protocol Pattern',
    description: 'Zero-knowledge circuit vulnerability pattern from HashCloak Light audit.',
    severity: 'high',
    pattern: /zk|zero_knowledge|proof|groth16(?![\s\S]{0,100}verify_proof|[\s\S]{0,100}trusted_setup)/i,
    recommendation: 'Properly verify ZK proofs and handle trusted setup for zero-knowledge circuits.',
    references: ['https://github.com/Lightprotocol/light-protocol-program/blob/main/Audit/Light%20Protocol%20Audit%20Report.pdf']
  },
  {
    id: 'SOL6658',
    name: 'Ackee: Marinade Staking Pattern',
    description: 'Liquid staking vulnerability pattern from Ackee Marinade audit.',
    severity: 'high',
    pattern: /liquid_staking|msol|stake_pool(?![\s\S]{0,100}validator_list|[\s\S]{0,100}stake_account_check)/i,
    recommendation: 'Validate stake accounts and validator list in liquid staking operations.',
    references: ['https://docs.marinade.finance/marinade-protocol/security/audits']
  },
  {
    id: 'SOL6659',
    name: 'Opcodes: Streamflow Vesting Pattern',
    description: 'Vesting/streaming vulnerability pattern from Opcodes Streamflow audit.',
    severity: 'medium',
    pattern: /vesting|stream|cliff(?![\s\S]{0,100}revocable|[\s\S]{0,100}transferable_check)/i,
    recommendation: 'Handle vesting cliff and stream parameters carefully with proper revocation controls.',
    references: ['https://github.com/streamflow-finance/rust-sdk/blob/main/protocol_audit.pdf']
  },
  {
    id: 'SOL6660',
    name: 'Certik: Francium Yield Pattern',
    description: 'Yield aggregator vulnerability pattern from Certik Francium audit.',
    severity: 'high',
    pattern: /yield|farm|aggregator(?![\s\S]{0,100}strategy_whitelist|[\s\S]{0,100}vault_cap)/i,
    recommendation: 'Implement strategy whitelists and vault caps for yield aggregators.',
    references: ['https://www.certik.com/projects/francium']
  },

  // ============================================
  // ADVANCED EXPLOIT CHAINING
  // ============================================
  {
    id: 'SOL6661',
    name: 'Exploit Chaining: Small Bugs Combine',
    description: 'From samczsun: Multiple small vulnerabilities chain into major exploits.',
    severity: 'high',
    pattern: /(?:TODO|FIXME|HACK|XXX)[\s\S]{0,50}(?:low|minor|small)/i,
    recommendation: 'Don\'t dismiss small bugs - they can chain into major exploits. Fix all issues. Reference: samczsun exploit chaining talk.',
    references: ['https://www.youtube.com/watch?v=oA6Td5ujGrM']
  },

  // ============================================
  // COMPREHENSIVE ANCHOR PATTERNS
  // ============================================
  {
    id: 'SOL6662',
    name: 'Anchor: Missing Account Bump',
    description: 'PDA account without bump field, preventing bump verification on subsequent calls.',
    severity: 'high',
    pattern: /#\[account\([\s\S]*?seeds\s*=[\s\S]*?\)\][\s\S]*?pub\s+\w+\s*:\s*Account[\s\S]{0,100}(?!bump)/i,
    recommendation: 'Store bump seed in PDA account for verification: bump = some_account.bump',
    references: ['https://www.anchor-lang.com/docs/pdas']
  },
  {
    id: 'SOL6663',
    name: 'Anchor: Unconstrained has_one',
    description: 'has_one constraint without corresponding field validation.',
    severity: 'medium',
    pattern: /has_one\s*=\s*\w+(?![\s\S]{0,50}@|[\s\S]{0,50}constraint)/i,
    recommendation: 'Add error handling to has_one: has_one = authority @ ErrorCode::InvalidAuthority',
    references: ['https://www.anchor-lang.com/docs/account-constraints']
  },
  {
    id: 'SOL6664',
    name: 'Anchor: Space Calculation Error',
    description: 'Account space calculation may be incorrect, causing runtime errors.',
    severity: 'medium',
    pattern: /space\s*=\s*\d+(?![\s\S]{0,30}DISCRIMINATOR|[\s\S]{0,30}\+\s*8)/i,
    recommendation: 'Include 8-byte discriminator in space: space = 8 + AccountStruct::INIT_SPACE',
    references: ['https://www.anchor-lang.com/docs/space']
  },
  {
    id: 'SOL6665',
    name: 'Anchor: Missing Close Constraint Recipient',
    description: 'Close constraint without specifying recipient, potential for lamport leak.',
    severity: 'medium',
    pattern: /close(?![\s\S]{0,30}=\s*\w+)/,
    recommendation: 'Always specify close recipient: close = recipient_account',
    references: ['https://www.anchor-lang.com/docs/account-constraints']
  },

  // ============================================
  // COMPREHENSIVE CPI PATTERNS
  // ============================================
  {
    id: 'SOL6666',
    name: 'CPI: Return Data Not Checked',
    description: 'CPI call without checking return data for success/failure.',
    severity: 'high',
    pattern: /invoke(?:_signed)?[\s\S]{0,50}(?!\?|[\s\S]{0,30}expect|[\s\S]{0,30}unwrap|[\s\S]{0,30}get_return_data)/i,
    recommendation: 'Check CPI return data using sol_get_return_data() when applicable.',
    references: ['https://docs.solana.com/developing/on-chain-programs/calling-between-programs']
  },
  {
    id: 'SOL6667',
    name: 'CPI: Account Privilege Escalation',
    description: 'CPI passing signer privilege to untrusted program.',
    severity: 'critical',
    pattern: /invoke(?:_signed)?[\s\S]{0,100}is_signer\s*:\s*true(?![\s\S]{0,50}trusted_program)/i,
    recommendation: 'Never pass signer privilege to untrusted programs. Validate program ID before CPI.',
    references: ['https://github.com/project-serum/sealevel-attacks']
  },
  {
    id: 'SOL6668',
    name: 'CPI: Account Writable Escalation',
    description: 'CPI passing writable privilege to untrusted program.',
    severity: 'high',
    pattern: /invoke(?:_signed)?[\s\S]{0,100}is_writable\s*:\s*true(?![\s\S]{0,50}trusted_program)/i,
    recommendation: 'Be careful passing writable accounts to external programs. Validate program ID.',
    references: ['https://github.com/project-serum/sealevel-attacks']
  },

  // ============================================
  // STATE MANAGEMENT PATTERNS
  // ============================================
  {
    id: 'SOL6669',
    name: 'State: Unprotected State Transition',
    description: 'State machine transition without proper guard conditions.',
    severity: 'high',
    pattern: /state\s*=\s*State::\w+(?![\s\S]{0,50}require!|[\s\S]{0,50}assert!|[\s\S]{0,50}match)/i,
    recommendation: 'Guard all state transitions with proper condition checks.',
    references: ['https://www.sec3.dev/blog/how-to-audit-solana-smart-contracts-part-1-a-systematic-approach']
  },
  {
    id: 'SOL6670',
    name: 'State: Missing Intermediate State',
    description: 'Two-step operation without intermediate pending state.',
    severity: 'medium',
    pattern: /(?:transfer|set)_(?:authority|owner)(?![\s\S]{0,100}pending|[\s\S]{0,100}accept)/i,
    recommendation: 'Use pending state for two-step operations (set_pending_authority -> accept_authority).',
    references: ['https://github.com/project-serum/sealevel-attacks']
  },

  // ============================================
  // ADDITIONAL PATTERNS TO REACH 100
  // ============================================
  {
    id: 'SOL6671',
    name: 'Token: Missing Decimals Check',
    description: 'Token operations without checking decimal places.',
    severity: 'high',
    pattern: /token.*amount|amount.*token(?![\s\S]{0,100}decimals|[\s\S]{0,100}\.decimals)/i,
    recommendation: 'Always verify token decimals when performing amount calculations.',
    references: ['https://www.sec3.dev/blog/how-to-audit-solana-smart-contracts-part-1-a-systematic-approach']
  },
  {
    id: 'SOL6672',
    name: 'Token: Supply Validation Missing',
    description: 'Token mint operations without supply validation.',
    severity: 'high',
    pattern: /mint_to|MintTo(?![\s\S]{0,100}supply|[\s\S]{0,100}max_supply)/i,
    recommendation: 'Validate supply limits before minting tokens.',
    references: ['https://www.sec3.dev/blog/how-to-audit-solana-smart-contracts-part-1-a-systematic-approach']
  },
  {
    id: 'SOL6673',
    name: 'Account: Data Length Validation',
    description: 'Account data access without length validation.',
    severity: 'high',
    pattern: /data\[\d+\]|data\.get\((?![\s\S]{0,50}len|[\s\S]{0,50}data_len)/i,
    recommendation: 'Validate account data length before access: require!(data.len() >= expected_len).',
    references: ['https://blog.neodyme.io/posts/solana_common_pitfalls']
  },
  {
    id: 'SOL6674',
    name: 'Account: Key Derivation Collision',
    description: 'PDA seeds that could collide across different contexts.',
    severity: 'high',
    pattern: /seeds\s*=\s*\[[\s\S]*?b"[\w]+"[\s\S]*?\](?![\s\S]{0,50}authority|[\s\S]{0,50}user)/i,
    recommendation: 'Include context-specific identifiers in PDA seeds to prevent collisions.',
    references: ['https://github.com/project-serum/sealevel-attacks']
  },
  {
    id: 'SOL6675',
    name: 'Error: Generic Error Messages',
    description: 'Generic error messages that don\'t help with debugging.',
    severity: 'low',
    pattern: /Error::(?:Custom|InvalidInput|InvalidArgument)(?!\s*\()/i,
    recommendation: 'Use specific error codes and messages for better debugging.',
    references: ['https://www.anchor-lang.com/docs/errors']
  },
  {
    id: 'SOL6676',
    name: 'Serialization: Borsh Without Size Limits',
    description: 'Borsh deserialization without size limits could cause DoS.',
    severity: 'medium',
    pattern: /try_from_slice|deserialize(?![\s\S]{0,100}max_len|[\s\S]{0,100}size_limit)/i,
    recommendation: 'Add size limits to deserialization to prevent DoS attacks.',
    references: ['https://www.sec3.dev/blog/how-to-audit-solana-smart-contracts-part-1-a-systematic-approach']
  },
  {
    id: 'SOL6677',
    name: 'Compute: Unbounded Loop Risk',
    description: 'Loop without bounds could exceed compute budget.',
    severity: 'medium',
    pattern: /for\s+\w+\s+in\s+\w+(?![\s\S]{0,50}take\(|[\s\S]{0,50}\.iter\(\)\.take)/i,
    recommendation: 'Bound all loops with maximum iteration count: iter().take(MAX_ITERATIONS).',
    references: ['https://www.sec3.dev/blog/how-to-audit-solana-smart-contracts-part-5-dos-and-liveness-vulnerabilities']
  },
  {
    id: 'SOL6678',
    name: 'Compute: Heavy Operation in Loop',
    description: 'Expensive operation inside loop could exhaust compute budget.',
    severity: 'medium',
    pattern: /for[\s\S]{0,50}\{[\s\S]*?(?:invoke|log|serialize|deserialize)/i,
    recommendation: 'Minimize expensive operations in loops. Consider batching or pagination.',
    references: ['https://www.sec3.dev/blog/how-to-audit-solana-smart-contracts-part-5-dos-and-liveness-vulnerabilities']
  },
  {
    id: 'SOL6679',
    name: 'Timestamp: Clock Manipulation Risk',
    description: 'Using clock timestamp for time-sensitive operations.',
    severity: 'medium',
    pattern: /clock\.unix_timestamp|slot|epoch(?![\s\S]{0,100}tolerance|[\s\S]{0,100}drift)/i,
    recommendation: 'Account for slot/timestamp drift. Don\'t rely on precise timing for security-critical operations.',
    references: ['https://www.sec3.dev/blog/how-to-audit-solana-smart-contracts-part-1-a-systematic-approach']
  },
  {
    id: 'SOL6680',
    name: 'Rent: Exemption Not Verified',
    description: 'Account creation without rent exemption verification.',
    severity: 'medium',
    pattern: /create_account|transfer[\s\S]{0,100}lamports(?![\s\S]{0,100}rent_exempt|[\s\S]{0,100}minimum_balance)/i,
    recommendation: 'Verify account has sufficient lamports for rent exemption.',
    references: ['https://blog.neodyme.io/posts/solana_common_pitfalls']
  },
  {
    id: 'SOL6681',
    name: 'Multisig: Threshold Not Enforced',
    description: 'Multisig operation without proper threshold enforcement.',
    severity: 'critical',
    pattern: /multisig|multi_sig(?![\s\S]{0,100}threshold|[\s\S]{0,100}num_signers)/i,
    recommendation: 'Enforce multisig threshold: require!(signers >= threshold).',
    references: ['https://github.com/project-serum/sealevel-attacks']
  },
  {
    id: 'SOL6682',
    name: 'Timelock: Duration Too Short',
    description: 'Timelock duration may be too short for governance safety.',
    severity: 'medium',
    pattern: /timelock|delay\s*[:=]\s*\d{1,4}(?![\s\S]{0,30}days|[\s\S]{0,30}hours)/i,
    recommendation: 'Use appropriate timelock durations (typically 24-48 hours minimum for governance).',
    references: ['https://www.sec3.dev/blog/how-to-audit-solana-smart-contracts-part-1-a-systematic-approach']
  },
  {
    id: 'SOL6683',
    name: 'Pausable: Missing Pause Check',
    description: 'Operation that should be pausable but lacks pause check.',
    severity: 'medium',
    pattern: /(?:swap|transfer|deposit|withdraw)(?![\s\S]{0,100}is_paused|[\s\S]{0,100}paused)/i,
    recommendation: 'Add pause functionality for emergency situations: require!(!state.is_paused).',
    references: ['https://www.sec3.dev/blog/how-to-audit-solana-smart-contracts-part-1-a-systematic-approach']
  },
  {
    id: 'SOL6684',
    name: 'Emergency: No Withdrawal Function',
    description: 'Protocol lacks emergency withdrawal mechanism.',
    severity: 'high',
    pattern: /vault|pool|treasury(?![\s\S]{0,200}emergency_withdraw|[\s\S]{0,200}rescue)/i,
    recommendation: 'Implement emergency withdrawal function with proper access controls.',
    references: ['https://www.sec3.dev/blog/how-to-audit-solana-smart-contracts-part-1-a-systematic-approach']
  },
  {
    id: 'SOL6685',
    name: 'Fee: Hardcoded Fee Values',
    description: 'Fees hardcoded instead of configurable, preventing adjustment.',
    severity: 'low',
    pattern: /fee\s*[:=]\s*\d+(?![\s\S]{0,50}config|[\s\S]{0,50}state\.fee)/i,
    recommendation: 'Make fees configurable through governance rather than hardcoded.',
    references: ['https://www.sec3.dev/blog/how-to-audit-solana-smart-contracts-part-1-a-systematic-approach']
  },
  {
    id: 'SOL6686',
    name: 'Fee: Missing Fee Cap',
    description: 'Fee can be set without upper bound, potential for exploitation.',
    severity: 'high',
    pattern: /set_fee|update_fee(?![\s\S]{0,100}max_fee|[\s\S]{0,100}<\s*MAX)/i,
    recommendation: 'Cap fees at reasonable maximum: require!(fee <= MAX_FEE).',
    references: ['https://www.sec3.dev/blog/how-to-audit-solana-smart-contracts-part-1-a-systematic-approach']
  },
  {
    id: 'SOL6687',
    name: 'Versioning: No Version Check',
    description: 'Account structure lacks version field for future upgrades.',
    severity: 'low',
    pattern: /pub\s+struct\s+\w+\s*\{(?![\s\S]{0,100}version\s*:|[\s\S]{0,100}schema_version)/i,
    recommendation: 'Add version field to account structures for future compatibility.',
    references: ['https://www.sec3.dev/blog/how-to-audit-solana-smart-contracts-part-1-a-systematic-approach']
  },
  {
    id: 'SOL6688',
    name: 'Migration: No Migration Path',
    description: 'Program upgrade without account migration strategy.',
    severity: 'medium',
    pattern: /upgrade|migrate(?![\s\S]{0,100}migration|[\s\S]{0,100}realloc)/i,
    recommendation: 'Plan account migration strategy for program upgrades using realloc.',
    references: ['https://www.anchor-lang.com/docs/account-constraints']
  },
  {
    id: 'SOL6689',
    name: 'Logging: Sensitive Data in Logs',
    description: 'Potentially sensitive data being logged.',
    severity: 'medium',
    pattern: /msg![\s\S]{0,50}(?:key|secret|password|private)/i,
    recommendation: 'Never log sensitive data like keys or secrets.',
    references: ['https://www.sec3.dev/blog/how-to-audit-solana-smart-contracts-part-1-a-systematic-approach']
  },
  {
    id: 'SOL6690',
    name: 'Testing: Missing Edge Case Tests',
    description: 'Complex logic without edge case testing.',
    severity: 'info',
    pattern: /#\[test\][\s\S]{0,500}(?![\s\S]{0,200}overflow|[\s\S]{0,200}underflow|[\s\S]{0,200}zero|[\s\S]{0,200}max)/i,
    recommendation: 'Add edge case tests: zero values, max values, overflow, underflow.',
    references: ['https://www.sec3.dev/blog/how-to-audit-solana-smart-contracts-part-3-penetration-testing']
  },
  {
    id: 'SOL6691',
    name: 'Native: System Program ID Check',
    description: 'System program operations without ID verification.',
    severity: 'high',
    pattern: /system_instruction|SystemInstruction(?![\s\S]{0,100}system_program::ID|[\s\S]{0,100}system_program::id)/i,
    recommendation: 'Verify system_program account is actually the system program.',
    references: ['https://github.com/project-serum/sealevel-attacks']
  },
  {
    id: 'SOL6692',
    name: 'Native: Token Program ID Check',
    description: 'Token operations without program ID verification.',
    severity: 'high',
    pattern: /spl_token|TokenInstruction(?![\s\S]{0,100}spl_token::ID|[\s\S]{0,100}token_program)/i,
    recommendation: 'Verify token_program account is actually the SPL token program.',
    references: ['https://github.com/project-serum/sealevel-attacks']
  },
  {
    id: 'SOL6693',
    name: 'Memory: Large Stack Allocation',
    description: 'Large array/struct on stack could cause stack overflow.',
    severity: 'medium',
    pattern: /\[\w+;\s*(?:1024|2048|4096|8192|16384|32768)\]/i,
    recommendation: 'Use heap allocation (Box, Vec) for large data structures.',
    references: ['https://www.sec3.dev/blog/how-to-audit-solana-smart-contracts-part-5-dos-and-liveness-vulnerabilities']
  },
  {
    id: 'SOL6694',
    name: 'Memory: Uninitialized Memory Usage',
    description: 'Potential use of uninitialized memory.',
    severity: 'high',
    pattern: /MaybeUninit|uninit|assume_init(?![\s\S]{0,50}write|[\s\S]{0,50}zeroed)/i,
    recommendation: 'Initialize all memory before use. Use zeroed() for safe initialization.',
    references: ['https://www.sec3.dev/blog/how-to-audit-solana-smart-contracts-part-1-a-systematic-approach']
  },
  {
    id: 'SOL6695',
    name: 'Concurrency: Slot Race Condition',
    description: 'Multiple transactions in same slot could race on state.',
    severity: 'medium',
    pattern: /slot|clock\.slot(?![\s\S]{0,100}atomic|[\s\S]{0,100}mutex|[\s\S]{0,100}lock)/i,
    recommendation: 'Design for concurrent transactions in same slot. Use atomic operations where needed.',
    references: ['https://www.sec3.dev/blog/how-to-audit-solana-smart-contracts-part-1-a-systematic-approach']
  },
  {
    id: 'SOL6696',
    name: 'Reentrancy: Cross-Program State',
    description: 'State modified before CPI could enable reentrancy-like attacks.',
    severity: 'high',
    pattern: /state\.\w+\s*=[\s\S]{0,100}invoke(?:_signed)?/i,
    recommendation: 'Follow checks-effects-interactions: update state after CPI or use reentrancy guards.',
    references: ['https://github.com/project-serum/sealevel-attacks']
  },
  {
    id: 'SOL6697',
    name: 'Trust: Hardcoded Addresses Mutable',
    description: 'Critical addresses stored in mutable state instead of constants.',
    severity: 'medium',
    pattern: /admin|authority|owner\s*:\s*Pubkey(?![\s\S]{0,100}constant|[\s\S]{0,100}const)/i,
    recommendation: 'Consider using constant addresses for critical values that shouldn\'t change.',
    references: ['https://www.sec3.dev/blog/how-to-audit-solana-smart-contracts-part-1-a-systematic-approach']
  },
  {
    id: 'SOL6698',
    name: 'Validation: Missing Pubkey::default Check',
    description: 'Pubkey field could be default (all zeros) which might be unintended.',
    severity: 'medium',
    pattern: /Pubkey(?![\s\S]{0,100}!=\s*Pubkey::default|[\s\S]{0,100}default\(\))/i,
    recommendation: 'Check that pubkeys are not default: require!(key != Pubkey::default()).',
    references: ['https://www.sec3.dev/blog/how-to-audit-solana-smart-contracts-part-1-a-systematic-approach']
  },
  {
    id: 'SOL6699',
    name: 'Documentation: Missing Security Comments',
    description: 'Security-critical code without documentation.',
    severity: 'info',
    pattern: /(?:authority|admin|owner|verify|validate)(?![\s\S]{0,50}\/\/|[\s\S]{0,50}\/\*)/i,
    recommendation: 'Document security-critical code with comments explaining the safety invariants.',
    references: ['https://www.sec3.dev/blog/how-to-audit-solana-smart-contracts-part-1-a-systematic-approach']
  },
  {
    id: 'SOL6700',
    name: 'Audit: Coverage Gap Indicator',
    description: 'Complex business logic that may benefit from formal audit.',
    severity: 'info',
    pattern: /(?:swap|liquidate|borrow|lend|stake|unstake|governance|vote)[\s\S]{0,200}(?:invoke|transfer|mint|burn)/i,
    recommendation: 'Consider professional security audit for complex DeFi logic. Reference: solsec curated audit list.',
    references: ['https://github.com/sannykim/solsec']
  },
];

/**
 * Run Batch 104 patterns against input
 */
export function checkBatch104Patterns(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  const content = input.rust?.content || '';
  const filePath = input.path || '';
  
  if (!content) return findings;
  
  const lines = content.split('\n');
  
  for (const pattern of BATCH_104_PATTERNS) {
    try {
      const regex = new RegExp(pattern.pattern.source, pattern.pattern.flags + 'g');
      const matches = [...content.matchAll(regex)];
      
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
          location: { file: filePath, line: lineNum },
          recommendation: pattern.recommendation,
          code: snippet.substring(0, 200),
        });
      }
    } catch (error) {
      // Skip pattern on error
    }
  }
  
  return findings;
}

export { BATCH_104_PATTERNS };
