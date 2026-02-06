/**
 * SolGuard Batch 58: 2025-2026 Latest Exploits + Infrastructure Security
 * 
 * 70 patterns (SOL2351-SOL2420) based on:
 * - Feb 2026 latest security incidents
 * - Validator and infrastructure vulnerabilities
 * - MEV and Jito-specific patterns
 * - Token-2022 advanced patterns
 * - cNFT and compression security
 */

import type { Finding, PatternInput } from './index.js';

interface PatternDef {
  id: string;
  name: string;
  severity: 'critical' | 'high' | 'medium' | 'low' | 'info';
  pattern: RegExp;
  description: string;
  recommendation: string;
}

const BATCH_58_PATTERNS: PatternDef[] = [
  // 2025-2026 Latest Exploit Patterns (SOL2351-SOL2370)
  {
    id: 'SOL2351',
    name: 'Step Finance Treasury Pattern ($40M)',
    severity: 'critical',
    pattern: /treasury|admin_wallet(?![\s\S]{0,100}multisig|timelock)/i,
    description: 'Treasury without multisig protection (Step Finance pattern).',
    recommendation: 'Use multisig + timelock for all treasury operations.'
  },
  {
    id: 'SOL2352',
    name: 'Authority Transfer Phishing',
    severity: 'critical',
    pattern: /set_authority|transfer_authority(?![\s\S]{0,100}two_step|pending)/i,
    description: 'Authority transfer without two-step confirmation.',
    recommendation: 'Implement two-step authority transfer with pending state.'
  },
  {
    id: 'SOL2353',
    name: 'Owner Permission Spoofing',
    severity: 'critical',
    pattern: /owner\s*=|authority\s*=(?![\s\S]{0,50}verify_signature)/i,
    description: 'Owner field manipulation without signature verification.',
    recommendation: 'Verify signatures for all authority changes.'
  },
  {
    id: 'SOL2354',
    name: 'Transaction Simulation Bypass',
    severity: 'high',
    pattern: /simulation|simulate(?![\s\S]{0,100}production_check)/i,
    description: 'Transaction may behave differently in simulation vs production.',
    recommendation: 'Add simulation detection safeguards.'
  },
  {
    id: 'SOL2355',
    name: 'NoOnes Escrow Pattern ($8.5M)',
    severity: 'critical',
    pattern: /escrow|p2p(?![\s\S]{0,100}release_verification)/i,
    description: 'Escrow release without proper verification.',
    recommendation: 'Implement multi-party escrow release verification.'
  },
  {
    id: 'SOL2356',
    name: 'Loopscale Admin Launch ($5.8M)',
    severity: 'critical',
    pattern: /launch|deploy(?![\s\S]{0,100}admin_rotation|key_ceremony)/i,
    description: 'Protocol launch without admin key rotation.',
    recommendation: 'Rotate admin keys post-launch.'
  },
  {
    id: 'SOL2357',
    name: 'NPM Crypto-Clipper 2025',
    severity: 'critical',
    pattern: /npm|package(?![\s\S]{0,100}integrity|checksum)/i,
    description: 'NPM dependency without integrity verification.',
    recommendation: 'Verify package checksums and use lockfiles.'
  },
  {
    id: 'SOL2358',
    name: 'Pump.fun Early Withdrawal ($1.9M)',
    severity: 'high',
    pattern: /bonding_curve|launch(?![\s\S]{0,100}lock_period|vesting)/i,
    description: 'Token launch without liquidity lock.',
    recommendation: 'Implement liquidity lock period.'
  },
  {
    id: 'SOL2359',
    name: 'Banana Gun Bot Pattern ($1.4M)',
    severity: 'high',
    pattern: /bot|trading_bot(?![\s\S]{0,100}session_validation)/i,
    description: 'Trading bot without session validation.',
    recommendation: 'Implement secure session management.'
  },
  {
    id: 'SOL2360',
    name: 'Thunder Terminal MongoDB ($240K)',
    severity: 'high',
    pattern: /mongodb|database(?![\s\S]{0,100}encrypted|tls)/i,
    description: 'Database connection without encryption.',
    recommendation: 'Use encrypted database connections.'
  },
  {
    id: 'SOL2361',
    name: 'Cypher Insider Pattern ($317K)',
    severity: 'high',
    pattern: /team_access|insider(?![\s\S]{0,100}audit_log|monitoring)/i,
    description: 'Insider access without audit logging.',
    recommendation: 'Log all insider/team actions.'
  },
  {
    id: 'SOL2362',
    name: 'io.net API Key Exposure',
    severity: 'critical',
    pattern: /api_key|secret(?![\s\S]{0,50}env|secret_manager)/i,
    description: 'API key potentially exposed in code.',
    recommendation: 'Use environment variables or secret manager.'
  },
  {
    id: 'SOL2363',
    name: 'Aurory Game Exploit ($830K)',
    severity: 'high',
    pattern: /game_item|nft_game(?![\s\S]{0,100}server_validation)/i,
    description: 'Game item without server-side validation.',
    recommendation: 'Validate all game actions server-side.'
  },
  {
    id: 'SOL2364',
    name: 'SVT Token Unclaimed Vuln ($1M)',
    severity: 'high',
    pattern: /unclaimed|claim(?![\s\S]{0,100}expiry|deadline)/i,
    description: 'Claim mechanism without expiry.',
    recommendation: 'Add claim deadlines and expiry.'
  },
  {
    id: 'SOL2365',
    name: 'Saga DAO Insider ($1.5M)',
    severity: 'high',
    pattern: /dao_treasury|community_fund(?![\s\S]{0,100}multisig)/i,
    description: 'DAO treasury without multisig.',
    recommendation: 'Require multisig for DAO treasury.'
  },
  {
    id: 'SOL2366',
    name: 'Solareum Rug Detection',
    severity: 'critical',
    pattern: /rugpull|rug(?![\s\S]{0,100}liquidity_lock)/i,
    description: 'Potential rugpull pattern detected.',
    recommendation: 'Lock liquidity and use trusted deployer.'
  },
  {
    id: 'SOL2367',
    name: 'Parcl CDN Compromise',
    severity: 'high',
    pattern: /cdn|frontend(?![\s\S]{0,100}sri|integrity)/i,
    description: 'Frontend without subresource integrity.',
    recommendation: 'Implement SRI for all external resources.'
  },
  {
    id: 'SOL2368',
    name: 'Web3.js Supply Chain',
    severity: 'critical',
    pattern: /web3\.js|@solana\/web3(?![\s\S]{0,100}version_pin)/i,
    description: 'Solana web3.js without version pinning.',
    recommendation: 'Pin specific web3.js versions.'
  },
  {
    id: 'SOL2369',
    name: 'Tulip Flash Loan Vault ($5.2M)',
    severity: 'high',
    pattern: /flash_loan|vault(?![\s\S]{0,100}same_block_check)/i,
    description: 'Vault vulnerable to flash loan attacks.',
    recommendation: 'Add same-block operation restrictions.'
  },
  {
    id: 'SOL2370',
    name: 'UXD Depeg Risk ($3.9M)',
    severity: 'high',
    pattern: /stablecoin|peg(?![\s\S]{0,100}oracle_deviation)/i,
    description: 'Stablecoin without depeg detection.',
    recommendation: 'Monitor and react to depeg events.'
  },

  // Validator & Infrastructure Patterns (SOL2371-SOL2385)
  {
    id: 'SOL2371',
    name: 'Validator Commission Manipulation',
    severity: 'high',
    pattern: /commission|validator_fee(?![\s\S]{0,100}max_cap|limit)/i,
    description: 'Validator commission without cap.',
    recommendation: 'Enforce maximum commission rates.'
  },
  {
    id: 'SOL2372',
    name: 'Stake Pool Centralization',
    severity: 'medium',
    pattern: /stake_pool|delegation(?![\s\S]{0,100}distribution_check)/i,
    description: 'Stake pool without distribution requirements.',
    recommendation: 'Enforce stake distribution across validators.'
  },
  {
    id: 'SOL2373',
    name: 'Turbine Block Propagation',
    severity: 'high',
    pattern: /turbine|shred(?![\s\S]{0,100}validation)/i,
    description: 'Turbine shred handling without validation.',
    recommendation: 'Validate all turbine shreds.'
  },
  {
    id: 'SOL2374',
    name: 'Durable Nonce Expiry Risk',
    severity: 'medium',
    pattern: /durable_nonce|nonce(?![\s\S]{0,100}advance_check)/i,
    description: 'Durable nonce without advance verification.',
    recommendation: 'Check nonce state before use.'
  },
  {
    id: 'SOL2375',
    name: 'JIT Cache Corruption',
    severity: 'critical',
    pattern: /jit|cache(?![\s\S]{0,100}integrity_check)/i,
    description: 'JIT compilation without integrity verification.',
    recommendation: 'Verify JIT cache integrity.'
  },
  {
    id: 'SOL2376',
    name: 'ELF Address Alignment',
    severity: 'high',
    pattern: /elf|bpf_loader(?![\s\S]{0,100}alignment)/i,
    description: 'ELF loading without address alignment check.',
    recommendation: 'Verify proper ELF address alignment.'
  },
  {
    id: 'SOL2377',
    name: 'Compute Unit Exhaustion',
    severity: 'high',
    pattern: /compute_units|cu(?![\s\S]{0,100}budget_check)/i,
    description: 'Operation without compute budget check.',
    recommendation: 'Verify compute budget before expensive ops.'
  },
  {
    id: 'SOL2378',
    name: 'Account Heap Overflow',
    severity: 'critical',
    pattern: /heap|allocate(?![\s\S]{0,100}size_check)/i,
    description: 'Heap allocation without size check.',
    recommendation: 'Validate allocation sizes.'
  },
  {
    id: 'SOL2379',
    name: 'Stack Frame Limit',
    severity: 'high',
    pattern: /stack|recursion(?![\s\S]{0,100}depth_limit)/i,
    description: 'Recursion without stack depth limit.',
    recommendation: 'Limit recursive call depth.'
  },
  {
    id: 'SOL2380',
    name: 'CPI Depth Exhaustion',
    severity: 'high',
    pattern: /cpi|invoke(?![\s\S]{0,100}depth_check)/i,
    description: 'CPI without depth tracking.',
    recommendation: 'Track and limit CPI depth (max 4).'
  },
  {
    id: 'SOL2381',
    name: 'Account Reallocation DOS',
    severity: 'high',
    pattern: /realloc|resize(?![\s\S]{0,100}max_size)/i,
    description: 'Account reallocation without size limit.',
    recommendation: 'Limit account reallocation size.'
  },
  {
    id: 'SOL2382',
    name: 'Rent Epoch Skip',
    severity: 'medium',
    pattern: /rent_epoch|epoch(?![\s\S]{0,100}validation)/i,
    description: 'Rent epoch not validated.',
    recommendation: 'Validate rent epoch for accounts.'
  },
  {
    id: 'SOL2383',
    name: 'Slot Hash Manipulation',
    severity: 'high',
    pattern: /slot_hashes|recent_blockhash(?![\s\S]{0,100}verify)/i,
    description: 'Slot hash used without verification.',
    recommendation: 'Verify slot hash freshness.'
  },
  {
    id: 'SOL2384',
    name: 'Clock Sysvar Drift',
    severity: 'medium',
    pattern: /sysvar::clock|Clock(?![\s\S]{0,100}drift_check)/i,
    description: 'Clock sysvar without drift consideration.',
    recommendation: 'Account for clock drift in time-based ops.'
  },
  {
    id: 'SOL2385',
    name: 'Instructions Sysvar Abuse',
    severity: 'high',
    pattern: /sysvar::instructions|Instructions(?![\s\S]{0,100}verify)/i,
    description: 'Instructions sysvar without verification.',
    recommendation: 'Verify instruction sysvar contents.'
  },

  // MEV & Jito Patterns (SOL2386-SOL2395)
  {
    id: 'SOL2386',
    name: 'Jito Bundle Sandwich',
    severity: 'high',
    pattern: /bundle|jito(?![\s\S]{0,100}sandwich_protection)/i,
    description: 'Transaction vulnerable to Jito sandwich attacks.',
    recommendation: 'Implement private transaction submission.'
  },
  {
    id: 'SOL2387',
    name: 'Priority Fee Manipulation',
    severity: 'medium',
    pattern: /priority_fee|tip(?![\s\S]{0,100}max_cap)/i,
    description: 'Priority fee without maximum cap.',
    recommendation: 'Cap priority fees to prevent manipulation.'
  },
  {
    id: 'SOL2388',
    name: 'MEV Frontrunning',
    severity: 'high',
    pattern: /swap|trade(?![\s\S]{0,100}commit_reveal|private)/i,
    description: 'Trade vulnerable to frontrunning.',
    recommendation: 'Use commit-reveal or private mempools.'
  },
  {
    id: 'SOL2389',
    name: 'Searcher Collusion',
    severity: 'high',
    pattern: /searcher|mev(?![\s\S]{0,100}fair_ordering)/i,
    description: 'MEV extraction without fair ordering.',
    recommendation: 'Use fair ordering mechanisms.'
  },
  {
    id: 'SOL2390',
    name: 'Backrunning Vulnerability',
    severity: 'medium',
    pattern: /oracle_update|price_update(?![\s\S]{0,100}delay)/i,
    description: 'Oracle update vulnerable to backrunning.',
    recommendation: 'Add delay to oracle updates.'
  },
  {
    id: 'SOL2391',
    name: 'Bundle Reversion Attack',
    severity: 'high',
    pattern: /bundle|atomic(?![\s\S]{0,100}revert_check)/i,
    description: 'Bundle without reversion handling.',
    recommendation: 'Handle partial bundle execution.'
  },
  {
    id: 'SOL2392',
    name: 'Jito DDoS Pattern',
    severity: 'high',
    pattern: /spam|flood(?![\s\S]{0,100}rate_limit)/i,
    description: 'Spam vulnerability without rate limiting.',
    recommendation: 'Implement rate limiting.'
  },
  {
    id: 'SOL2393',
    name: 'Block Builder Manipulation',
    severity: 'high',
    pattern: /block_builder|validator(?![\s\S]{0,100}randomization)/i,
    description: 'Block building without randomization.',
    recommendation: 'Use randomized leader selection.'
  },
  {
    id: 'SOL2394',
    name: 'Liquidation MEV',
    severity: 'high',
    pattern: /liquidation|liquidate(?![\s\S]{0,100}dutch_auction)/i,
    description: 'Liquidation vulnerable to MEV extraction.',
    recommendation: 'Use Dutch auction for liquidations.'
  },
  {
    id: 'SOL2395',
    name: 'Just-In-Time Liquidity',
    severity: 'medium',
    pattern: /jit_liquidity|just_in_time(?![\s\S]{0,100}lockup)/i,
    description: 'JIT liquidity provision risk.',
    recommendation: 'Require minimum liquidity lockup.'
  },

  // Token-2022 Advanced Patterns (SOL2396-SOL2408)
  {
    id: 'SOL2396',
    name: 'Token-2022 Transfer Hook Reentry',
    severity: 'critical',
    pattern: /transfer_hook|TransferHook(?![\s\S]{0,100}reentrancy_guard)/i,
    description: 'Transfer hook without reentrancy protection.',
    recommendation: 'Add reentrancy guard to transfer hooks.'
  },
  {
    id: 'SOL2397',
    name: 'Token-2022 Confidential Amount',
    severity: 'high',
    pattern: /confidential_transfer|encrypted(?![\s\S]{0,100}zk_verify)/i,
    description: 'Confidential transfer without ZK verification.',
    recommendation: 'Verify ZK proofs for confidential transfers.'
  },
  {
    id: 'SOL2398',
    name: 'Token-2022 Interest Bearing Exploit',
    severity: 'high',
    pattern: /interest_bearing|interest_rate(?![\s\S]{0,100}compound_check)/i,
    description: 'Interest bearing token without compound check.',
    recommendation: 'Properly calculate compounding interest.'
  },
  {
    id: 'SOL2399',
    name: 'Token-2022 Permanent Delegate Abuse',
    severity: 'critical',
    pattern: /permanent_delegate|PermanentDelegate(?![\s\S]{0,100}guardian)/i,
    description: 'Permanent delegate without guardian oversight.',
    recommendation: 'Require guardian for permanent delegation.'
  },
  {
    id: 'SOL2400',
    name: 'Token-2022 Memo Required Bypass',
    severity: 'medium',
    pattern: /memo_required|MemoTransfer(?![\s\S]{0,100}enforce)/i,
    description: 'Memo requirement can be bypassed.',
    recommendation: 'Enforce memo at program level.'
  },
  {
    id: 'SOL2401',
    name: 'Token-2022 Non-Transferable Override',
    severity: 'high',
    pattern: /non_transferable|soul_bound(?![\s\S]{0,100}immutable)/i,
    description: 'Non-transferable token can be overridden.',
    recommendation: 'Make non-transferable truly immutable.'
  },
  {
    id: 'SOL2402',
    name: 'Token-2022 Default State Abuse',
    severity: 'medium',
    pattern: /default_account_state|DefaultAccountState(?![\s\S]{0,100}verify)/i,
    description: 'Default account state not verified.',
    recommendation: 'Verify account state on operations.'
  },
  {
    id: 'SOL2403',
    name: 'Token-2022 Group Member Attack',
    severity: 'high',
    pattern: /token_group|GroupMember(?![\s\S]{0,100}authority_check)/i,
    description: 'Token group without authority verification.',
    recommendation: 'Verify group member authority.'
  },
  {
    id: 'SOL2404',
    name: 'Token-2022 Metadata Pointer',
    severity: 'medium',
    pattern: /metadata_pointer|MetadataPointer(?![\s\S]{0,100}validate)/i,
    description: 'Metadata pointer not validated.',
    recommendation: 'Validate metadata pointer targets.'
  },
  {
    id: 'SOL2405',
    name: 'Token-2022 Close Authority Drain',
    severity: 'high',
    pattern: /close_authority|CloseAuthority(?![\s\S]{0,100}balance_check)/i,
    description: 'Close authority without balance verification.',
    recommendation: 'Verify zero balance before close.'
  },
  {
    id: 'SOL2406',
    name: 'Token-2022 Fee Config Abuse',
    severity: 'high',
    pattern: /transfer_fee_config|TransferFeeConfig(?![\s\S]{0,100}max_fee)/i,
    description: 'Transfer fee without maximum cap.',
    recommendation: 'Cap transfer fees at reasonable maximum.'
  },
  {
    id: 'SOL2407',
    name: 'Token-2022 CPI Guard State',
    severity: 'high',
    pattern: /cpi_guard|CpiGuard(?![\s\S]{0,100}state_check)/i,
    description: 'CPI guard state not verified.',
    recommendation: 'Check CPI guard before operations.'
  },
  {
    id: 'SOL2408',
    name: 'Token-2022 Immutable Owner Bypass',
    severity: 'high',
    pattern: /immutable_owner|ImmutableOwner(?![\s\S]{0,100}verify)/i,
    description: 'Immutable owner can be bypassed.',
    recommendation: 'Enforce immutable owner check.'
  },

  // Compressed NFT Patterns (SOL2409-SOL2420)
  {
    id: 'SOL2409',
    name: 'cNFT Merkle Proof Spoofing',
    severity: 'critical',
    pattern: /merkle_proof|MerkleProof(?![\s\S]{0,100}verify_proof)/i,
    description: 'cNFT merkle proof without verification.',
    recommendation: 'Verify all merkle proofs.'
  },
  {
    id: 'SOL2410',
    name: 'cNFT Canopy Depth Attack',
    severity: 'high',
    pattern: /canopy|tree_depth(?![\s\S]{0,100}depth_check)/i,
    description: 'Canopy depth not validated.',
    recommendation: 'Validate canopy depth on operations.'
  },
  {
    id: 'SOL2411',
    name: 'cNFT Concurrent Modification',
    severity: 'high',
    pattern: /concurrent|atomic_update(?![\s\S]{0,100}seq_check)/i,
    description: 'cNFT tree concurrent modification risk.',
    recommendation: 'Use sequence numbers for atomicity.'
  },
  {
    id: 'SOL2412',
    name: 'cNFT Leaf Index Overflow',
    severity: 'high',
    pattern: /leaf_index|tree_index(?![\s\S]{0,100}bounds_check)/i,
    description: 'cNFT leaf index without bounds check.',
    recommendation: 'Validate leaf index bounds.'
  },
  {
    id: 'SOL2413',
    name: 'cNFT Creator Verification',
    severity: 'high',
    pattern: /creator_hash|creator_verification(?![\s\S]{0,100}verify)/i,
    description: 'cNFT creator hash not verified.',
    recommendation: 'Verify creator hash on operations.'
  },
  {
    id: 'SOL2414',
    name: 'cNFT Data Hash Collision',
    severity: 'high',
    pattern: /data_hash|asset_hash(?![\s\S]{0,100}unique)/i,
    description: 'cNFT data hash may collide.',
    recommendation: 'Ensure data hash uniqueness.'
  },
  {
    id: 'SOL2415',
    name: 'cNFT Tree Authority Transfer',
    severity: 'critical',
    pattern: /tree_authority|tree_delegate(?![\s\S]{0,100}two_step)/i,
    description: 'Tree authority transfer without two-step.',
    recommendation: 'Use two-step authority transfer.'
  },
  {
    id: 'SOL2416',
    name: 'cNFT Decompress Attack',
    severity: 'high',
    pattern: /decompress|unpack(?![\s\S]{0,100}verify_ownership)/i,
    description: 'cNFT decompression without ownership verify.',
    recommendation: 'Verify ownership before decompression.'
  },
  {
    id: 'SOL2417',
    name: 'cNFT Collection Verification',
    severity: 'high',
    pattern: /collection_verified|collection_hash(?![\s\S]{0,100}check)/i,
    description: 'cNFT collection not verified.',
    recommendation: 'Verify collection membership.'
  },
  {
    id: 'SOL2418',
    name: 'Bubblegum Creator Share',
    severity: 'medium',
    pattern: /creator_share|royalty(?![\s\S]{0,100}total_100)/i,
    description: 'Creator shares may not sum to 100.',
    recommendation: 'Verify creator shares sum to 100%.'
  },
  {
    id: 'SOL2419',
    name: 'Bubblegum Delegate Scope',
    severity: 'high',
    pattern: /delegate|burn_delegate(?![\s\S]{0,100}scope_check)/i,
    description: 'cNFT delegate scope not limited.',
    recommendation: 'Limit delegate permissions scope.'
  },
  {
    id: 'SOL2420',
    name: 'Bubblegum Metadata Update',
    severity: 'medium',
    pattern: /metadata_update|update_metadata(?![\s\S]{0,100}authority)/i,
    description: 'Metadata update without authority check.',
    recommendation: 'Verify update authority.'
  },
];

export function checkBatch58Patterns(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  const content = input.rust?.content || '';
  const fileName = input.path || input.rust?.filePath || 'unknown';

  if (!content) return findings;

  const lines = content.split('\n');

  for (const pattern of BATCH_58_PATTERNS) {
    try {
      const flags = pattern.pattern.flags.includes('g') ? pattern.pattern.flags : pattern.pattern.flags + 'g';
      const regex = new RegExp(pattern.pattern.source, flags);
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
          location: { file: fileName, line: lineNum },
          recommendation: pattern.recommendation,
          code: snippet.substring(0, 200),
        });
      }
    } catch (error) {
      // Skip failed pattern
    }
  }

  return findings;
}

export const BATCH_58_COUNT = BATCH_58_PATTERNS.length;
