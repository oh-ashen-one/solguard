/**
 * SolGuard Batch 57: Solsec Audit Findings + Advanced PoC Patterns
 * 
 * 70 patterns (SOL2281-SOL2350) based on:
 * - sannykim/solsec curated audit findings
 * - Real audit reports from Kudelski, Neodyme, OtterSec, Bramah, Halborn
 * - PoC exploit frameworks and techniques
 * - Feb 2026 latest security research
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

const BATCH_57_PATTERNS: PatternDef[] = [
  // Kudelski Audit Patterns (SOL2281-SOL2295)
  {
    id: 'SOL2281',
    name: 'Kudelski: Missing Ownership Validation',
    severity: 'critical',
    pattern: /AccountInfo[\s\S]{0,100}(?!owner\s*==|\.owner\.eq)/i,
    description: 'Account ownership not validated per Kudelski audit methodology.',
    recommendation: 'Validate account owner matches expected program ID.'
  },
  {
    id: 'SOL2282',
    name: 'Kudelski: Unvalidated Data Field',
    severity: 'high',
    pattern: /data\s*=\s*account[\s\S]{0,50}(?!validate|check|verify)/i,
    description: 'Account data accessed without field validation.',
    recommendation: 'Validate all account data fields before use.'
  },
  {
    id: 'SOL2283',
    name: 'Kudelski: Missing Stake Pool Validation',
    severity: 'high',
    pattern: /stake_pool|StakePool(?![\s\S]{0,100}validator_list)/i,
    description: 'Stake pool operations without validator list check.',
    recommendation: 'Verify stake pool validator list integrity.'
  },
  {
    id: 'SOL2284',
    name: 'Kudelski: Token Swap Slippage Missing',
    severity: 'high',
    pattern: /swap|exchange(?![\s\S]{0,100}minimum_amount|slippage)/i,
    description: 'Token swap without slippage protection.',
    recommendation: 'Implement minimum output amount checks.'
  },
  {
    id: 'SOL2285',
    name: 'Kudelski: Shared Memory Vulnerability',
    severity: 'high',
    pattern: /shared_memory|SharedMemory(?![\s\S]{0,50}validate)/i,
    description: 'Shared memory access without validation.',
    recommendation: 'Validate shared memory before use.'
  },
  {
    id: 'SOL2286',
    name: 'Kudelski: Synthetify Collateral Check',
    severity: 'critical',
    pattern: /synthetic|collateral(?![\s\S]{0,100}ratio|threshold)/i,
    description: 'Synthetic asset without collateral ratio check.',
    recommendation: 'Enforce minimum collateralization ratios.'
  },
  {
    id: 'SOL2287',
    name: 'Kudelski: Solido Stake Validation',
    severity: 'high',
    pattern: /stake_account|StakeAccount(?![\s\S]{0,100}activation_epoch)/i,
    description: 'Stake account without activation epoch check.',
    recommendation: 'Verify stake account activation status.'
  },
  {
    id: 'SOL2288',
    name: 'Kudelski: Friktion Volt Risk',
    severity: 'high',
    pattern: /volt|option(?![\s\S]{0,100}expiry|strike)/i,
    description: 'Options vault without expiry validation.',
    recommendation: 'Validate option expiry and strike prices.'
  },
  {
    id: 'SOL2289',
    name: 'Kudelski: Hubble Stability Check',
    severity: 'high',
    pattern: /stability_pool|StabilityPool(?![\s\S]{0,100}debt_ceiling)/i,
    description: 'Stability pool without debt ceiling enforcement.',
    recommendation: 'Enforce debt ceiling limits.'
  },
  {
    id: 'SOL2290',
    name: 'Kudelski: Swim Bridge Decimals',
    severity: 'medium',
    pattern: /bridge|cross_chain(?![\s\S]{0,100}decimals)/i,
    description: 'Cross-chain bridge without decimal normalization.',
    recommendation: 'Normalize token decimals across chains.'
  },
  {
    id: 'SOL2291',
    name: 'Kudelski: Marinade Delayed Unstake',
    severity: 'medium',
    pattern: /unstake|withdraw_stake(?![\s\S]{0,100}delay|cooldown)/i,
    description: 'Unstaking without delay mechanism.',
    recommendation: 'Implement unstaking delay period.'
  },
  {
    id: 'SOL2292',
    name: 'Kudelski: Hedge CDP Validation',
    severity: 'high',
    pattern: /cdp|vault(?![\s\S]{0,100}health_factor|collateral_ratio)/i,
    description: 'CDP without health factor validation.',
    recommendation: 'Check vault health factor before operations.'
  },
  {
    id: 'SOL2293',
    name: 'Kudelski: Orca Whirlpool Tick',
    severity: 'high',
    pattern: /tick|whirlpool(?![\s\S]{0,100}spacing|bounds)/i,
    description: 'Whirlpool tick without bounds checking.',
    recommendation: 'Validate tick spacing and bounds.'
  },
  {
    id: 'SOL2294',
    name: 'Kudelski: Aldrin DEX Order',
    severity: 'medium',
    pattern: /order_book|OrderBook(?![\s\S]{0,100}expiry|cancel)/i,
    description: 'Order book without order expiry handling.',
    recommendation: 'Implement order expiry and cancellation.'
  },
  {
    id: 'SOL2295',
    name: 'Kudelski: Audius Governance Race',
    severity: 'high',
    pattern: /governance|proposal(?![\s\S]{0,100}snapshot|block_height)/i,
    description: 'Governance without snapshot mechanism.',
    recommendation: 'Use snapshot-based voting power.'
  },

  // Neodyme Audit Patterns (SOL2296-SOL2310)
  {
    id: 'SOL2296',
    name: 'Neodyme: Mango Oracle Staleness',
    severity: 'critical',
    pattern: /oracle|price_feed(?![\s\S]{0,100}last_update|staleness)/i,
    description: 'Oracle price without staleness check (Mango pattern).',
    recommendation: 'Verify oracle price freshness.'
  },
  {
    id: 'SOL2297',
    name: 'Neodyme: Wormhole SignatureSet',
    severity: 'critical',
    pattern: /signature_set|SignatureSet(?![\s\S]{0,100}guardian_count)/i,
    description: 'Signature set without guardian count validation.',
    recommendation: 'Verify guardian quorum in signature sets.'
  },
  {
    id: 'SOL2298',
    name: 'Neodyme: SPL Lending Precision',
    severity: 'high',
    pattern: /interest|rate(?![\s\S]{0,100}precision|decimals)/i,
    description: 'Interest rate calculation without precision handling.',
    recommendation: 'Use high-precision arithmetic for rates.'
  },
  {
    id: 'SOL2299',
    name: 'Neodyme: Rounding Direction',
    severity: 'high',
    pattern: /\.round\(\)|as\s+u\d+(?![\s\S]{0,30}ceil|floor)/i,
    description: 'Rounding without explicit direction.',
    recommendation: 'Use explicit ceil/floor for financial math.'
  },
  {
    id: 'SOL2300',
    name: 'Neodyme: Debridge Finality',
    severity: 'critical',
    pattern: /bridge_message|cross_chain(?![\s\S]{0,100}finalized|confirmations)/i,
    description: 'Cross-chain message without finality check.',
    recommendation: 'Wait for chain finality before processing.'
  },
  {
    id: 'SOL2301',
    name: 'Neodyme: PoC Attacker Framework',
    severity: 'high',
    pattern: /test|poc(?![\s\S]{0,50}assert|expect)/i,
    description: 'Test code pattern detected in production.',
    recommendation: 'Remove test/PoC code from production.'
  },
  {
    id: 'SOL2302',
    name: 'Neodyme: Common Pitfall Owner',
    severity: 'critical',
    pattern: /AccountInfo[\s\S]{0,50}\.key(?![\s\S]{0,30}owner)/i,
    description: 'Account key check without owner verification.',
    recommendation: 'Always verify account owner with key.'
  },
  {
    id: 'SOL2303',
    name: 'Neodyme: Common Pitfall Signer',
    severity: 'critical',
    pattern: /authority|admin(?![\s\S]{0,50}is_signer|Signer)/i,
    description: 'Authority without signer check.',
    recommendation: 'Verify authority is signer for all admin ops.'
  },
  {
    id: 'SOL2304',
    name: 'Neodyme: Marinade v2 Rate',
    severity: 'high',
    pattern: /exchange_rate|conversion(?![\s\S]{0,100}update_time)/i,
    description: 'Exchange rate without update time check.',
    recommendation: 'Verify rate freshness before conversion.'
  },
  {
    id: 'SOL2305',
    name: 'Neodyme: Solido Validator Selection',
    severity: 'medium',
    pattern: /validator|stake_pool(?![\s\S]{0,100}selection|weight)/i,
    description: 'Validator selection without weighting.',
    recommendation: 'Implement weighted validator selection.'
  },
  {
    id: 'SOL2306',
    name: 'Neodyme: Workshop Level 0',
    severity: 'medium',
    pattern: /seeds\s*=\s*\[(?![\s\S]{0,30}bump)/i,
    description: 'PDA seeds without bump in derivation.',
    recommendation: 'Include bump seed in PDA derivation.'
  },
  {
    id: 'SOL2307',
    name: 'Neodyme: Workshop Level 1',
    severity: 'high',
    pattern: /try_borrow|borrow_mut(?![\s\S]{0,50}RefCell)/i,
    description: 'Mutable borrow without RefCell pattern.',
    recommendation: 'Use RefCell for safe interior mutability.'
  },
  {
    id: 'SOL2308',
    name: 'Neodyme: Workshop Level 2',
    severity: 'high',
    pattern: /checked_|saturating_(?![\s\S]{0,20}unwrap_or)/i,
    description: 'Checked math without default handling.',
    recommendation: 'Handle None case from checked operations.'
  },
  {
    id: 'SOL2309',
    name: 'Neodyme: Workshop Level 3',
    severity: 'critical',
    pattern: /invoke_signed[\s\S]{0,100}(?!seeds_with_bump)/i,
    description: 'invoke_signed without seeds_with_bump pattern.',
    recommendation: 'Use seeds_with_bump for CPI signing.'
  },
  {
    id: 'SOL2310',
    name: 'Neodyme: Workshop Level 4',
    severity: 'high',
    pattern: /discriminator[\s\S]{0,50}(?!unique|8\s*bytes)/i,
    description: 'Account discriminator may not be unique.',
    recommendation: 'Ensure 8-byte unique discriminators.'
  },

  // OtterSec Audit Patterns (SOL2311-SOL2325)
  {
    id: 'SOL2311',
    name: 'OtterSec: LP Token Oracle Manipulation',
    severity: 'critical',
    pattern: /lp_token|liquidity_pool(?![\s\S]{0,100}fair_value|sqrt_price)/i,
    description: 'LP token valuation vulnerable to manipulation.',
    recommendation: 'Use fair LP pricing formula.'
  },
  {
    id: 'SOL2312',
    name: 'OtterSec: Jet Governance PoC',
    severity: 'high',
    pattern: /governance|vote(?![\s\S]{0,100}weight_at_slot)/i,
    description: 'Governance voting without historical weight.',
    recommendation: 'Use slot-based vote weight snapshots.'
  },
  {
    id: 'SOL2313',
    name: 'OtterSec: Cashmere Multisig',
    severity: 'high',
    pattern: /multisig|multi_sig(?![\s\S]{0,100}threshold|quorum)/i,
    description: 'Multisig without threshold validation.',
    recommendation: 'Validate multisig threshold before execution.'
  },
  {
    id: 'SOL2314',
    name: 'OtterSec: Cega Vault Risk',
    severity: 'high',
    pattern: /vault|strategy(?![\s\S]{0,100}max_deposit|cap)/i,
    description: 'Vault without deposit cap enforcement.',
    recommendation: 'Enforce vault deposit caps.'
  },
  {
    id: 'SOL2315',
    name: 'OtterSec: Port Sundial Oracle',
    severity: 'high',
    pattern: /sundial|fixed_rate(?![\s\S]{0,100}oracle_source)/i,
    description: 'Fixed rate without oracle source validation.',
    recommendation: 'Validate oracle sources for rate feeds.'
  },
  {
    id: 'SOL2316',
    name: 'OtterSec: Juiced Yield Risk',
    severity: 'medium',
    pattern: /yield|apy(?![\s\S]{0,100}sustainable|cap)/i,
    description: 'Yield strategy without sustainability check.',
    recommendation: 'Validate yield sustainability.'
  },
  {
    id: 'SOL2317',
    name: 'OtterSec: Solvent NFT Fractionalization',
    severity: 'high',
    pattern: /fractionalize|nft_shares(?![\s\S]{0,100}total_supply)/i,
    description: 'NFT fractionalization without supply tracking.',
    recommendation: 'Track total fractional shares accurately.'
  },
  {
    id: 'SOL2318',
    name: 'OtterSec: Squads MPL Authority',
    severity: 'high',
    pattern: /squad|multisig(?![\s\S]{0,100}member_count)/i,
    description: 'Squad without member count validation.',
    recommendation: 'Validate squad member count for quorum.'
  },
  {
    id: 'SOL2319',
    name: 'OtterSec: Phoenix Order Matching',
    severity: 'high',
    pattern: /order_matching|match_order(?![\s\S]{0,100}price_time_priority)/i,
    description: 'Order matching without price-time priority.',
    recommendation: 'Implement proper order matching rules.'
  },
  {
    id: 'SOL2320',
    name: 'OtterSec: Bottomless Pit Attack',
    severity: 'critical',
    pattern: /pool|liquidity(?![\s\S]{0,100}minimum_liquidity)/i,
    description: 'Pool without minimum liquidity protection.',
    recommendation: 'Lock minimum liquidity to prevent draining.'
  },
  {
    id: 'SOL2321',
    name: 'OtterSec: Auditor Perspective Entry',
    severity: 'medium',
    pattern: /entrypoint|process_instruction(?![\s\S]{0,100}verify_accounts)/i,
    description: 'Entry point without account verification.',
    recommendation: 'Verify all accounts at entry point.'
  },
  {
    id: 'SOL2322',
    name: 'OtterSec: CPI Return Value',
    severity: 'high',
    pattern: /invoke|invoke_signed(?![\s\S]{0,50}\?|Result)/i,
    description: 'CPI without error handling.',
    recommendation: 'Handle CPI return values with ?.'
  },
  {
    id: 'SOL2323',
    name: 'OtterSec: Account Lifecycle',
    severity: 'high',
    pattern: /close_account|close\s*=(?![\s\S]{0,100}rent_destination)/i,
    description: 'Account closure without rent destination.',
    recommendation: 'Specify rent destination on account close.'
  },
  {
    id: 'SOL2324',
    name: 'OtterSec: State Machine Transition',
    severity: 'high',
    pattern: /state\s*=|status\s*=(?![\s\S]{0,50}valid_transition)/i,
    description: 'State transition without validation.',
    recommendation: 'Validate state machine transitions.'
  },
  {
    id: 'SOL2325',
    name: 'OtterSec: Event Ordering',
    severity: 'low',
    pattern: /emit!|msg!(?![\s\S]{0,30}after.*state)/i,
    description: 'Event emitted before state finalized.',
    recommendation: 'Emit events after state changes complete.'
  },

  // Bramah Systems Audit Patterns (SOL2326-SOL2335)
  {
    id: 'SOL2326',
    name: 'Bramah: Crema Fee Accumulator',
    severity: 'high',
    pattern: /fee_accumulator|accumulated_fee(?![\s\S]{0,100}overflow)/i,
    description: 'Fee accumulator vulnerable to overflow.',
    recommendation: 'Use checked math for fee accumulation.'
  },
  {
    id: 'SOL2327',
    name: 'Bramah: Saber StableSwap Invariant',
    severity: 'critical',
    pattern: /stable_swap|curve(?![\s\S]{0,100}invariant_check)/i,
    description: 'StableSwap without invariant verification.',
    recommendation: 'Verify curve invariant after operations.'
  },
  {
    id: 'SOL2328',
    name: 'Bramah: Maple Loan Maturity',
    severity: 'high',
    pattern: /loan|borrow(?![\s\S]{0,100}maturity|due_date)/i,
    description: 'Loan without maturity date enforcement.',
    recommendation: 'Enforce loan maturity dates.'
  },
  {
    id: 'SOL2329',
    name: 'Bramah: Solido Validator Score',
    severity: 'medium',
    pattern: /validator_score|performance(?![\s\S]{0,100}update_period)/i,
    description: 'Validator score without update period.',
    recommendation: 'Implement score update intervals.'
  },
  {
    id: 'SOL2330',
    name: 'Bramah: Emergency Shutdown',
    severity: 'medium',
    pattern: /emergency|pause(?![\s\S]{0,100}guardian|multisig)/i,
    description: 'Emergency shutdown without guardian.',
    recommendation: 'Require guardian/multisig for emergency.'
  },
  {
    id: 'SOL2331',
    name: 'Bramah: Rate Limit Bypass',
    severity: 'high',
    pattern: /rate_limit|throttle(?![\s\S]{0,100}per_epoch|per_slot)/i,
    description: 'Rate limit without time-based enforcement.',
    recommendation: 'Implement slot/epoch-based rate limits.'
  },
  {
    id: 'SOL2332',
    name: 'Bramah: Collateral Rebalance',
    severity: 'high',
    pattern: /rebalance|collateral(?![\s\S]{0,100}atomic)/i,
    description: 'Collateral rebalance not atomic.',
    recommendation: 'Make collateral operations atomic.'
  },
  {
    id: 'SOL2333',
    name: 'Bramah: LP Share Dilution',
    severity: 'high',
    pattern: /lp_shares|mint_lp(?![\s\S]{0,100}total_supply_check)/i,
    description: 'LP share minting without supply check.',
    recommendation: 'Check total supply before minting shares.'
  },
  {
    id: 'SOL2334',
    name: 'Bramah: Auction Reserve Price',
    severity: 'high',
    pattern: /auction|bid(?![\s\S]{0,100}reserve_price|minimum_bid)/i,
    description: 'Auction without reserve price.',
    recommendation: 'Set minimum reserve price for auctions.'
  },
  {
    id: 'SOL2335',
    name: 'Bramah: Insurance Fund',
    severity: 'medium',
    pattern: /insurance|coverage(?![\s\S]{0,100}fund_balance)/i,
    description: 'Insurance without fund balance check.',
    recommendation: 'Verify insurance fund solvency.'
  },

  // Halborn Audit Patterns (SOL2336-SOL2350)
  {
    id: 'SOL2336',
    name: 'Halborn: Cropper AMM Invariant',
    severity: 'critical',
    pattern: /amm|swap(?![\s\S]{0,100}constant_product|xy=k)/i,
    description: 'AMM without constant product invariant.',
    recommendation: 'Verify xy=k invariant on all swaps.'
  },
  {
    id: 'SOL2337',
    name: 'Halborn: GooseFX Swap Router',
    severity: 'high',
    pattern: /router|swap_route(?![\s\S]{0,100}path_validation)/i,
    description: 'Swap router without path validation.',
    recommendation: 'Validate all swap path components.'
  },
  {
    id: 'SOL2338',
    name: 'Halborn: Parrot Protocol Debt',
    severity: 'high',
    pattern: /debt|borrow(?![\s\S]{0,100}debt_ceiling)/i,
    description: 'Protocol without debt ceiling.',
    recommendation: 'Enforce protocol-wide debt ceiling.'
  },
  {
    id: 'SOL2339',
    name: 'Halborn: Phantasia NFT Store',
    severity: 'medium',
    pattern: /nft_store|marketplace(?![\s\S]{0,100}listing_validation)/i,
    description: 'NFT store without listing validation.',
    recommendation: 'Validate NFT listings before sale.'
  },
  {
    id: 'SOL2340',
    name: 'Halborn: Wormhole Guardian Rotation',
    severity: 'critical',
    pattern: /guardian_set|guardians(?![\s\S]{0,100}rotation_delay)/i,
    description: 'Guardian set without rotation delay.',
    recommendation: 'Implement guardian rotation delay.'
  },
  {
    id: 'SOL2341',
    name: 'Halborn: Cross-Chain Replay',
    severity: 'critical',
    pattern: /cross_chain|bridge(?![\s\S]{0,100}chain_id|nonce)/i,
    description: 'Cross-chain message without replay protection.',
    recommendation: 'Include chain ID and nonce in messages.'
  },
  {
    id: 'SOL2342',
    name: 'Halborn: Token Extension Conflict',
    severity: 'high',
    pattern: /token_2022|extension(?![\s\S]{0,100}compatible)/i,
    description: 'Token-2022 extension compatibility not checked.',
    recommendation: 'Verify extension compatibility.'
  },
  {
    id: 'SOL2343',
    name: 'Halborn: Metadata URI Injection',
    severity: 'medium',
    pattern: /metadata_uri|uri(?![\s\S]{0,100}sanitize|validate)/i,
    description: 'Metadata URI without sanitization.',
    recommendation: 'Sanitize all metadata URIs.'
  },
  {
    id: 'SOL2344',
    name: 'Halborn: Royalty Enforcement',
    severity: 'high',
    pattern: /royalty|creator_fee(?![\s\S]{0,100}enforced|required)/i,
    description: 'Royalty not enforced on transfer.',
    recommendation: 'Use enforced royalty standards.'
  },
  {
    id: 'SOL2345',
    name: 'Halborn: Program Upgrade Window',
    severity: 'medium',
    pattern: /upgrade|set_authority(?![\s\S]{0,100}timelock|delay)/i,
    description: 'Program upgrade without timelock.',
    recommendation: 'Implement upgrade timelock.'
  },
  {
    id: 'SOL2346',
    name: 'Halborn: Treasury Sweep',
    severity: 'high',
    pattern: /treasury|sweep(?![\s\S]{0,100}recipient_validation)/i,
    description: 'Treasury sweep without recipient check.',
    recommendation: 'Validate treasury sweep recipients.'
  },
  {
    id: 'SOL2347',
    name: 'Halborn: Staking Reward Calculation',
    severity: 'high',
    pattern: /staking_reward|reward_rate(?![\s\S]{0,100}per_share)/i,
    description: 'Staking reward not using per-share calculation.',
    recommendation: 'Use reward-per-share for fairness.'
  },
  {
    id: 'SOL2348',
    name: 'Halborn: Flash Mint Detection',
    severity: 'critical',
    pattern: /flash_mint|instant_mint(?![\s\S]{0,100}burn_required)/i,
    description: 'Flash mint without burn verification.',
    recommendation: 'Verify flash mint is burned same tx.'
  },
  {
    id: 'SOL2349',
    name: 'Halborn: Order Book DOS',
    severity: 'high',
    pattern: /order_book|orders(?![\s\S]{0,100}max_orders|limit)/i,
    description: 'Order book without order limit.',
    recommendation: 'Limit orders per user/market.'
  },
  {
    id: 'SOL2350',
    name: 'Halborn: Account Rent Attack',
    severity: 'medium',
    pattern: /create_account|init(?![\s\S]{0,100}rent_exempt_check)/i,
    description: 'Account creation without rent exemption check.',
    recommendation: 'Verify rent-exempt minimum on creation.'
  },
];

export function checkBatch57Patterns(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  const content = input.rust?.content || '';
  const fileName = input.path || input.rust?.filePath || 'unknown';

  if (!content) return findings;

  const lines = content.split('\n');

  for (const pattern of BATCH_57_PATTERNS) {
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

export const BATCH_57_COUNT = BATCH_57_PATTERNS.length;
