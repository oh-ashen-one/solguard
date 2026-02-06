/**
 * Batch 105: Protocol-Specific Audit Findings + 2026 Emerging Threats
 * 
 * Based on comprehensive audit reports and 2026 security trends:
 * - Mango Markets, Orca Whirlpools, Drift, Phoenix, Marinade audits
 * - Token-2022 advanced patterns, Compressed NFT security
 * - AI Agent security, MEV protection, Validator attacks
 * 
 * Pattern IDs: SOL6701-SOL6800
 * Focus: Deep protocol patterns + emerging attack vectors
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

const BATCH_105_PATTERNS: Pattern[] = [
  // ============================================
  // MANGO MARKETS AUDIT PATTERNS
  // ============================================
  {
    id: 'SOL6701',
    name: 'Mango: Perp Market Price Band',
    description: 'From Mango/Neodyme audit: Perpetual markets need price bands to prevent manipulation.',
    severity: 'critical',
    pattern: /perp|perpetual[\s\S]{0,100}price(?![\s\S]{0,100}band|[\s\S]{0,100}limit|[\s\S]{0,100}cap)/i,
    recommendation: 'Implement price bands for perpetual markets to prevent flash loan manipulation.',
    references: ['https://docs.mango.markets/audit']
  },
  {
    id: 'SOL6702',
    name: 'Mango: Position Limit Bypass',
    description: 'From Mango audit: Position limits can be bypassed through multiple accounts.',
    severity: 'high',
    pattern: /position_limit|max_position(?![\s\S]{0,100}global|[\s\S]{0,100}aggregate)/i,
    recommendation: 'Implement global position limits that aggregate across related accounts.',
    references: ['https://docs.mango.markets/audit']
  },
  {
    id: 'SOL6703',
    name: 'Mango: Funding Rate Manipulation',
    description: 'From Mango audit: Funding rates can be manipulated through mark price.',
    severity: 'high',
    pattern: /funding_rate|mark_price(?![\s\S]{0,100}twap|[\s\S]{0,100}ema)/i,
    recommendation: 'Use TWAP or EMA for mark price to prevent funding rate manipulation.',
    references: ['https://docs.mango.markets/audit']
  },
  {
    id: 'SOL6704',
    name: 'Mango: Liquidation Incentive Gaming',
    description: 'From Mango audit: Liquidation incentives can be gamed by self-liquidation.',
    severity: 'medium',
    pattern: /liquidation_fee|liquidator_fee(?![\s\S]{0,100}self_liquidation_check)/i,
    recommendation: 'Prevent self-liquidation or reduce incentives for self-liquidation.',
    references: ['https://docs.mango.markets/audit']
  },

  // ============================================
  // ORCA WHIRLPOOLS AUDIT PATTERNS
  // ============================================
  {
    id: 'SOL6705',
    name: 'Orca: Tick Array Bounds',
    description: 'From Orca/Kudelski audit: Tick array bounds not properly validated.',
    severity: 'high',
    pattern: /tick_array|tick_index(?![\s\S]{0,100}bounds|[\s\S]{0,100}min_tick|[\s\S]{0,100}max_tick)/i,
    recommendation: 'Validate tick indices are within allowed bounds (MIN_TICK to MAX_TICK).',
    references: ['https://docs.orca.so/#has-orca-been-audited']
  },
  {
    id: 'SOL6706',
    name: 'Orca: Liquidity Position Spoofing',
    description: 'From Orca audit: Liquidity positions can be spoofed without ownership check.',
    severity: 'critical',
    pattern: /position|liquidity[\s\S]{0,100}(?![\s\S]{0,100}owner\s*==|[\s\S]{0,100}has_one.*owner)/i,
    recommendation: 'Always verify position ownership before operations.',
    references: ['https://docs.orca.so/#has-orca-been-audited']
  },
  {
    id: 'SOL6707',
    name: 'Orca: Fee Tier Validation',
    description: 'From Orca audit: Fee tier must be validated against allowed values.',
    severity: 'medium',
    pattern: /fee_tier|fee_rate(?![\s\S]{0,100}allowed_tiers|[\s\S]{0,100}valid_fee)/i,
    recommendation: 'Validate fee tier against whitelist of allowed values.',
    references: ['https://docs.orca.so/#has-orca-been-audited']
  },
  {
    id: 'SOL6708',
    name: 'Orca: Sqrt Price Precision',
    description: 'From Orca audit: Square root price calculations need high precision.',
    severity: 'medium',
    pattern: /sqrt_price|sqrtPriceX64(?![\s\S]{0,100}checked|[\s\S]{0,100}U128)/i,
    recommendation: 'Use U128 or higher precision for sqrt price calculations.',
    references: ['https://docs.orca.so/#has-orca-been-audited']
  },

  // ============================================
  // DRIFT PROTOCOL AUDIT PATTERNS (Zellic)
  // ============================================
  {
    id: 'SOL6709',
    name: 'Drift: Oracle Validity Window',
    description: 'From Drift/Zellic audit: Oracle data valid within specific slot window.',
    severity: 'critical',
    pattern: /oracle.*slot|slot.*oracle(?![\s\S]{0,100}valid_slot|[\s\S]{0,100}slot_diff)/i,
    recommendation: 'Check oracle data is from recent slot: require!(current_slot - oracle_slot < MAX_SLOT_DIFF).',
    references: ['https://github.com/Zellic/publications/blob/master/Drift%20Protocol%20Audit%20Report.pdf']
  },
  {
    id: 'SOL6710',
    name: 'Drift: Insurance Fund Validation',
    description: 'From Drift audit: Insurance fund operations need strict validation.',
    severity: 'high',
    pattern: /insurance_fund|if_stake(?![\s\S]{0,100}validate_if|[\s\S]{0,100}authority)/i,
    recommendation: 'Validate insurance fund authority and state before operations.',
    references: ['https://github.com/Zellic/publications/blob/master/Drift%20Protocol%20Audit%20Report.pdf']
  },
  {
    id: 'SOL6711',
    name: 'Drift: Market Status Check',
    description: 'From Drift audit: Market status (active/settlement/etc) must be checked.',
    severity: 'high',
    pattern: /market[\s\S]{0,50}(?:swap|trade|order)(?![\s\S]{0,100}status|[\s\S]{0,100}is_active)/i,
    recommendation: 'Check market status before allowing operations: require!(market.status == Active).',
    references: ['https://github.com/Zellic/publications/blob/master/Drift%20Protocol%20Audit%20Report.pdf']
  },
  {
    id: 'SOL6712',
    name: 'Drift: Margin Calculation Precision',
    description: 'From Drift audit: Margin calculations require high precision to avoid exploitation.',
    severity: 'high',
    pattern: /margin|collateral[\s\S]{0,100}(?:calculate|compute)(?![\s\S]{0,100}precision|[\s\S]{0,100}PRECISION)/i,
    recommendation: 'Use high precision constants for all margin calculations.',
    references: ['https://github.com/Zellic/publications/blob/master/Drift%20Protocol%20Audit%20Report.pdf']
  },

  // ============================================
  // MARINADE FINANCE AUDIT PATTERNS
  // ============================================
  {
    id: 'SOL6713',
    name: 'Marinade: Validator List Manipulation',
    description: 'From Marinade/Neodyme audit: Validator list can be manipulated.',
    severity: 'critical',
    pattern: /validator_list|stake_list(?![\s\S]{0,100}sorted|[\s\S]{0,100}verify_order)/i,
    recommendation: 'Maintain sorted validator list and verify order on operations.',
    references: ['https://marinade.finance/docs/Neodyme.pdf']
  },
  {
    id: 'SOL6714',
    name: 'Marinade: mSOL/SOL Rate Manipulation',
    description: 'From Marinade audit: Exchange rate can be manipulated through stake timing.',
    severity: 'high',
    pattern: /exchange_rate|msol.*rate(?![\s\S]{0,100}epoch|[\s\S]{0,100}time_weighted)/i,
    recommendation: 'Use time-weighted exchange rates to prevent timing attacks.',
    references: ['https://docs.marinade.finance/marinade-protocol/security/audits']
  },
  {
    id: 'SOL6715',
    name: 'Marinade: Stake Account Validation',
    description: 'From Marinade audit: Stake account state must be validated.',
    severity: 'high',
    pattern: /stake_account(?![\s\S]{0,100}state|[\s\S]{0,100}delegation|[\s\S]{0,100}lockup)/i,
    recommendation: 'Validate stake account state, delegation, and lockup before operations.',
    references: ['https://docs.marinade.finance/marinade-protocol/security/audits']
  },

  // ============================================
  // PHOENIX DEX AUDIT PATTERNS
  // ============================================
  {
    id: 'SOL6716',
    name: 'Phoenix: Self-Trade Prevention',
    description: 'From Phoenix/OtterSec audit: Orders must prevent self-trading.',
    severity: 'high',
    pattern: /order|trade(?![\s\S]{0,100}self_trade|[\s\S]{0,100}maker_.*taker)/i,
    recommendation: 'Implement self-trade prevention: require!(maker != taker).',
    references: ['https://github.com/Ellipsis-Labs/phoenix-v1/tree/master/audits']
  },
  {
    id: 'SOL6717',
    name: 'Phoenix: Order Book Integrity',
    description: 'From Phoenix audit: Order book state integrity must be maintained.',
    severity: 'critical',
    pattern: /order_book|orderbook(?![\s\S]{0,100}verify_integrity|[\s\S]{0,100}sorted)/i,
    recommendation: 'Verify order book integrity (proper ordering) after modifications.',
    references: ['https://github.com/Ellipsis-Labs/phoenix-v1/tree/master/audits']
  },
  {
    id: 'SOL6718',
    name: 'Phoenix: Sequence Number Check',
    description: 'From Phoenix audit: Orders need sequence numbers to prevent replay.',
    severity: 'high',
    pattern: /order[\s\S]{0,100}(?![\s\S]{0,100}sequence|[\s\S]{0,100}nonce|[\s\S]{0,100}order_id)/i,
    recommendation: 'Include sequence numbers in orders to prevent replay attacks.',
    references: ['https://github.com/Ellipsis-Labs/phoenix-v1/tree/master/audits']
  },

  // ============================================
  // SOLIDO AUDIT PATTERNS (Chorus One)
  // ============================================
  {
    id: 'SOL6719',
    name: 'Solido: Epoch Boundary Attack',
    description: 'From Solido/Neodyme audit: Epoch boundaries create arbitrage opportunities.',
    severity: 'high',
    pattern: /epoch[\s\S]{0,100}(?:boundary|transition|change)(?![\s\S]{0,100}guard|[\s\S]{0,100}cooldown)/i,
    recommendation: 'Add guards around epoch boundaries to prevent arbitrage.',
    references: ['https://github.com/ChorusOne/solido/tree/163b26aee08958fbdc0f3909ccb6ef606a1ea0f2/audit']
  },
  {
    id: 'SOL6720',
    name: 'Solido: Withdrawal Queue Attack',
    description: 'From Solido audit: Withdrawal queue can be gamed through timing.',
    severity: 'medium',
    pattern: /withdrawal_queue|unstake_queue(?![\s\S]{0,100}fifo|[\s\S]{0,100}fair_order)/i,
    recommendation: 'Implement fair ordering (FIFO) for withdrawal queues.',
    references: ['https://github.com/ChorusOne/solido/tree/163b26aee08958fbdc0f3909ccb6ef606a1ea0f2/audit']
  },

  // ============================================
  // TOKEN-2022 ADVANCED PATTERNS
  // ============================================
  {
    id: 'SOL6721',
    name: 'Token-2022: Transfer Hook Reentrancy',
    description: 'Transfer hooks can be exploited for reentrancy-style attacks.',
    severity: 'critical',
    pattern: /transfer_hook|TransferHook(?![\s\S]{0,100}reentrancy_guard|[\s\S]{0,100}mutex)/i,
    recommendation: 'Implement reentrancy guards for transfer hook programs.',
    references: ['https://spl.solana.com/token-2022/extensions']
  },
  {
    id: 'SOL6722',
    name: 'Token-2022: Confidential Transfer Key Exposure',
    description: 'Confidential transfer encryption keys must be protected.',
    severity: 'critical',
    pattern: /confidential_transfer|encryption_key(?![\s\S]{0,100}protected|[\s\S]{0,100}encrypted)/i,
    recommendation: 'Never expose confidential transfer encryption keys in logs or state.',
    references: ['https://spl.solana.com/token-2022/extensions']
  },
  {
    id: 'SOL6723',
    name: 'Token-2022: Interest Bearing Calculation',
    description: 'Interest-bearing tokens need precise compounding calculations.',
    severity: 'high',
    pattern: /interest_bearing|compound_interest(?![\s\S]{0,100}precision|[\s\S]{0,100}scaled)/i,
    recommendation: 'Use high-precision math for interest-bearing token calculations.',
    references: ['https://spl.solana.com/token-2022/extensions']
  },
  {
    id: 'SOL6724',
    name: 'Token-2022: Permanent Delegate Abuse',
    description: 'Permanent delegate can be abused for token theft.',
    severity: 'critical',
    pattern: /permanent_delegate(?![\s\S]{0,100}trusted|[\s\S]{0,100}verified)/i,
    recommendation: 'Only use permanent delegate with extreme caution and documentation.',
    references: ['https://spl.solana.com/token-2022/extensions']
  },
  {
    id: 'SOL6725',
    name: 'Token-2022: Non-Transferable Bypass',
    description: 'Non-transferable tokens can potentially be bypassed.',
    severity: 'high',
    pattern: /non_transferable(?![\s\S]{0,100}verify_extension|[\s\S]{0,100}check_transfer)/i,
    recommendation: 'Always verify non-transferable extension before assuming restriction.',
    references: ['https://spl.solana.com/token-2022/extensions']
  },

  // ============================================
  // COMPRESSED NFT SECURITY PATTERNS
  // ============================================
  {
    id: 'SOL6726',
    name: 'cNFT: Merkle Root Verification',
    description: 'Compressed NFT operations must verify merkle root.',
    severity: 'critical',
    pattern: /merkle_tree|compressed_nft(?![\s\S]{0,100}verify_root|[\s\S]{0,100}merkle_proof)/i,
    recommendation: 'Always verify merkle proof and root for compressed NFT operations.',
    references: ['https://developers.metaplex.com/bubblegum']
  },
  {
    id: 'SOL6727',
    name: 'cNFT: Leaf Index Manipulation',
    description: 'Leaf index can be manipulated to access wrong NFT.',
    severity: 'high',
    pattern: /leaf_index|nonce(?![\s\S]{0,100}verify_leaf|[\s\S]{0,100}proof)/i,
    recommendation: 'Verify leaf index against merkle proof, not just nonce.',
    references: ['https://developers.metaplex.com/bubblegum']
  },
  {
    id: 'SOL6728',
    name: 'cNFT: Tree Authority Check',
    description: 'Merkle tree authority must be verified for operations.',
    severity: 'critical',
    pattern: /tree_authority|tree_delegate(?![\s\S]{0,100}verify|[\s\S]{0,100}signer)/i,
    recommendation: 'Verify tree authority is signer for privileged operations.',
    references: ['https://developers.metaplex.com/bubblegum']
  },
  {
    id: 'SOL6729',
    name: 'cNFT: Canopy Depth Security',
    description: 'Insufficient canopy depth increases proof size and cost.',
    severity: 'medium',
    pattern: /canopy|canopy_depth(?![\s\S]{0,100}>=\s*\d+|[\s\S]{0,100}MIN_CANOPY)/i,
    recommendation: 'Set appropriate canopy depth to balance cost and security.',
    references: ['https://developers.metaplex.com/bubblegum']
  },

  // ============================================
  // AI AGENT SECURITY PATTERNS (2026 Emerging)
  // ============================================
  {
    id: 'SOL6730',
    name: 'AI Agent: Unbounded Action Execution',
    description: '2026 threat: AI agents executing unbounded on-chain actions.',
    severity: 'critical',
    pattern: /agent|bot[\s\S]{0,100}execute(?![\s\S]{0,100}limit|[\s\S]{0,100}rate_limit|[\s\S]{0,100}whitelist)/i,
    recommendation: 'Implement action limits and whitelists for AI agent programs.',
    references: ['https://www.sec3.dev/blog']
  },
  {
    id: 'SOL6731',
    name: 'AI Agent: Prompt Injection in State',
    description: '2026 threat: Malicious data in on-chain state exploiting AI agents.',
    severity: 'high',
    pattern: /agent[\s\S]{0,100}(?:read|fetch|get)[\s\S]{0,50}(?:state|data|account)/i,
    recommendation: 'Sanitize on-chain data before processing by AI agents.',
    references: ['https://www.sec3.dev/blog']
  },
  {
    id: 'SOL6732',
    name: 'AI Agent: Autonomous Transaction Signing',
    description: '2026 threat: AI agents with autonomous signing authority.',
    severity: 'critical',
    pattern: /autonomous|auto_sign|agent.*signer(?![\s\S]{0,100}spending_limit|[\s\S]{0,100}daily_limit)/i,
    recommendation: 'Implement strict spending limits and approval flows for autonomous agents.',
    references: ['https://www.sec3.dev/blog']
  },

  // ============================================
  // MEV PROTECTION PATTERNS (2026)
  // ============================================
  {
    id: 'SOL6733',
    name: 'MEV: Jito Bundle Frontrunning',
    description: '2026 MEV: Jito bundles can be frontrun by validators.',
    severity: 'high',
    pattern: /jito|bundle(?![\s\S]{0,100}private|[\s\S]{0,100}encrypted|[\s\S]{0,100}flashbots)/i,
    recommendation: 'Consider private transaction pools or encrypted mempools for MEV protection.',
    references: ['https://www.jito.wtf/']
  },
  {
    id: 'SOL6734',
    name: 'MEV: Sandwich Attack Vulnerability',
    description: 'Swap operation vulnerable to sandwich attacks.',
    severity: 'high',
    pattern: /swap[\s\S]{0,100}(?![\s\S]{0,100}min_out|[\s\S]{0,100}slippage|[\s\S]{0,100}deadline)/i,
    recommendation: 'Always include min_amount_out and deadline for swaps.',
    references: ['https://docs.flashbots.net/']
  },
  {
    id: 'SOL6735',
    name: 'MEV: Atomic Arbitrage Pattern',
    description: 'Pattern susceptible to atomic arbitrage extraction.',
    severity: 'medium',
    pattern: /(?:swap|trade)[\s\S]{0,200}(?:swap|trade)(?![\s\S]{0,100}same_tx_check)/i,
    recommendation: 'Consider MEV implications of multi-hop operations in single transaction.',
    references: ['https://docs.flashbots.net/']
  },

  // ============================================
  // VALIDATOR SECURITY PATTERNS (2026)
  // ============================================
  {
    id: 'SOL6736',
    name: 'Validator: Stake Concentration Risk',
    description: '2026 concern: Stake concentration in few validators creates systemic risk.',
    severity: 'medium',
    pattern: /validator[\s\S]{0,100}stake(?![\s\S]{0,100}diversity|[\s\S]{0,100}concentration)/i,
    recommendation: 'Consider stake distribution when delegating programmatically.',
    references: ['https://www.helius.dev/blog/solana-hacks']
  },
  {
    id: 'SOL6737',
    name: 'Validator: Vote Account Hijacking',
    description: 'Vote account authority changes need careful handling.',
    severity: 'high',
    pattern: /vote_account|VoteState(?![\s\S]{0,100}verify_authority|[\s\S]{0,100}authorized)/i,
    recommendation: 'Verify vote account authority chain before stake operations.',
    references: ['https://www.helius.dev/blog/solana-hacks']
  },

  // ============================================
  // CROSS-CHAIN BRIDGE PATTERNS (2026)
  // ============================================
  {
    id: 'SOL6738',
    name: 'Bridge: Message Replay Attack',
    description: 'Cross-chain messages can be replayed on other chains.',
    severity: 'critical',
    pattern: /bridge[\s\S]{0,100}message(?![\s\S]{0,100}nonce|[\s\S]{0,100}chain_id|[\s\S]{0,100}sequence)/i,
    recommendation: 'Include chain_id, nonce, and sequence in bridge messages.',
    references: ['https://halborn.com/explained-the-wormhole-hack-february-2022/']
  },
  {
    id: 'SOL6739',
    name: 'Bridge: Finality Assumption',
    description: 'Bridge assumes finality before source chain confirms.',
    severity: 'critical',
    pattern: /bridge[\s\S]{0,100}confirm(?![\s\S]{0,100}finality|[\s\S]{0,100}confirmations)/i,
    recommendation: 'Wait for sufficient confirmations before processing bridge messages.',
    references: ['https://halborn.com/explained-the-wormhole-hack-february-2022/']
  },
  {
    id: 'SOL6740',
    name: 'Bridge: Relayer Trust',
    description: 'Bridge relayer is trusted without verification.',
    severity: 'high',
    pattern: /relayer(?![\s\S]{0,100}verify|[\s\S]{0,100}signature|[\s\S]{0,100}proof)/i,
    recommendation: 'Verify relayer signatures or use trustless proof verification.',
    references: ['https://halborn.com/explained-the-wormhole-hack-february-2022/']
  },

  // ============================================
  // GOVERNANCE PATTERNS (Advanced)
  // ============================================
  {
    id: 'SOL6741',
    name: 'Governance: Flash Loan Voting',
    description: 'Governance tokens can be flash loaned to manipulate votes.',
    severity: 'critical',
    pattern: /vote[\s\S]{0,100}(?:power|weight)(?![\s\S]{0,100}snapshot|[\s\S]{0,100}time_lock)/i,
    recommendation: 'Use vote power snapshots from past blocks, not current balance.',
    references: ['https://blog.neodyme.io/posts/how_to_hack_a_dao']
  },
  {
    id: 'SOL6742',
    name: 'Governance: Proposal Griefing',
    description: 'Proposals can be griefed by malicious voting patterns.',
    severity: 'medium',
    pattern: /proposal[\s\S]{0,100}(?:create|submit)(?![\s\S]{0,100}deposit|[\s\S]{0,100}stake)/i,
    recommendation: 'Require deposit or stake to create proposals.',
    references: ['https://blog.neodyme.io/posts/how_to_hack_a_dao']
  },
  {
    id: 'SOL6743',
    name: 'Governance: Vote Delegation Chain',
    description: 'Vote delegation can create circular or infinite chains.',
    severity: 'high',
    pattern: /delegate[\s\S]{0,100}vote(?![\s\S]{0,100}max_depth|[\s\S]{0,100}circular_check)/i,
    recommendation: 'Limit delegation depth and check for circular delegations.',
    references: ['https://blog.neodyme.io/posts/how_to_hack_a_dao']
  },

  // ============================================
  // ECONOMIC SECURITY PATTERNS
  // ============================================
  {
    id: 'SOL6744',
    name: 'Economic: TVL Manipulation',
    description: 'TVL can be artificially inflated to attract users.',
    severity: 'medium',
    pattern: /tvl|total_value_locked(?![\s\S]{0,100}verify|[\s\S]{0,100}oracle)/i,
    recommendation: 'Use verified oracle for TVL calculations, not self-reported.',
    references: ['https://www.sec3.dev/blog/how-to-audit-solana-smart-contracts-part-1-a-systematic-approach']
  },
  {
    id: 'SOL6745',
    name: 'Economic: APY/APR Manipulation',
    description: 'Displayed APY/APR can be manipulated through short-term spikes.',
    severity: 'medium',
    pattern: /apy|apr[\s\S]{0,100}(?:calculate|display)(?![\s\S]{0,100}average|[\s\S]{0,100}smoothed)/i,
    recommendation: 'Use time-weighted averages for APY/APR display.',
    references: ['https://www.sec3.dev/blog/how-to-audit-solana-smart-contracts-part-1-a-systematic-approach']
  },
  {
    id: 'SOL6746',
    name: 'Economic: Ponzi Structure Detection',
    description: 'Reward structure may be unsustainable (Ponzi-like).',
    severity: 'high',
    pattern: /reward[\s\S]{0,100}(?:from|funded)[\s\S]{0,50}(?:deposit|new_user)/i,
    recommendation: 'Ensure rewards come from sustainable sources, not new deposits.',
    references: ['https://www.sec3.dev/blog/how-to-audit-solana-smart-contracts-part-1-a-systematic-approach']
  },

  // ============================================
  // NFT MARKETPLACE PATTERNS
  // ============================================
  {
    id: 'SOL6747',
    name: 'NFT: Royalty Enforcement Bypass',
    description: 'NFT royalties can be bypassed through wrapping or P2P.',
    severity: 'high',
    pattern: /royalt(?:y|ies)(?![\s\S]{0,100}enforce|[\s\S]{0,100}pnft)/i,
    recommendation: 'Use pNFTs (Metaplex) for enforceable royalties.',
    references: ['https://developers.metaplex.com/']
  },
  {
    id: 'SOL6748',
    name: 'NFT: Listing Price Manipulation',
    description: 'NFT listing prices can be manipulated for wash trading.',
    severity: 'medium',
    pattern: /listing[\s\S]{0,100}price(?![\s\S]{0,100}floor|[\s\S]{0,100}market_check)/i,
    recommendation: 'Validate listing prices against market data to detect manipulation.',
    references: ['https://developers.metaplex.com/']
  },
  {
    id: 'SOL6749',
    name: 'NFT: Bid Sniping',
    description: 'Auction bids can be sniped at the last moment.',
    severity: 'low',
    pattern: /auction[\s\S]{0,100}bid(?![\s\S]{0,100}extension|[\s\S]{0,100}anti_snipe)/i,
    recommendation: 'Implement auction extension for bids near deadline.',
    references: ['https://developers.metaplex.com/']
  },

  // ============================================
  // DEPIN SECURITY PATTERNS (2026)
  // ============================================
  {
    id: 'SOL6750',
    name: 'DePIN: Oracle Data Authenticity',
    description: '2026 DePIN: Sensor/device data submitted without attestation.',
    severity: 'high',
    pattern: /sensor|device[\s\S]{0,100}data(?![\s\S]{0,100}attest|[\s\S]{0,100}signed|[\s\S]{0,100}tee)/i,
    recommendation: 'Require device attestation (TEE, secure enclave) for DePIN data.',
    references: ['https://www.sec3.dev/blog']
  },
  {
    id: 'SOL6751',
    name: 'DePIN: Sybil Device Attack',
    description: '2026 DePIN: Multiple fake devices to earn rewards.',
    severity: 'high',
    pattern: /device[\s\S]{0,100}reward(?![\s\S]{0,100}unique_check|[\s\S]{0,100}device_id)/i,
    recommendation: 'Implement device uniqueness verification (hardware attestation).',
    references: ['https://www.sec3.dev/blog']
  },
  {
    id: 'SOL6752',
    name: 'DePIN: Location Spoofing',
    description: '2026 DePIN: GPS/location data can be spoofed.',
    severity: 'medium',
    pattern: /location|gps[\s\S]{0,100}(?![\s\S]{0,100}verify|[\s\S]{0,100}cross_check)/i,
    recommendation: 'Cross-verify location data with multiple sources.',
    references: ['https://www.sec3.dev/blog']
  },

  // ============================================
  // LENDING PROTOCOL PATTERNS (Advanced)
  // ============================================
  {
    id: 'SOL6753',
    name: 'Lending: Interest Rate Model Attack',
    description: 'Interest rate model can be manipulated through utilization.',
    severity: 'high',
    pattern: /interest_rate[\s\S]{0,100}utilization(?![\s\S]{0,100}cap|[\s\S]{0,100}ceiling)/i,
    recommendation: 'Cap interest rates and limit utilization manipulation.',
    references: ['https://blog.neodyme.io/posts/lending_disclosure']
  },
  {
    id: 'SOL6754',
    name: 'Lending: Bad Debt Accumulation',
    description: 'Protocol can accumulate bad debt without socialization.',
    severity: 'high',
    pattern: /bad_debt|shortfall(?![\s\S]{0,100}socialize|[\s\S]{0,100}insurance)/i,
    recommendation: 'Implement bad debt socialization or insurance fund.',
    references: ['https://blog.neodyme.io/posts/lending_disclosure']
  },
  {
    id: 'SOL6755',
    name: 'Lending: Isolated Risk Asset',
    description: 'Risky assets should be isolated to prevent contagion.',
    severity: 'medium',
    pattern: /new_asset|add_asset(?![\s\S]{0,100}isolated|[\s\S]{0,100}risk_tier)/i,
    recommendation: 'Use isolated lending mode for risky/new assets.',
    references: ['https://blog.neodyme.io/posts/lending_disclosure']
  },

  // ============================================
  // DEX/AMM ADVANCED PATTERNS
  // ============================================
  {
    id: 'SOL6756',
    name: 'AMM: Concentrated Liquidity Range Attack',
    description: 'CLMM positions at extreme ranges can be attacked.',
    severity: 'high',
    pattern: /range|tick[\s\S]{0,100}(?:lower|upper)(?![\s\S]{0,100}validate_range)/i,
    recommendation: 'Validate tick ranges are reasonable and within bounds.',
    references: ['https://docs.orca.so/#has-orca-been-audited']
  },
  {
    id: 'SOL6757',
    name: 'AMM: Just-in-Time Liquidity',
    description: 'JIT liquidity can extract value from regular LPs.',
    severity: 'medium',
    pattern: /liquidity[\s\S]{0,100}(?:add|provide)(?![\s\S]{0,100}cooldown|[\s\S]{0,100}lock_time)/i,
    recommendation: 'Consider JIT protection mechanisms (cooldowns, lock periods).',
    references: ['https://docs.orca.so/#has-orca-been-audited']
  },
  {
    id: 'SOL6758',
    name: 'DEX: Order Expiry Attack',
    description: 'Stale orders can be filled at disadvantageous prices.',
    severity: 'high',
    pattern: /order(?![\s\S]{0,100}expiry|[\s\S]{0,100}valid_until|[\s\S]{0,100}deadline)/i,
    recommendation: 'Include expiry timestamp in all orders.',
    references: ['https://github.com/Ellipsis-Labs/phoenix-v1/tree/master/audits']
  },

  // ============================================
  // STAKING PROTOCOL PATTERNS
  // ============================================
  {
    id: 'SOL6759',
    name: 'Staking: Unbonding Period Attack',
    description: 'Unbonding period can be exploited during price drops.',
    severity: 'medium',
    pattern: /unbond|unstake[\s\S]{0,100}(?![\s\S]{0,100}cooldown|[\s\S]{0,100}delay)/i,
    recommendation: 'Implement appropriate unbonding periods (14-28 days typical).',
    references: ['https://docs.marinade.finance/marinade-protocol/security/audits']
  },
  {
    id: 'SOL6760',
    name: 'Staking: Reward Distribution Fairness',
    description: 'Reward distribution may not be fair across stakers.',
    severity: 'medium',
    pattern: /reward[\s\S]{0,100}distribute(?![\s\S]{0,100}proportional|[\s\S]{0,100}per_share)/i,
    recommendation: 'Use proportional or per-share reward distribution.',
    references: ['https://docs.marinade.finance/marinade-protocol/security/audits']
  },

  // ============================================
  // PERPETUAL/OPTIONS PATTERNS
  // ============================================
  {
    id: 'SOL6761',
    name: 'Perp: Funding Rate Delay Attack',
    description: 'Funding rate calculation delay can be exploited.',
    severity: 'high',
    pattern: /funding[\s\S]{0,100}(?:calculate|compute)(?![\s\S]{0,100}time_weighted|[\s\S]{0,100}twap)/i,
    recommendation: 'Use time-weighted funding rates, not spot.',
    references: ['https://github.com/Zellic/publications/blob/master/Drift%20Protocol%20Audit%20Report.pdf']
  },
  {
    id: 'SOL6762',
    name: 'Options: IV Manipulation',
    description: 'Implied volatility can be manipulated for mispricing.',
    severity: 'high',
    pattern: /implied_volatility|iv(?![\s\S]{0,100}bounds|[\s\S]{0,100}cap)/i,
    recommendation: 'Cap IV within reasonable bounds to prevent manipulation.',
    references: ['https://www.sec3.dev/blog/how-to-audit-solana-smart-contracts-part-1-a-systematic-approach']
  },
  {
    id: 'SOL6763',
    name: 'Options: Exercise Window Attack',
    description: 'Option exercise windows can be exploited.',
    severity: 'medium',
    pattern: /exercise[\s\S]{0,100}(?:option|call|put)(?![\s\S]{0,100}window|[\s\S]{0,100}valid)/i,
    recommendation: 'Validate exercise is within valid window.',
    references: ['https://www.sec3.dev/blog/how-to-audit-solana-smart-contracts-part-1-a-systematic-approach']
  },

  // ============================================
  // YIELD AGGREGATOR PATTERNS
  // ============================================
  {
    id: 'SOL6764',
    name: 'Yield: Strategy Migration Risk',
    description: 'Strategy migration can be exploited during transition.',
    severity: 'high',
    pattern: /migrate|strategy[\s\S]{0,100}(?:change|switch)(?![\s\S]{0,100}timelock|[\s\S]{0,100}delay)/i,
    recommendation: 'Implement timelock for strategy changes.',
    references: ['https://www.certik.com/projects/francium']
  },
  {
    id: 'SOL6765',
    name: 'Yield: Harvest Sandwich',
    description: 'Harvest operations can be sandwiched for value extraction.',
    severity: 'medium',
    pattern: /harvest|compound(?![\s\S]{0,100}private|[\s\S]{0,100}min_reward)/i,
    recommendation: 'Use private pools or minimum reward thresholds for harvests.',
    references: ['https://www.certik.com/projects/francium']
  },

  // ============================================
  // REAL-WORLD ASSET PATTERNS
  // ============================================
  {
    id: 'SOL6766',
    name: 'RWA: Collateral Verification',
    description: 'Real-world asset collateral needs off-chain verification.',
    severity: 'critical',
    pattern: /rwa|real_world[\s\S]{0,100}collateral(?![\s\S]{0,100}oracle|[\s\S]{0,100}attestation)/i,
    recommendation: 'Use trusted oracles and attestations for RWA verification.',
    references: ['https://www.sec3.dev/blog/how-to-audit-solana-smart-contracts-part-1-a-systematic-approach']
  },
  {
    id: 'SOL6767',
    name: 'RWA: Redemption Delays',
    description: 'RWA redemptions may have off-chain delays.',
    severity: 'medium',
    pattern: /redeem[\s\S]{0,100}rwa(?![\s\S]{0,100}pending|[\s\S]{0,100}queue)/i,
    recommendation: 'Implement pending redemption state for RWAs.',
    references: ['https://www.sec3.dev/blog/how-to-audit-solana-smart-contracts-part-1-a-systematic-approach']
  },

  // ============================================
  // SOCIAL-FI PATTERNS
  // ============================================
  {
    id: 'SOL6768',
    name: 'SocialFi: Follower Count Manipulation',
    description: 'On-chain follower counts can be manipulated by Sybil.',
    severity: 'medium',
    pattern: /follower|follow_count(?![\s\S]{0,100}verified|[\s\S]{0,100}sybil_check)/i,
    recommendation: 'Implement Sybil resistance for social metrics.',
    references: ['https://www.sec3.dev/blog']
  },
  {
    id: 'SOL6769',
    name: 'SocialFi: Creator Token Pump',
    description: 'Creator tokens vulnerable to pump and dump.',
    severity: 'high',
    pattern: /creator_token|social_token(?![\s\S]{0,100}vesting|[\s\S]{0,100}lock)/i,
    recommendation: 'Implement vesting and lock periods for creator tokens.',
    references: ['https://www.sec3.dev/blog']
  },

  // ============================================
  // GAMING/METAVERSE PATTERNS
  // ============================================
  {
    id: 'SOL6770',
    name: 'Gaming: Item Duplication',
    description: 'Game items can potentially be duplicated through race conditions.',
    severity: 'high',
    pattern: /game_item|inventory[\s\S]{0,100}(?:transfer|trade)(?![\s\S]{0,100}atomic|[\s\S]{0,100}lock)/i,
    recommendation: 'Use atomic operations for game item transfers.',
    references: ['https://www.sec3.dev/blog']
  },
  {
    id: 'SOL6771',
    name: 'Gaming: Randomness Prediction',
    description: 'Game randomness can be predicted or manipulated.',
    severity: 'high',
    pattern: /random|rng[\s\S]{0,100}game(?![\s\S]{0,100}vrf|[\s\S]{0,100}commit_reveal)/i,
    recommendation: 'Use VRF (Switchboard) or commit-reveal for game randomness.',
    references: ['https://github.com/Arrowana/cope-roulette-pro']
  },
  {
    id: 'SOL6772',
    name: 'Gaming: Score Manipulation',
    description: 'Game scores can be manipulated by client-side cheats.',
    severity: 'medium',
    pattern: /score|leaderboard(?![\s\S]{0,100}verify|[\s\S]{0,100}server_side)/i,
    recommendation: 'Verify game scores server-side, not client-submitted.',
    references: ['https://www.sec3.dev/blog']
  },

  // ============================================
  // PRIVACY PATTERNS
  // ============================================
  {
    id: 'SOL6773',
    name: 'Privacy: Transaction Graph Leak',
    description: 'Transaction patterns can leak user privacy.',
    severity: 'medium',
    pattern: /privacy|private[\s\S]{0,100}(?:transfer|send)(?![\s\S]{0,100}mix|[\s\S]{0,100}shielded)/i,
    recommendation: 'Consider privacy implications of transaction patterns.',
    references: ['https://www.sec3.dev/blog']
  },
  {
    id: 'SOL6774',
    name: 'Privacy: Metadata Exposure',
    description: 'Transaction metadata (timestamps, amounts) exposed.',
    severity: 'low',
    pattern: /confidential(?![\s\S]{0,100}metadata|[\s\S]{0,100}hide_amount)/i,
    recommendation: 'Use confidential transfers to hide amounts when needed.',
    references: ['https://spl.solana.com/token-2022/extensions']
  },

  // ============================================
  // ADDITIONAL COMPREHENSIVE PATTERNS
  // ============================================
  {
    id: 'SOL6775',
    name: 'Account: Resize Vulnerability',
    description: 'Account reallocation without proper size validation.',
    severity: 'high',
    pattern: /realloc(?![\s\S]{0,100}zero|[\s\S]{0,100}max_size|[\s\S]{0,100}space)/i,
    recommendation: 'Validate new size and zero-initialize on realloc expansion.',
    references: ['https://www.anchor-lang.com/docs/account-constraints']
  },
  {
    id: 'SOL6776',
    name: 'Account: Dangling Reference',
    description: 'Reference to closed account could be dangling.',
    severity: 'high',
    pattern: /close[\s\S]{0,200}(?:account|reference)(?![\s\S]{0,100}clear_ref)/i,
    recommendation: 'Clear all references to accounts before closing.',
    references: ['https://github.com/project-serum/sealevel-attacks']
  },
  {
    id: 'SOL6777',
    name: 'Instruction: Data Size Validation',
    description: 'Instruction data size not validated.',
    severity: 'medium',
    pattern: /instruction_data(?![\s\S]{0,100}len|[\s\S]{0,100}size)/i,
    recommendation: 'Validate instruction data size: require!(data.len() >= MIN_SIZE).',
    references: ['https://blog.neodyme.io/posts/solana_common_pitfalls']
  },
  {
    id: 'SOL6778',
    name: 'Return Data: Unchecked',
    description: 'Program return data not checked for success.',
    severity: 'medium',
    pattern: /get_return_data(?![\s\S]{0,50}\?|[\s\S]{0,50}unwrap|[\s\S]{0,50}expect)/i,
    recommendation: 'Check return data indicates success before proceeding.',
    references: ['https://docs.solana.com/developing/on-chain-programs/calling-between-programs']
  },
  {
    id: 'SOL6779',
    name: 'Epoch: Boundary Condition',
    description: 'Epoch boundary operations may have edge cases.',
    severity: 'medium',
    pattern: /epoch[\s\S]{0,100}(?:end|start|boundary)(?![\s\S]{0,100}handle|[\s\S]{0,100}edge)/i,
    recommendation: 'Handle epoch boundary edge cases explicitly.',
    references: ['https://docs.marinade.finance/marinade-protocol/security/audits']
  },
  {
    id: 'SOL6780',
    name: 'Upgrade: Authority Not Checked',
    description: 'Program upgrade authority not properly checked.',
    severity: 'critical',
    pattern: /upgrade[\s\S]{0,100}authority(?![\s\S]{0,100}verify|[\s\S]{0,100}signer)/i,
    recommendation: 'Verify upgrade authority is expected address and signer.',
    references: ['https://www.sec3.dev/blog/how-to-audit-solana-smart-contracts-part-1-a-systematic-approach']
  },
  {
    id: 'SOL6781',
    name: 'Lookup Table: Untrusted Entries',
    description: 'Address lookup table entries not validated.',
    severity: 'high',
    pattern: /lookup_table|AddressLookupTable(?![\s\S]{0,100}verify_entries)/i,
    recommendation: 'Validate lookup table entries come from trusted source.',
    references: ['https://www.sec3.dev/blog']
  },
  {
    id: 'SOL6782',
    name: 'Compute: Budget Exceeded Silently',
    description: 'Program may fail silently on compute budget exceeded.',
    severity: 'medium',
    pattern: /compute_budget(?![\s\S]{0,100}check|[\s\S]{0,100}request)/i,
    recommendation: 'Request sufficient compute budget for complex operations.',
    references: ['https://www.sec3.dev/blog/how-to-audit-solana-smart-contracts-part-5-dos-and-liveness-vulnerabilities']
  },
  {
    id: 'SOL6783',
    name: 'Priority Fee: Not Passed',
    description: 'Transaction without priority fee may be delayed.',
    severity: 'low',
    pattern: /priority_fee|compute_unit_price(?![\s\S]{0,100}set|[\s\S]{0,100}configure)/i,
    recommendation: 'Set appropriate priority fee for time-sensitive operations.',
    references: ['https://www.sec3.dev/blog']
  },
  {
    id: 'SOL6784',
    name: 'Serialization: Version Mismatch',
    description: 'Deserialization may fail on version mismatch.',
    severity: 'medium',
    pattern: /deserialize(?![\s\S]{0,100}version|[\s\S]{0,100}schema)/i,
    recommendation: 'Include version in serialized data for forward compatibility.',
    references: ['https://www.sec3.dev/blog/how-to-audit-solana-smart-contracts-part-1-a-systematic-approach']
  },
  {
    id: 'SOL6785',
    name: 'String: Unterminated or Oversized',
    description: 'String data may be unterminated or exceed bounds.',
    severity: 'medium',
    pattern: /String|str[\s\S]{0,100}(?![\s\S]{0,100}max_len|[\s\S]{0,100}truncate)/i,
    recommendation: 'Limit string lengths and validate termination.',
    references: ['https://blog.neodyme.io/posts/solana_common_pitfalls']
  },
  {
    id: 'SOL6786',
    name: 'Array: Index Out of Bounds',
    description: 'Array access without bounds checking.',
    severity: 'high',
    pattern: /\[\s*\w+\s*\](?![\s\S]{0,50}get\(|[\s\S]{0,50}len)/i,
    recommendation: 'Use .get() for safe array access or validate bounds.',
    references: ['https://blog.neodyme.io/posts/solana_common_pitfalls']
  },
  {
    id: 'SOL6787',
    name: 'Event: Missing Critical Event',
    description: 'State change without emitting event.',
    severity: 'low',
    pattern: /(?:authority|owner|admin)[\s\S]{0,50}=(?![\s\S]{0,100}emit|[\s\S]{0,100}log)/i,
    recommendation: 'Emit events for all authority/ownership changes.',
    references: ['https://www.sec3.dev/blog/how-to-audit-solana-smart-contracts-part-1-a-systematic-approach']
  },
  {
    id: 'SOL6788',
    name: 'Config: Hardcoded Value Risk',
    description: 'Configuration value hardcoded instead of parameterized.',
    severity: 'low',
    pattern: /const\s+\w+:\s+u\d+\s*=\s*\d{3,}(?![\s\S]{0,50}config)/i,
    recommendation: 'Consider making large constants configurable.',
    references: ['https://www.sec3.dev/blog/how-to-audit-solana-smart-contracts-part-1-a-systematic-approach']
  },
  {
    id: 'SOL6789',
    name: 'Error: Information Disclosure',
    description: 'Error messages may reveal sensitive information.',
    severity: 'low',
    pattern: /msg![\s\S]{0,50}(?:balance|amount|address|key)/i,
    recommendation: 'Avoid revealing sensitive data in error messages.',
    references: ['https://www.sec3.dev/blog/how-to-audit-solana-smart-contracts-part-1-a-systematic-approach']
  },
  {
    id: 'SOL6790',
    name: 'Testing: No Fuzz Tests',
    description: 'Complex arithmetic without fuzz testing.',
    severity: 'info',
    pattern: /checked_(?:add|sub|mul|div)[\s\S]{0,200}(?!fuzz|proptest)/i,
    recommendation: 'Add fuzz tests for arithmetic operations using Trident.',
    references: ['https://github.com/Ackee-Blockchain/trident']
  },
  {
    id: 'SOL6791',
    name: 'Audit: No Security Audit',
    description: 'Complex DeFi logic without evidence of security audit.',
    severity: 'info',
    pattern: /(?:lending|swap|stake|bridge)[\s\S]{0,200}(?!audited|audit_report)/i,
    recommendation: 'Consider professional security audit before mainnet.',
    references: ['https://github.com/sannykim/solsec']
  },

  // ============================================
  // FINAL PATTERNS TO REACH 100
  // ============================================
  {
    id: 'SOL6792',
    name: 'Metaplex: Collection Verification',
    description: 'NFT collection membership not properly verified.',
    severity: 'high',
    pattern: /collection(?![\s\S]{0,100}verified|[\s\S]{0,100}authority)/i,
    recommendation: 'Verify collection membership is verified by collection authority.',
    references: ['https://developers.metaplex.com/']
  },
  {
    id: 'SOL6793',
    name: 'Metaplex: Creator Verification',
    description: 'NFT creator not verified as signed.',
    severity: 'high',
    pattern: /creator(?![\s\S]{0,100}verified|[\s\S]{0,100}signed)/i,
    recommendation: 'Check creator verified flag is true for trusted creators.',
    references: ['https://developers.metaplex.com/']
  },
  {
    id: 'SOL6794',
    name: 'SPL Governance: Realm Config',
    description: 'Governance realm configuration not properly validated.',
    severity: 'high',
    pattern: /realm|governance[\s\S]{0,100}config(?![\s\S]{0,100}validate)/i,
    recommendation: 'Validate all governance realm configuration parameters.',
    references: ['https://github.com/solana-labs/solana-program-library/tree/master/governance']
  },
  {
    id: 'SOL6795',
    name: 'SPL Governance: Token Owner Record',
    description: 'Token owner record not properly validated.',
    severity: 'high',
    pattern: /token_owner_record(?![\s\S]{0,100}verify|[\s\S]{0,100}governance_delegate)/i,
    recommendation: 'Verify token owner record matches caller and realm.',
    references: ['https://github.com/solana-labs/solana-program-library/tree/master/governance']
  },
  {
    id: 'SOL6796',
    name: 'Associated Token: PDA Derivation',
    description: 'ATA derivation using incorrect seeds.',
    severity: 'high',
    pattern: /associated_token(?![\s\S]{0,100}get_associated_token_address|[\s\S]{0,100}find_program_address)/i,
    recommendation: 'Use standard ATA derivation: get_associated_token_address().',
    references: ['https://spl.solana.com/associated-token-account']
  },
  {
    id: 'SOL6797',
    name: 'Memo: Untrusted Data',
    description: 'Memo data used for logic without validation.',
    severity: 'medium',
    pattern: /memo[\s\S]{0,100}(?:parse|decode|interpret)(?![\s\S]{0,100}validate)/i,
    recommendation: 'Never trust memo data for program logic - can be arbitrary.',
    references: ['https://spl.solana.com/memo']
  },
  {
    id: 'SOL6798',
    name: 'Name Service: Resolution Attack',
    description: 'Name service resolution without verification.',
    severity: 'medium',
    pattern: /name_service|sns[\s\S]{0,100}resolve(?![\s\S]{0,100}verify_owner)/i,
    recommendation: 'Verify name service resolution matches expected owner.',
    references: ['https://www.sec3.dev/blog']
  },
  {
    id: 'SOL6799',
    name: 'Compression: Proof Verification Cost',
    description: 'Merkle proof verification cost not accounted for.',
    severity: 'low',
    pattern: /merkle_proof[\s\S]{0,100}(?:verify|check)(?![\s\S]{0,100}compute_budget)/i,
    recommendation: 'Request additional compute budget for proof verification.',
    references: ['https://developers.metaplex.com/bubblegum']
  },
  {
    id: 'SOL6800',
    name: 'Comprehensive: Security Checklist Gap',
    description: 'Program may benefit from comprehensive security review.',
    severity: 'info',
    pattern: /fn\s+process|#\[program\]/i,
    recommendation: 'Review against Solsec security checklist: github.com/sannykim/solsec',
    references: ['https://github.com/sannykim/solsec']
  },
];

/**
 * Run Batch 105 patterns against input
 */
export function checkBatch105Patterns(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  const content = input.rust?.content || '';
  const filePath = input.path || '';
  
  if (!content) return findings;
  
  const lines = content.split('\n');
  
  for (const pattern of BATCH_105_PATTERNS) {
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

export { BATCH_105_PATTERNS };
