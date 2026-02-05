/**
 * SolGuard Security Patterns - Batch 54
 * 
 * 70 Patterns (SOL2071-SOL2140)
 * Source: Helius Complete Exploit History + 2025 Security Research
 * 
 * Categories:
 * - Solend-style Auth Bypass (SOL2071-SOL2085)
 * - Wormhole-style Signature Bypass (SOL2086-SOL2095)
 * - Cashio-style Mint Validation (SOL2096-SOL2105)
 * - Crema-style Tick Spoofing (SOL2106-SOL2115)
 * - Program Closure Risks (SOL2116-SOL2125)
 * - 2025 DeFi Emerging Patterns (SOL2126-SOL2140)
 */

import type { PatternInput, Finding } from './index.js';

/** Batch 54 Patterns: Helius Exploits + 2025 Emerging */
export const BATCH_54_PATTERNS = [
  // ========== Solend-style Auth Bypass (SOL2071-SOL2085) ==========
  {
    id: 'SOL2071',
    name: 'UpdateReserveConfig Auth Bypass',
    severity: 'critical' as const,
    pattern: /update.*reserve.*config|reserve.*update|config.*update/i,
    description: 'Reserve config update without proper lending market ownership validation. An attacker can create their own lending market and pass it to bypass admin checks (Solend Aug 2021).',
    recommendation: 'Verify lending market ownership before allowing reserve config updates. Use has_one constraint on lending_market authority.'
  },
  {
    id: 'SOL2072',
    name: 'Lending Market Ownership Bypass',
    severity: 'critical' as const,
    pattern: /lending_market|LendingMarket[\s\S]{0,100}(?!has_one|owner\s*==)/i,
    description: 'Lending market passed as account without verifying caller owns it. Attacker can substitute their own market.',
    recommendation: 'Add has_one = lending_market constraint or verify lending_market.owner == authority.key().'
  },
  {
    id: 'SOL2073',
    name: 'Liquidation Threshold Manipulation',
    severity: 'critical' as const,
    pattern: /liquidation_threshold|ltv|loan_to_value[\s\S]{0,50}(?:=|update)/i,
    description: 'Liquidation threshold can be modified without proper authorization (Solend exploit vector).',
    recommendation: 'Require multisig or timelock for liquidation parameter changes.'
  },
  {
    id: 'SOL2074',
    name: 'Liquidation Bonus Inflation',
    severity: 'high' as const,
    pattern: /liquidation_bonus|liquidator_bonus[\s\S]{0,50}(?:=|update|set)/i,
    description: 'Liquidation bonus can be inflated to steal from liquidated positions.',
    recommendation: 'Cap liquidation bonus at reasonable maximum (e.g., 15%) and require governance for changes.'
  },
  {
    id: 'SOL2075',
    name: 'Reserve Configuration Race',
    severity: 'high' as const,
    pattern: /reserve(?:_config)?[\s\S]{0,100}(?:update|modify|set)[\s\S]{0,50}(?!timelock|delay)/i,
    description: 'Reserve config changes take effect immediately, allowing front-run attacks.',
    recommendation: 'Add timelock delay for configuration changes.'
  },
  {
    id: 'SOL2076',
    name: 'Admin Lending Market Substitution',
    severity: 'critical' as const,
    pattern: /admin|authority[\s\S]{0,100}market(?:_account)?/i,
    description: 'Admin can substitute lending market to bypass checks.',
    recommendation: 'Hardcode or derive lending market address, never accept as input for admin functions.'
  },
  {
    id: 'SOL2077',
    name: 'Borrowing Suspension Bypass',
    severity: 'high' as const,
    pattern: /borrow(?:ing)?[\s\S]{0,50}(?:suspend|pause|disable)[\s\S]{0,50}(?!require|assert)/i,
    description: 'Borrowing suspension can be bypassed or may not be checked during borrows.',
    recommendation: 'Check suspension status at the start of every borrow instruction.'
  },
  {
    id: 'SOL2078',
    name: 'Bot Liquidator Privilege',
    severity: 'medium' as const,
    pattern: /liquidator(?:_bot)?|bot_liquidat/i,
    description: 'Protocol liquidator bot may have undue privileges over user positions.',
    recommendation: 'Ensure liquidator bots follow same rules as external liquidators.'
  },
  {
    id: 'SOL2079',
    name: 'Reserve State Desync',
    severity: 'high' as const,
    pattern: /reserve[\s\S]{0,50}state[\s\S]{0,50}(?!refresh|reload|update)/i,
    description: 'Reserve state not refreshed before critical operations.',
    recommendation: 'Always refresh reserve state before reads in same transaction.'
  },
  {
    id: 'SOL2080',
    name: 'Interest Rate Model Injection',
    severity: 'high' as const,
    pattern: /interest_rate|rate_model[\s\S]{0,50}(?:=|set|update)/i,
    description: 'Interest rate model can be injected/changed maliciously.',
    recommendation: 'Validate interest rate model address against allowlist.'
  },
  {
    id: 'SOL2081',
    name: 'Collateral Factor Manipulation',
    severity: 'critical' as const,
    pattern: /collateral_factor|cf[\s\S]{0,30}(?:=|set|update)/i,
    description: 'Collateral factor changes can make positions instantly liquidatable.',
    recommendation: 'Require governance vote and delay for collateral factor changes.'
  },
  {
    id: 'SOL2082',
    name: 'Lending Pool Admin Takeover',
    severity: 'critical' as const,
    pattern: /(?:lending_)?pool[\s\S]{0,50}admin[\s\S]{0,50}(?:=|transfer|set)/i,
    description: 'Pool admin can be transferred without proper safeguards.',
    recommendation: 'Require two-step admin transfer with acceptance confirmation.'
  },
  {
    id: 'SOL2083',
    name: 'Reserve Withdraw Authority',
    severity: 'high' as const,
    pattern: /reserve[\s\S]{0,50}withdraw(?:_authority)?/i,
    description: 'Reserve withdraw authority may allow unauthorized withdrawals.',
    recommendation: 'Restrict reserve withdrawals to protocol PDAs only.'
  },
  {
    id: 'SOL2084',
    name: 'Oracle Price Admin Override',
    severity: 'critical' as const,
    pattern: /(?:oracle|price)[\s\S]{0,50}admin[\s\S]{0,30}override/i,
    description: 'Admin can override oracle prices, enabling manipulation.',
    recommendation: 'Remove admin price override capability or require multisig + delay.'
  },
  {
    id: 'SOL2085',
    name: 'Emergency Liquidation Mode',
    severity: 'high' as const,
    pattern: /emergency[\s\S]{0,50}liquidat/i,
    description: 'Emergency liquidation mode may allow exploitative liquidations.',
    recommendation: 'Cap emergency mode privileges, require timelock to activate.'
  },

  // ========== Wormhole-style Signature Bypass (SOL2086-SOL2095) ==========
  {
    id: 'SOL2086',
    name: 'Guardian Signature Verification Bypass',
    severity: 'critical' as const,
    pattern: /guardian[\s\S]{0,100}(?:verify|signature|sign)[\s\S]{0,50}(?!require|assert|check)/i,
    description: 'Guardian signatures not properly verified (Wormhole $326M exploit pattern).',
    recommendation: 'Always verify guardian signatures against known guardian set with quorum.'
  },
  {
    id: 'SOL2087',
    name: 'Signature Set Spoofing',
    severity: 'critical' as const,
    pattern: /signature_set|SignatureSet[\s\S]{0,100}(?!owner_check|verify_owner)/i,
    description: 'Signature set account can be spoofed (Wormhole exploit pattern).',
    recommendation: 'Verify signature set is owned by expected program and properly initialized.'
  },
  {
    id: 'SOL2088',
    name: 'VAA Validation Incomplete',
    severity: 'critical' as const,
    pattern: /vaa|VAA[\s\S]{0,100}(?!verify_signatures|check_guardian)/i,
    description: 'Verified Action Approval (VAA) not fully validated.',
    recommendation: 'Verify all VAA fields including guardian signatures, timestamp, and sequence.'
  },
  {
    id: 'SOL2089',
    name: 'Cross-Chain Message Forgery',
    severity: 'critical' as const,
    pattern: /cross_chain[\s\S]{0,50}message[\s\S]{0,50}(?!verify|validate)/i,
    description: 'Cross-chain messages can be forged without proper attestation.',
    recommendation: 'Require multiple independent attestations for cross-chain messages.'
  },
  {
    id: 'SOL2090',
    name: 'Bridge Guardian Quorum',
    severity: 'critical' as const,
    pattern: /guardian[\s\S]{0,50}quorum[\s\S]{0,50}(?!>=|threshold)/i,
    description: 'Guardian quorum not checked before accepting bridge messages.',
    recommendation: 'Require 2/3+ guardian signatures for any bridge operation.'
  },
  {
    id: 'SOL2091',
    name: 'Wrapped Token Mint Authority',
    severity: 'critical' as const,
    pattern: /wrapped[\s\S]{0,30}(?:token|mint)[\s\S]{0,50}authority/i,
    description: 'Wrapped token mint authority may be compromised or bypassed.',
    recommendation: 'Mint authority must be PDA derived from verified bridge program.'
  },
  {
    id: 'SOL2092',
    name: 'Bridge Finality Check',
    severity: 'high' as const,
    pattern: /bridge[\s\S]{0,50}(?:transfer|deposit|withdraw)[\s\S]{0,50}(?!finality|confirm)/i,
    description: 'Bridge operations without checking source chain finality.',
    recommendation: 'Wait for sufficient block confirmations on source chain before minting.'
  },
  {
    id: 'SOL2093',
    name: 'Relayer Trust Assumption',
    severity: 'high' as const,
    pattern: /relayer[\s\S]{0,50}(?:submit|relay|forward)/i,
    description: 'Relayer is trusted to submit valid messages without verification.',
    recommendation: 'Verify message content on-chain, never trust relayer-provided data.'
  },
  {
    id: 'SOL2094',
    name: 'Guardian Set Update Race',
    severity: 'critical' as const,
    pattern: /guardian_set[\s\S]{0,50}(?:update|rotate|change)/i,
    description: 'Guardian set update can race with pending operations.',
    recommendation: 'Implement guardian set update delay and process pending ops first.'
  },
  {
    id: 'SOL2095',
    name: 'Ed25519 Precompile Bypass',
    severity: 'critical' as const,
    pattern: /ed25519[\s\S]{0,50}(?:verify|check)[\s\S]{0,50}(?!precompile|native)/i,
    description: 'Ed25519 signature verification not using native precompile.',
    recommendation: 'Use Ed25519 native program for signature verification.'
  },

  // ========== Cashio-style Mint Validation (SOL2096-SOL2105) ==========
  {
    id: 'SOL2096',
    name: 'Collateral Mint Whitelist Missing',
    severity: 'critical' as const,
    pattern: /collateral[\s\S]{0,50}mint[\s\S]{0,50}(?!whitelist|allowlist|verify)/i,
    description: 'Collateral mint not validated against whitelist (Cashio $52M exploit).',
    recommendation: 'Verify collateral mint is in approved whitelist before accepting.'
  },
  {
    id: 'SOL2097',
    name: 'Saber LP Token Validation',
    severity: 'critical' as const,
    pattern: /saber[\s\S]{0,50}(?:lp|pool|swap)/i,
    description: 'Saber LP token not properly validated for mint field.',
    recommendation: 'Verify saber_swap.arrow mint field matches expected collateral.'
  },
  {
    id: 'SOL2098',
    name: 'Root of Trust Missing',
    severity: 'critical' as const,
    pattern: /(?:collateral|backing|reserve)[\s\S]{0,100}(?!root_of_trust|chain_validation)/i,
    description: 'Missing root of trust validation for collateral chain.',
    recommendation: 'Establish and verify complete chain of trust for all collateral.'
  },
  {
    id: 'SOL2099',
    name: 'Fake Account Substitution',
    severity: 'critical' as const,
    pattern: /(?:account|token_account)[\s\S]{0,50}(?:collateral|backing)/i,
    description: 'Fake accounts can be substituted for real collateral.',
    recommendation: 'Verify every account in the collateral chain against known PDAs.'
  },
  {
    id: 'SOL2100',
    name: 'Infinite Mint Vulnerability',
    severity: 'critical' as const,
    pattern: /mint(?:_to)?[\s\S]{0,100}(?!balance_check|limit|cap)/i,
    description: 'Minting without proper balance or cap checks enables infinite mint.',
    recommendation: 'Verify backing ratio before minting, enforce supply caps.'
  },
  {
    id: 'SOL2101',
    name: 'Stablecoin Peg Attack',
    severity: 'critical' as const,
    pattern: /stable(?:coin)?[\s\S]{0,50}(?:mint|redeem|swap)/i,
    description: 'Stablecoin can be minted or redeemed to attack the peg.',
    recommendation: 'Implement mint/redeem fees, rate limits, and oracle validation.'
  },
  {
    id: 'SOL2102',
    name: 'Arrow Account Validation',
    severity: 'high' as const,
    pattern: /arrow[\s\S]{0,50}account/i,
    description: 'Arrow/wrapper account not fully validated.',
    recommendation: 'Verify all nested account fields in wrapper structures.'
  },
  {
    id: 'SOL2103',
    name: 'LP Token Fake Mint',
    severity: 'critical' as const,
    pattern: /lp_mint|pool_mint[\s\S]{0,50}(?!==|verify|check)/i,
    description: 'LP token mint can be faked if not verified against pool.',
    recommendation: 'Derive LP mint address and verify it matches provided account.'
  },
  {
    id: 'SOL2104',
    name: 'Nested Account Trust Chain',
    severity: 'critical' as const,
    pattern: /nested[\s\S]{0,30}account|account[\s\S]{0,30}chain/i,
    description: 'Nested account structure breaks trust chain validation.',
    recommendation: 'Validate each level of nested accounts independently.'
  },
  {
    id: 'SOL2105',
    name: 'Worthless Collateral Deposit',
    severity: 'critical' as const,
    pattern: /deposit[\s\S]{0,50}collateral[\s\S]{0,50}(?!value_check|price_check)/i,
    description: 'Worthless tokens can be deposited as collateral.',
    recommendation: 'Verify collateral value via oracle before accepting deposits.'
  },

  // ========== Crema-style Tick Spoofing (SOL2106-SOL2115) ==========
  {
    id: 'SOL2106',
    name: 'Tick Account Owner Bypass',
    severity: 'critical' as const,
    pattern: /tick(?:_account)?[\s\S]{0,50}(?!owner\s*==|has_one)/i,
    description: 'Tick account ownership not verified (Crema $8.8M exploit).',
    recommendation: 'Verify tick account is owned by expected pool program.'
  },
  {
    id: 'SOL2107',
    name: 'CLMM Position Spoofing',
    severity: 'critical' as const,
    pattern: /(?:clmm|concentrated)[\s\S]{0,50}position[\s\S]{0,50}(?!verify|owner_check)/i,
    description: 'CLMM position can be spoofed to claim excess fees.',
    recommendation: 'Verify position ownership and tick range before fee claims.'
  },
  {
    id: 'SOL2108',
    name: 'Fee Accumulator Manipulation',
    severity: 'critical' as const,
    pattern: /fee(?:_accumulator|_growth)?[\s\S]{0,50}(?:claim|collect|withdraw)/i,
    description: 'Fee accumulator can be manipulated via fake tick accounts.',
    recommendation: 'Recalculate fees from verified tick data, never trust stored values.'
  },
  {
    id: 'SOL2109',
    name: 'Flash Loan + CLMM Attack',
    severity: 'critical' as const,
    pattern: /flash[\s\S]{0,50}(?:clmm|concentrated|tick)/i,
    description: 'Flash loans combined with CLMM manipulation.',
    recommendation: 'Add flash loan protection to CLMM fee calculation.'
  },
  {
    id: 'SOL2110',
    name: 'Tick Range Validation',
    severity: 'high' as const,
    pattern: /tick(?:_lower|_upper|_range)[\s\S]{0,50}(?!validate|check|verify)/i,
    description: 'Tick range not validated for positions.',
    recommendation: 'Verify tick indices are within valid pool range.'
  },
  {
    id: 'SOL2111',
    name: 'Liquidity Delta Overflow',
    severity: 'high' as const,
    pattern: /liquidity[\s\S]{0,30}(?:delta|change|add|remove)/i,
    description: 'Liquidity delta calculation can overflow.',
    recommendation: 'Use checked math for all liquidity calculations.'
  },
  {
    id: 'SOL2112',
    name: 'Sqrt Price Manipulation',
    severity: 'high' as const,
    pattern: /sqrt_price|sqrtPrice[\s\S]{0,50}(?!bounds|validate)/i,
    description: 'Square root price can be manipulated beyond bounds.',
    recommendation: 'Validate sqrt price against tick bounds after operations.'
  },
  {
    id: 'SOL2113',
    name: 'Pool Swap Fee Extraction',
    severity: 'high' as const,
    pattern: /swap_fee|pool_fee[\s\S]{0,50}(?:extract|claim|withdraw)/i,
    description: 'Protocol fees can be extracted improperly.',
    recommendation: 'Only allow fee extraction through verified admin functions.'
  },
  {
    id: 'SOL2114',
    name: 'Observation Account Staleness',
    severity: 'medium' as const,
    pattern: /observation[\s\S]{0,50}(?:oracle|twap)/i,
    description: 'Observation/oracle data may be stale.',
    recommendation: 'Check observation timestamp before using TWAP data.'
  },
  {
    id: 'SOL2115',
    name: 'Position NFT Authority',
    severity: 'high' as const,
    pattern: /position[\s\S]{0,30}(?:nft|token)[\s\S]{0,30}(?:authority|owner)/i,
    description: 'Position NFT authority can be bypassed.',
    recommendation: 'Verify NFT owner matches position authority on all operations.'
  },

  // ========== Program Closure Risks (SOL2116-SOL2125) ==========
  {
    id: 'SOL2116',
    name: 'Accidental Program Close',
    severity: 'critical' as const,
    pattern: /solana\s+program\s+close|close.*program/i,
    description: 'Program can be accidentally closed, locking all funds (OptiFi $661K).',
    recommendation: 'Add deployment review process with multiple approvers.'
  },
  {
    id: 'SOL2117',
    name: 'PDA Fund Recovery',
    severity: 'high' as const,
    pattern: /pda[\s\S]{0,50}(?:close|recovery|rescue)/i,
    description: 'Funds in PDAs may be unrecoverable if program is closed.',
    recommendation: 'Design escape hatches that work even if program is closed.'
  },
  {
    id: 'SOL2118',
    name: 'Upgrade Authority Lock',
    severity: 'high' as const,
    pattern: /upgrade_authority[\s\S]{0,50}(?:=|set|revoke)/i,
    description: 'Upgrade authority can be revoked, making bugs permanent.',
    recommendation: 'Use multisig for upgrade authority, never fully revoke on mainnet.'
  },
  {
    id: 'SOL2119',
    name: 'Program Data Account',
    severity: 'medium' as const,
    pattern: /program_data|ProgramData/i,
    description: 'Program data account manipulation risks.',
    recommendation: 'Verify program data account in deployment scripts.'
  },
  {
    id: 'SOL2120',
    name: 'Buffer Account Cleanup',
    severity: 'low' as const,
    pattern: /buffer[\s\S]{0,30}(?:close|cleanup|recover)/i,
    description: 'Buffer accounts not cleaned up after deployment.',
    recommendation: 'Close buffer accounts after successful deployment to recover rent.'
  },
  {
    id: 'SOL2121',
    name: 'Deployment Script Validation',
    severity: 'high' as const,
    pattern: /deploy[\s\S]{0,50}(?:script|mainnet)/i,
    description: 'Deployment scripts may contain dangerous commands.',
    recommendation: 'Review deployment scripts with multiple team members.'
  },
  {
    id: 'SOL2122',
    name: 'Program Signer Seeds',
    severity: 'medium' as const,
    pattern: /program_signer|signer_seeds/i,
    description: 'Program signer seeds must be consistent across upgrades.',
    recommendation: 'Document and version all PDA seeds used by program.'
  },
  {
    id: 'SOL2123',
    name: 'Close Authority Transfer',
    severity: 'critical' as const,
    pattern: /close_authority[\s\S]{0,50}(?:transfer|set|change)/i,
    description: 'Close authority can be transferred to attacker.',
    recommendation: 'Close authority should only be PDA or multisig.'
  },
  {
    id: 'SOL2124',
    name: 'Immutable Program State',
    severity: 'medium' as const,
    pattern: /immutable[\s\S]{0,30}(?:state|config)/i,
    description: 'Immutable state cannot be fixed if buggy.',
    recommendation: 'Design state migration paths for critical data.'
  },
  {
    id: 'SOL2125',
    name: 'Program Freeze Risk',
    severity: 'high' as const,
    pattern: /program[\s\S]{0,30}freeze|freeze[\s\S]{0,30}program/i,
    description: 'Program can be frozen, halting all operations.',
    recommendation: 'Implement emergency functions that work even when frozen.'
  },

  // ========== 2025 DeFi Emerging Patterns (SOL2126-SOL2140) ==========
  {
    id: 'SOL2126',
    name: 'Intent-Based Order Manipulation',
    severity: 'high' as const,
    pattern: /intent[\s\S]{0,50}(?:order|swap|trade)/i,
    description: 'Intent-based orders can be manipulated by solvers.',
    recommendation: 'Validate solver execution against user intent parameters.'
  },
  {
    id: 'SOL2127',
    name: 'Restaking Slash Cascade',
    severity: 'critical' as const,
    pattern: /restaking[\s\S]{0,50}(?:slash|penalty)/i,
    description: 'Restaking slashing can cascade across protocols.',
    recommendation: 'Implement slashing caps and circuit breakers.'
  },
  {
    id: 'SOL2128',
    name: 'LRT Depeg Attack',
    severity: 'high' as const,
    pattern: /(?:lrt|liquid_restaking)[\s\S]{0,50}(?:price|peg|exchange)/i,
    description: 'Liquid restaking tokens can depeg under stress.',
    recommendation: 'Use oracle prices not DEX prices for LRT valuation.'
  },
  {
    id: 'SOL2129',
    name: 'Points Manipulation',
    severity: 'medium' as const,
    pattern: /(?:points|airdrop)[\s\S]{0,50}(?:farm|accumulate|boost)/i,
    description: 'Points/airdrop farming can be gamed.',
    recommendation: 'Add anti-sybil measures and time-weighted calculations.'
  },
  {
    id: 'SOL2130',
    name: 'NFT Lending Liquidation',
    severity: 'high' as const,
    pattern: /nft[\s\S]{0,50}(?:lending|borrow|collateral)[\s\S]{0,50}liquidat/i,
    description: 'NFT lending liquidations can be manipulated via floor price.',
    recommendation: 'Use TWAP floor price and multiple oracle sources for NFT valuations.'
  },
  {
    id: 'SOL2131',
    name: 'Perpetual Funding Rate Attack',
    severity: 'high' as const,
    pattern: /funding(?:_rate)?[\s\S]{0,50}(?:manipulat|attack|exploit)/i,
    description: 'Perpetual funding rate can be manipulated to extract value.',
    recommendation: 'Cap funding rate changes and use time-weighted averages.'
  },
  {
    id: 'SOL2132',
    name: 'Synthetic Asset Oracle Depeg',
    severity: 'critical' as const,
    pattern: /synthetic[\s\S]{0,50}(?:oracle|price|peg)/i,
    description: 'Synthetic assets can depeg if oracle is manipulated.',
    recommendation: 'Use circuit breakers and multiple price sources for synths.'
  },
  {
    id: 'SOL2133',
    name: 'RWA Token Redemption',
    severity: 'high' as const,
    pattern: /rwa|real_world[\s\S]{0,50}(?:redeem|withdraw|claim)/i,
    description: 'Real-world asset token redemption may not be honored.',
    recommendation: 'Verify legal backing and maintain reserve attestations.'
  },
  {
    id: 'SOL2134',
    name: 'Social Token Rugpull',
    severity: 'high' as const,
    pattern: /social[\s\S]{0,30}token[\s\S]{0,50}(?:mint|authority)/i,
    description: 'Social/creator tokens can be rugged by creator.',
    recommendation: 'Lock mint authority or use bonding curve with locked liquidity.'
  },
  {
    id: 'SOL2135',
    name: 'Prediction Market Settlement',
    severity: 'high' as const,
    pattern: /prediction[\s\S]{0,50}(?:settle|resolve|outcome)/i,
    description: 'Prediction market settlement can be manipulated.',
    recommendation: 'Use decentralized oracle networks for settlement.'
  },
  {
    id: 'SOL2136',
    name: 'Blink Action Validation',
    severity: 'medium' as const,
    pattern: /blink[\s\S]{0,50}action[\s\S]{0,50}(?!validate|verify)/i,
    description: 'Solana Blink actions may not validate parameters.',
    recommendation: 'Validate all blink action parameters server-side.'
  },
  {
    id: 'SOL2137',
    name: 'Compressed NFT Proof',
    severity: 'high' as const,
    pattern: /cnft|compressed[\s\S]{0,30}nft[\s\S]{0,50}(?:proof|verify)/i,
    description: 'Compressed NFT merkle proofs must be verified.',
    recommendation: 'Always verify cNFT proofs against current merkle root.'
  },
  {
    id: 'SOL2138',
    name: 'Token-2022 Extension Conflict',
    severity: 'medium' as const,
    pattern: /token_2022[\s\S]{0,50}extension[\s\S]{0,50}(?:conflict|incompatible)/i,
    description: 'Token-2022 extension combinations may conflict.',
    recommendation: 'Test all extension combinations for compatibility.'
  },
  {
    id: 'SOL2139',
    name: 'Lookup Table Poisoning',
    severity: 'high' as const,
    pattern: /lookup_table|address_lookup[\s\S]{0,50}(?!verify|validate)/i,
    description: 'Address lookup tables can be poisoned with malicious addresses.',
    recommendation: 'Verify lookup table authority before use in transactions.'
  },
  {
    id: 'SOL2140',
    name: 'Priority Fee Griefing',
    severity: 'medium' as const,
    pattern: /priority[\s\S]{0,30}fee[\s\S]{0,50}(?:bid|auction|spam)/i,
    description: 'Priority fee bidding can be used to grief transactions.',
    recommendation: 'Implement transaction bundles and private mempools.'
  },
];

/**
 * Run Batch 54 patterns against input
 */
export function checkBatch54Patterns(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  const content = input.rust?.content || '';
  const fileName = input.path || input.rust?.filePath || 'unknown';
  
  if (!content) return findings;
  
  const lines = content.split('\n');
  
  for (const pattern of BATCH_54_PATTERNS) {
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
      // Skip pattern if regex fails
    }
  }
  
  return findings;
}

export default BATCH_54_PATTERNS;
