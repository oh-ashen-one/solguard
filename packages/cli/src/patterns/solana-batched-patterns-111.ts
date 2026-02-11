/**
 * Batch 111: Jan 2026 Agave Gossip/Vote Vulnerabilities + Validator Coordination + RPC Privacy + Token Governance
 * 
 * Sources:
 * - Anza Agave v3.0.14 Critical Security Patch (Jan 2026) — gossip & vote processing flaws
 * - CryptoSlate: Solana validator upgrade coordination risks (Jan 2026)
 * - Loopscale $5.8M RateX PT Token Pricing Exploit (Apr 2025)
 * - Umbra/Solana RPC Privacy Architecture Leaks (Feb 2026)
 * - LISA Token Dump — governance manipulation patterns (Jan 2026)
 * - Phantom Wallet lawsuit — $500K hack (2025)
 * 
 * Patterns: SOL7586-SOL7615 (30 patterns)
 * Focus: Gossip protocol abuse, vote transaction tampering, validator version checks,
 *        RPC metadata leaks, PT token pricing manipulation, governance voting exploits
 */

import type { PatternInput, Finding } from './index.js';

const BATCH_111_PATTERNS: {
  id: string;
  name: string;
  severity: 'critical' | 'high' | 'medium' | 'low' | 'info';
  pattern: RegExp;
  description: string;
  recommendation: string;
}[] = [
  // === GOSSIP PROTOCOL SECURITY (Agave v3.0.14) ===
  {
    id: 'SOL7586',
    name: 'Unvalidated Gossip Message Origin',
    severity: 'critical',
    pattern: /gossip[\s\S]{0,200}(?:process|handle|receive)[\s\S]{0,300}(?![\s\S]{0,150}verify_signature|[\s\S]{0,150}check_origin)/i,
    description: 'Gossip message handler does not verify the origin signature. Attackers can inject malicious gossip data to corrupt cluster state, as seen in the Dec 2025 Agave disclosure.',
    recommendation: 'Always verify gossip message signatures against the claimed sender pubkey before processing. Reject messages with invalid or missing signatures.'
  },
  {
    id: 'SOL7587',
    name: 'Gossip Duplicate Push Amplification',
    severity: 'high',
    pattern: /gossip[\s\S]{0,200}(?:push|broadcast|propagate)[\s\S]{0,300}(?![\s\S]{0,200}dedup|[\s\S]{0,200}seen_cache|[\s\S]{0,200}bloom_filter)/i,
    description: 'Gossip push handler lacks deduplication, allowing an attacker to amplify messages across the cluster by replaying the same payload from multiple endpoints.',
    recommendation: 'Implement a bloom filter or LRU seen-cache for gossip message hashes. Drop duplicate pushes within a configurable time window.'
  },
  {
    id: 'SOL7588',
    name: 'Gossip Pull Response Size Unbounded',
    severity: 'high',
    pattern: /gossip[\s\S]{0,200}pull[\s\S]{0,200}response[\s\S]{0,300}(?![\s\S]{0,150}max_size|[\s\S]{0,150}limit|[\s\S]{0,150}truncate)/i,
    description: 'Gossip pull responses are not bounded by size, enabling a malicious node to flood peers with oversized responses that exhaust memory or bandwidth.',
    recommendation: 'Enforce maximum response sizes for gossip pull operations. Truncate or paginate responses that exceed the configured limit.'
  },
  {
    id: 'SOL7589',
    name: 'Gossip CrdsValue Timestamp Drift Exploitation',
    severity: 'medium',
    pattern: /crds[\s\S]{0,200}(?:value|entry)[\s\S]{0,300}(?:wallclock|timestamp)[\s\S]{0,200}(?![\s\S]{0,150}max_drift|[\s\S]{0,150}clock_skew)/i,
    description: 'CRDS values accept timestamps with unbounded drift from the local clock, allowing attackers to inject entries that persist indefinitely or override newer legitimate entries.',
    recommendation: 'Reject CRDS values with wallclock timestamps that deviate more than a configurable threshold from the local clock. Typical bound: 10 minutes.'
  },
  // === VOTE TRANSACTION PROCESSING SECURITY ===
  {
    id: 'SOL7590',
    name: 'Vote Transaction Missing Authorized Voter Check',
    severity: 'critical',
    pattern: /vote[\s\S]{0,200}(?:process|execute|submit)[\s\S]{0,300}(?![\s\S]{0,200}authorized_voter|[\s\S]{0,200}vote_authority)/i,
    description: 'Vote transaction processing does not verify the authorized voter key matches the vote account. Spoofed votes can manipulate consensus and finality.',
    recommendation: 'Always verify the vote instruction signer matches the authorized voter stored in the vote account state before processing.'
  },
  {
    id: 'SOL7591',
    name: 'Vote Slot Hash Mismatch Undetected',
    severity: 'high',
    pattern: /vote[\s\S]{0,200}(?:slot|bank)[\s\S]{0,200}hash[\s\S]{0,300}(?![\s\S]{0,200}slot_hashes|[\s\S]{0,200}verify_hash)/i,
    description: 'Vote does not cross-reference the slot hash against the SlotHashes sysvar, allowing votes for fabricated or stale slot hashes that could fork consensus.',
    recommendation: 'Validate every vote slot+hash pair against the SlotHashes sysvar. Reject votes referencing unknown or expired slot hashes.'
  },
  {
    id: 'SOL7592',
    name: 'Vote Lockout Bypass via Commission Update',
    severity: 'high',
    pattern: /commission[\s\S]{0,200}(?:update|change|set)[\s\S]{0,300}(?![\s\S]{0,200}epoch_boundary|[\s\S]{0,200}lockout)/i,
    description: 'Validator commission changes are processed without enforcing epoch-boundary lockout constraints, allowing mid-epoch commission manipulation to extract delegator rewards.',
    recommendation: 'Enforce commission changes to take effect only at epoch boundaries. Reject mid-epoch commission update instructions.'
  },
  // === RPC METADATA PRIVACY LEAKS ===
  {
    id: 'SOL7593',
    name: 'RPC Request IP Address Logging Without Anonymization',
    severity: 'medium',
    pattern: /rpc[\s\S]{0,200}(?:log|record|store)[\s\S]{0,200}(?:ip|addr|remote|peer)[\s\S]{0,200}(?![\s\S]{0,150}hash|[\s\S]{0,150}anonymize|[\s\S]{0,150}redact)/i,
    description: 'RPC endpoint logs client IP addresses without anonymization, creating a metadata surveillance vector that can deanonymize wallet owners through request correlation.',
    recommendation: 'Hash or redact client IP addresses in RPC logs. Use rotating salts to prevent rainbow-table deanonymization while preserving rate-limiting capability.'
  },
  {
    id: 'SOL7594',
    name: 'Transaction Metadata Leaking Sender Identity',
    severity: 'medium',
    pattern: /(?:send_transaction|submit_transaction)[\s\S]{0,300}(?:memo|metadata|tag)[\s\S]{0,200}(?:user|identity|name|email)/i,
    description: 'Transaction submission includes identifiable metadata (memos, tags) that can link on-chain transactions to real-world identities via public explorers.',
    recommendation: 'Strip or encrypt personally identifiable metadata from transactions before submission. Use separate memo programs with encryption for necessary annotations.'
  },
  {
    id: 'SOL7595',
    name: 'Shared RPC Endpoint Wallet Correlation',
    severity: 'medium',
    pattern: /rpc[\s\S]{0,200}(?:get_account_info|get_balance|get_token)[\s\S]{0,300}(?:batch|multi|array)[\s\S]{0,200}(?![\s\S]{0,150}proxy|[\s\S]{0,150}relay)/i,
    description: 'Batched RPC queries for multiple accounts through a shared endpoint allow the RPC provider to correlate wallet ownership patterns across addresses.',
    recommendation: 'Split batched account queries across multiple RPC providers or use private relay nodes. Avoid querying all owned accounts in a single batch.'
  },
  // === PT TOKEN / YIELD TOKEN PRICING MANIPULATION (Loopscale-style) ===
  {
    id: 'SOL7596',
    name: 'PT Token Price Feed Without Secondary Oracle',
    severity: 'critical',
    pattern: /(?:pt_token|principal_token|rate_x)[\s\S]{0,300}(?:price|value|worth)[\s\S]{0,200}(?![\s\S]{0,200}twap|[\s\S]{0,200}secondary_oracle|[\s\S]{0,200}chainlink)/i,
    description: 'PT token pricing relies on a single on-chain price source without a secondary oracle or TWAP. The Loopscale $5.8M exploit manipulated RateX PT pricing to drain $5.8M through undercollateralized borrows.',
    recommendation: 'Use at least two independent price sources for PT/yield tokens. Implement TWAP with configurable windows and set maximum single-block price deviation thresholds.'
  },
  {
    id: 'SOL7597',
    name: 'Yield Token Collateral Ratio Stale After Maturity',
    severity: 'high',
    pattern: /(?:yield|pt|yt)[\s\S]{0,200}(?:collateral|ratio|ltv)[\s\S]{0,300}(?:maturity|expiry)[\s\S]{0,200}(?![\s\S]{0,150}update_after_maturity|[\s\S]{0,150}invalidate)/i,
    description: 'Yield token collateral ratios are not updated after maturity, allowing borrowers to maintain positions with stale favorable ratios while the underlying asset value diverges.',
    recommendation: 'Automatically recalculate collateral ratios at maturity. Invalidate or freeze positions using expired yield tokens until manual settlement.'
  },
  {
    id: 'SOL7598',
    name: 'Lending Market PT Token Undercollateralization Window',
    severity: 'critical',
    pattern: /(?:borrow|loan|lend)[\s\S]{0,300}(?:collateral[\s\S]{0,100}check|ltv[\s\S]{0,100}verify)[\s\S]{0,200}(?:pt|principal)[\s\S]{0,200}(?![\s\S]{0,200}atomic_price_check)/i,
    description: 'Lending protocol performs collateral checks and loan issuance in separate steps, creating a window where PT token price can be manipulated between validation and execution.',
    recommendation: 'Perform collateral valuation and loan issuance atomically within the same instruction. Re-validate collateral ratio immediately before fund disbursement.'
  },
  // === TOKEN GOVERNANCE MANIPULATION (LISA-style) ===
  {
    id: 'SOL7599',
    name: 'Governance Vote Without Token Lock Duration',
    severity: 'high',
    pattern: /(?:vote|proposal|govern)[\s\S]{0,300}(?:token|stake)[\s\S]{0,200}(?![\s\S]{0,200}lock_duration|[\s\S]{0,200}cooldown|[\s\S]{0,200}escrow)/i,
    description: 'Governance voting does not lock tokens for a minimum duration, enabling flash-loan governance attacks where an attacker borrows tokens, votes, and returns them in one transaction.',
    recommendation: 'Require governance tokens to be locked in an escrow for a minimum period (e.g., the full voting period plus a cooldown) before votes are counted.'
  },
  {
    id: 'SOL7600',
    name: 'Token Dump Via Concentrated Holder Without Timelock',
    severity: 'high',
    pattern: /(?:transfer|sell|swap)[\s\S]{0,200}(?:amount|quantity)[\s\S]{0,200}(?:total_supply|max_supply)[\s\S]{0,200}(?![\s\S]{0,200}timelock|[\s\S]{0,200}vesting|[\s\S]{0,200}rate_limit)/i,
    description: 'Large token holders can dump significant supply percentages without timelock or rate-limiting. The LISA token collapsed 76% in minutes when a concentrated holder exited.',
    recommendation: 'Implement sell-side rate limits for wallets exceeding a threshold percentage of total supply. Add progressive timelocks for large transfers.'
  },
  {
    id: 'SOL7601',
    name: 'Proposal Execution Without Quorum Validation',
    severity: 'critical',
    pattern: /(?:proposal|execute_proposal)[\s\S]{0,300}(?:approved|passed)[\s\S]{0,200}(?![\s\S]{0,200}quorum|[\s\S]{0,200}minimum_votes)/i,
    description: 'Governance proposal execution does not verify quorum was reached, allowing proposals to pass with trivially small participation when most token holders are inactive.',
    recommendation: 'Enforce a minimum quorum threshold before any proposal can be executed. Use absolute quorum (% of total supply) rather than relative (% of votes cast).'
  },
  // === VALIDATOR VERSION & UPGRADE COORDINATION ===
  {
    id: 'SOL7602',
    name: 'Missing Minimum Software Version Enforcement',
    severity: 'medium',
    pattern: /validator[\s\S]{0,200}(?:version|software)[\s\S]{0,300}(?![\s\S]{0,200}min_version|[\s\S]{0,200}required_version|[\s\S]{0,200}feature_gate)/i,
    description: 'Protocol does not enforce minimum validator software versions via feature gates. During the Jan 2026 Agave v3.0.14 incident, >80% of stake remained on vulnerable versions for days.',
    recommendation: 'Use Solana feature gates to enforce minimum client versions for critical security patches. Integrate version checks into delegation criteria for stake-weighted enforcement.'
  },
  {
    id: 'SOL7603',
    name: 'Feature Gate Activation Without Supermajority',
    severity: 'high',
    pattern: /feature[\s\S]{0,200}(?:activate|enable|gate)[\s\S]{0,300}(?![\s\S]{0,200}supermajority|[\s\S]{0,200}threshold[\s\S]{0,50}(?:67|0\.67|two_thirds))/i,
    description: 'Feature gate activation proceeds without requiring a supermajority (67%) of stake support. Premature activation can fork validators running older software.',
    recommendation: 'Enforce supermajority stake threshold (≥67%) before activating feature gates. Monitor real-time adoption before triggering activation.'
  },
  // === WALLET KEY MANAGEMENT ===
  {
    id: 'SOL7604',
    name: 'Browser Extension Key Storage Without Encryption At Rest',
    severity: 'critical',
    pattern: /(?:localStorage|sessionStorage|indexedDB)[\s\S]{0,200}(?:private_key|secret_key|seed|mnemonic)[\s\S]{0,200}(?![\s\S]{0,150}encrypt|[\s\S]{0,150}cipher)/i,
    description: 'Wallet extension stores private keys in browser storage without encryption at rest. The Phantom wallet lawsuit ($500K hack, 2025) highlighted browser extension key theft vectors.',
    recommendation: 'Encrypt all key material at rest using a user-derived key (password/biometric). Use WebCrypto API for encryption and never store plaintext keys in localStorage.'
  },
  {
    id: 'SOL7605',
    name: 'Wallet Simulation Bypass via Versioned Transaction',
    severity: 'high',
    pattern: /(?:versioned_transaction|v0_transaction)[\s\S]{0,300}(?:simulate|simulation)[\s\S]{0,200}(?![\s\S]{0,200}address_lookup|[\s\S]{0,200}resolve_lookups)/i,
    description: 'Wallet simulation of versioned transactions does not resolve address lookup tables, causing simulated results to differ from actual execution. Attackers use this to make malicious transactions appear safe.',
    recommendation: 'Fully resolve all address lookup table entries before simulation. Compare resolved account lists between simulation and signing to detect discrepancies.'
  },
  // === ADVANCED DeFi PATTERNS ===
  {
    id: 'SOL7606',
    name: 'Bonding Curve Asymmetric Slippage Exploitation',
    severity: 'high',
    pattern: /(?:bonding_curve|curve)[\s\S]{0,200}(?:buy|sell|swap)[\s\S]{0,300}(?:slippage)[\s\S]{0,200}(?![\s\S]{0,150}symmetric|[\s\S]{0,150}max_spread)/i,
    description: 'Bonding curve allows asymmetric slippage between buy and sell sides, enabling sandwich attacks that extract value by front-running buys with sells at tighter spreads.',
    recommendation: 'Enforce symmetric slippage bounds for buy and sell operations. Implement maximum spread limits that apply equally to both sides of the curve.'
  },
  {
    id: 'SOL7607',
    name: 'Pool Reserve Manipulation via Concentrated Liquidity Tick',
    severity: 'high',
    pattern: /(?:tick|concentrated[\s\S]{0,50}liquidity)[\s\S]{0,200}(?:reserve|balance)[\s\S]{0,300}(?![\s\S]{0,200}cross_tick_validation|[\s\S]{0,200}tick_bounds_check)/i,
    description: 'Concentrated liquidity pool does not validate reserves across tick boundaries during swaps, allowing attackers to manipulate the active tick to drain reserves from adjacent ranges.',
    recommendation: 'Validate pool reserves both before and after tick crossings. Ensure total reserves across all active ticks remain consistent with expected invariants.'
  },
  {
    id: 'SOL7608',
    name: 'Oracle Heartbeat Staleness in Fast-Moving Markets',
    severity: 'high',
    pattern: /(?:oracle|price_feed)[\s\S]{0,200}(?:heartbeat|staleness|max_age)[\s\S]{0,200}(?:30|60|120|300)[\s\S]{0,100}(?:seconds|secs)/i,
    description: 'Oracle staleness threshold set too high for volatile markets. A 30-300 second staleness window is an eternity for Solana slot times (~400ms), enabling exploitation during rapid price moves.',
    recommendation: 'Set oracle staleness thresholds relative to slot time, not wall-clock seconds. For high-volatility assets, use max staleness of 10-20 slots. Implement circuit breakers for price gaps.'
  },
  {
    id: 'SOL7609',
    name: 'Cross-Program Oracle Price Divergence Not Checked',
    severity: 'high',
    pattern: /(?:pyth|switchboard|chainlink)[\s\S]{0,300}(?:price|get_price)[\s\S]{0,200}(?![\s\S]{0,200}confidence|[\s\S]{0,200}deviation|[\s\S]{0,200}divergence)/i,
    description: 'Protocol consumes oracle prices without checking confidence intervals or cross-oracle divergence. An attacker can exploit momentary oracle disagreements to execute trades at stale prices.',
    recommendation: 'Check oracle confidence intervals and reject prices with wide confidence bands. When using multiple oracles, verify price divergence stays within acceptable bounds.'
  },
  // === SUPPLY CHAIN & DEPENDENCY SECURITY ===
  {
    id: 'SOL7610',
    name: 'NPM @solana Package Typosquatting Risk',
    severity: 'high',
    pattern: /(?:require|import)[\s\S]{0,50}(?:@solanna|@soIana|@s0lana|solana-web3\.js[\s\S]{0,10}(?!@solana))/i,
    description: 'Import references a possible typosquatted Solana package. The Dec 2024 @solana/web3.js supply chain attack injected a backdoor that stole private keys via malicious postinstall scripts.',
    recommendation: 'Verify package names exactly match official Solana packages. Use lockfiles with integrity hashes. Audit new dependencies before installation.'
  },
  {
    id: 'SOL7611',
    name: 'Dependency Using Deprecated @solana/web3.js Version',
    severity: 'medium',
    pattern: /@solana\/web3\.js[\s\S]{0,20}(?:1\.(?:[0-6]\d|7[0-7])\.|0\.)/i,
    description: 'Project depends on an older @solana/web3.js version that may contain known vulnerabilities. Versions prior to 1.78 predate critical security fixes from the Dec 2024 supply chain incident.',
    recommendation: 'Update @solana/web3.js to the latest patched version. Review the changelog for security-relevant changes and test thoroughly after upgrading.'
  },
  // === PROGRAM DEPLOYMENT SECURITY ===
  {
    id: 'SOL7612',
    name: 'Program Deployed Without Verified Build',
    severity: 'medium',
    pattern: /(?:deploy|program[\s\S]{0,20}deploy)[\s\S]{0,300}(?![\s\S]{0,200}verified_build|[\s\S]{0,200}solana_verify|[\s\S]{0,200}anchor_verify)/i,
    description: 'Program deployment process does not include verified build attestation. Without verified builds, users cannot confirm the deployed bytecode matches the published source code.',
    recommendation: 'Use solana-verify or Anchor verified builds to create reproducible build attestations. Publish verified build hashes alongside program deployments.'
  },
  {
    id: 'SOL7613',
    name: 'Program Authority Not Set to Multisig After Deploy',
    severity: 'high',
    pattern: /(?:program[\s\S]{0,30}deploy|upgrade_authority)[\s\S]{0,300}(?:keypair|wallet)[\s\S]{0,200}(?![\s\S]{0,200}multisig|[\s\S]{0,200}squads|[\s\S]{0,200}threshold)/i,
    description: 'Program upgrade authority remains a single keypair after deployment rather than a multisig. A compromised keypair gives an attacker full control to deploy malicious upgrades.',
    recommendation: 'Transfer program upgrade authority to a multisig (e.g., Squads) immediately after deployment. Require threshold signatures for any program upgrades.'
  },
  {
    id: 'SOL7614',
    name: 'Upgrade Authority Timelock Too Short',
    severity: 'medium',
    pattern: /(?:upgrade|program[\s\S]{0,20}update)[\s\S]{0,200}(?:timelock|delay)[\s\S]{0,100}(?:[0-9]{1,3}\s*(?:seconds|secs|minutes|mins)|0)/i,
    description: 'Program upgrade timelock is set to a trivially short duration, giving users insufficient time to review changes or exit positions before a potentially malicious upgrade takes effect.',
    recommendation: 'Set program upgrade timelocks to at least 48-72 hours for mainnet programs. For DeFi protocols holding significant TVL, consider 7+ day timelocks.'
  },
  {
    id: 'SOL7615',
    name: 'Missing Emergency Pause in High-TVL Protocol',
    severity: 'high',
    pattern: /(?:deposit|withdraw|swap|borrow|lend)[\s\S]{0,500}(?![\s\S]{0,300}paused|[\s\S]{0,300}is_paused|[\s\S]{0,300}emergency_stop|[\s\S]{0,300}circuit_breaker)/i,
    description: 'High-value protocol operations lack an emergency pause mechanism. When Loopscale detected its $5.8M exploit, the ability to immediately pause lending markets prevented further losses.',
    recommendation: 'Implement a circuit breaker / emergency pause flag checked at the start of every value-transferring instruction. Ensure pause authority is a fast-acting multisig.'
  },
];

export function detectBatch111(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  const content = input.rust?.content || '';
  
  for (const pattern of BATCH_111_PATTERNS) {
    if (pattern.pattern.test(content)) {
      findings.push({
        id: pattern.id,
        title: pattern.name,
        severity: pattern.severity,
        description: pattern.description,
        location: { file: input.path },
        recommendation: pattern.recommendation,
      });
    }
  }
  
  return findings;
}

export { BATCH_111_PATTERNS };
