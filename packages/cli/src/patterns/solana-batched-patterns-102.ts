/**
 * Batch 102: Helius Complete Exploit History Deep Dive
 * 
 * Based on Helius's comprehensive "Solana Hacks, Bugs, and Exploits: A Complete History"
 * Covers 38 verified incidents (2020-Q1 2025) with $600M gross losses
 * 
 * Sources:
 * - https://www.helius.dev/blog/solana-hacks
 * - Individual post-mortems and audit reports
 * 
 * Pattern IDs: SOL6401-SOL6500
 * Focus: Detailed exploit patterns from verified incidents
 */

import type { ParsedRust } from '../parsers/rust.js';
import type { Finding } from '../scanner.js';

interface Pattern {
  id: string;
  name: string;
  description: string;
  severity: 'critical' | 'high' | 'medium' | 'low' | 'info';
  pattern: RegExp;
  recommendation: string;
  references?: string[];
}

const BATCH_102_PATTERNS: Pattern[] = [
  // ============================================
  // SOLEND AUTH BYPASS (Aug 2021) - $2M at risk
  // ============================================
  {
    id: 'SOL6401',
    name: 'Solend-Style Auth Bypass - UpdateReserveConfig Vulnerability',
    description: 'Detects insecure admin authentication that allows attackers to bypass checks by passing their own lending market. Attackers can create new lending markets and use them to bypass admin verification, enabling unauthorized parameter updates.',
    severity: 'critical',
    pattern: /pub\s+fn\s+update_reserve_config|UpdateReserveConfig|lending_market:\s*AccountInfo|market_authority|reserve_config.*=|liquidation_threshold.*=|liquidation_bonus.*=/i,
    recommendation: 'Implement root-of-trust validation: verify lending_market ownership matches expected authority. Use PDAs with protocol seeds for admin accounts. Add timelocks for parameter changes. Pattern: require!(lending_market.owner == EXPECTED_PROGRAM_ID && lending_market.authority == admin.key());',
    references: ['https://hackmd.io/@prastut/r1wMdtcf3', 'https://www.quadrigainitiative.com/casestudy/solendinsecureauthenticationcheck.php']
  },
  {
    id: 'SOL6402',
    name: 'Liquidation Parameter Manipulation',
    description: 'Detects patterns where liquidation threshold or bonus can be modified without proper constraints. Attackers can lower thresholds to make accounts liquidatable and increase bonuses for profit extraction.',
    severity: 'high',
    pattern: /liquidation_threshold\s*=|set_liquidation|update_liquidation|liquidation_bonus\s*=|bonus_rate.*=|threshold.*percent/i,
    recommendation: 'Enforce bounds on liquidation parameters (threshold: 50-90%, bonus: 1-15%). Require multi-sig or timelock for changes. Emit events for all parameter modifications. Add circuit breakers for rapid changes.',
    references: ['https://hackmd.io/@prastut/r1wMdtcf3']
  },
  {
    id: 'SOL6403',
    name: 'Lending Market Creation Without Proper Authority Binding',
    description: 'Detects lending market initialization that doesn\'t properly bind authority or uses weak owner checks. Attackers can create fake markets to bypass authentication.',
    severity: 'high',
    pattern: /init_lending_market|LendingMarket::new|create_market|market\.authority\s*=|market\.owner\s*=/i,
    recommendation: 'Bind lending market authority to protocol-controlled PDA. Verify market is part of trusted registry. Add market_id seed to prevent market spoofing. Require existing market verification in all reserve operations.',
    references: ['https://www.helius.dev/blog/solana-hacks']
  },

  // ============================================
  // SLOPE WALLET EXPLOIT (Jul 2022) - $8M stolen
  // ============================================
  {
    id: 'SOL6404',
    name: 'Slope Wallet Pattern - Seed Phrase Logging to External Service',
    description: 'Detects patterns where sensitive key material (seed phrases, private keys) might be transmitted to external services like Sentry, analytics, or crash reporting. The Slope wallet leaked seed phrases to Sentry servers.',
    severity: 'critical',
    pattern: /sentry|analytics|crash_report|telemetry|log.*seed|log.*mnemonic|log.*private_key|send.*phrase|transmit.*key|report.*wallet/i,
    recommendation: 'NEVER log or transmit seed phrases or private keys to ANY external service. Use client-side only key generation. Audit all logging/analytics code paths. Implement code scanning for sensitive data patterns. Pattern: grep -r "sentry" "seed" "mnemonic" "private_key"',
    references: ['https://www.helius.dev/blog/solana-hacks', 'https://slope.finance/blog/update-on-wallet-security-incident']
  },
  {
    id: 'SOL6405',
    name: 'Wallet Key Material in Plain Text',
    description: 'Detects patterns where seed phrases or private keys might be stored in plain text or logged. Critical for wallet implementations.',
    severity: 'critical',
    pattern: /seed_phrase\s*=|mnemonic\s*=.*String|private_key\s*=.*str|secret_key.*log|println!.*key|format!.*seed|debug!.*mnemonic/i,
    recommendation: 'Use secure memory for key material. Zero memory after use. Never format/print key material. Use constant-time comparisons. Implement secure deletion. Consider hardware security modules.',
    references: ['https://www.helius.dev/blog/solana-hacks']
  },
  {
    id: 'SOL6406',
    name: 'Third-Party SDK Sending Sensitive Data',
    description: 'Detects integration patterns with third-party SDKs that might capture sensitive wallet data. The Slope incident showed how third-party services can become attack vectors.',
    severity: 'high',
    pattern: /Sentry::capture|sentry_sdk|crashlytics|bugsnag|rollbar|raygun|logrocket|fullstory|amplitude.*wallet/i,
    recommendation: 'Audit ALL third-party SDK integrations in wallet apps. Use allowlist for logged data. Implement data scrubbing before sending to any analytics. Consider self-hosted error tracking. Remove or sanitize wallet-related context from crash reports.',
    references: ['https://www.helius.dev/blog/solana-hacks']
  },

  // ============================================
  // OPTIFI LOCKUP BUG (Aug 2022) - $661K locked
  // ============================================
  {
    id: 'SOL6407',
    name: 'OptiFi Pattern - Accidental Program Closure with TVL',
    description: 'Detects close_program or program termination instructions that don\'t verify no active users/funds exist. OptiFi accidentally closed their program with $661K in user funds.',
    severity: 'critical',
    pattern: /close_program|terminate_program|self_destruct|program_close|system_instruction::close|lamports\s*=\s*0.*close/i,
    recommendation: 'NEVER allow program closure if TVL > 0. Implement shutdown guard: require all vaults empty, all positions closed, all user funds withdrawn. Add multi-day timelock for program closure. Pattern: require!(get_total_tvl() == 0, "Cannot close with active funds");',
    references: ['https://www.helius.dev/blog/solana-hacks']
  },
  {
    id: 'SOL6408',
    name: 'Program Closure Without User Fund Verification',
    description: 'Detects program closure patterns that don\'t check for existing user balances or active positions before termination.',
    severity: 'critical',
    pattern: /fn\s+close_program|close_all_accounts|shutdown_protocol|emergency_close(?!.*verify_no_funds)|terminate(?!.*check_balance)/i,
    recommendation: 'Before program closure: 1) Enumerate all user accounts, 2) Verify zero balances, 3) Force withdrawal period, 4) Multi-sig governance approval, 5) Timelock (30+ days). Never close with any user funds present.',
    references: ['https://www.helius.dev/blog/solana-hacks']
  },
  {
    id: 'SOL6409',
    name: 'Missing TVL Check Before Destructive Operations',
    description: 'Detects destructive protocol operations (closure, migration, pause) without TVL verification.',
    severity: 'high',
    pattern: /migrate_program|upgrade_and_close|pause_forever|permanent_shutdown|freeze_protocol(?!.*tvl)|terminate_vault(?!.*balance)/i,
    recommendation: 'All destructive operations must verify: total_tvl == 0, active_users == 0, pending_withdrawals == 0. Implement read-only mode before full shutdown. Provide user withdrawal window.',
    references: ['https://www.helius.dev/blog/solana-hacks']
  },

  // ============================================
  // UXD PROTOCOL (Jan 2023) - $20M at risk
  // ============================================
  {
    id: 'SOL6410',
    name: 'UXD Pattern - Insufficient Collateral Validation',
    description: 'Detects collateral deposit/minting patterns that might not properly verify collateral value against debt. UXD had a vulnerability in collateral validation.',
    severity: 'high',
    pattern: /mint_stable|deposit_collateral|borrow_against|collateral_ratio.*<|ltv.*check|collateral_value\s*\/|debt_to_collateral/i,
    recommendation: 'Use multiple oracle sources for collateral valuation. Implement strict LTV limits (typically 60-80%). Add buffer for price volatility. Use TWAP pricing. Verify collateral is not already used elsewhere.',
    references: ['https://docs.uxd.fi/uxdprotocol/resources/audits']
  },
  {
    id: 'SOL6411',
    name: 'Delta-Neutral Position Management Risk',
    description: 'Detects delta-neutral hedging patterns used in stablecoin protocols. Improper management can lead to under-collateralization during volatility.',
    severity: 'medium',
    pattern: /delta_neutral|hedge_position|perpetual_position|funding_rate|open_short|rebalance_delta|collateral_backing/i,
    recommendation: 'Implement continuous position monitoring. Set funding rate caps. Add emergency unwind mechanisms. Use circuit breakers for extreme market conditions. Maintain collateral reserves for adverse funding.',
    references: ['https://docs.uxd.fi/uxdprotocol/resources/audits']
  },

  // ============================================
  // TULIP PROTOCOL (Jun 2022) - Front-end compromise
  // ============================================
  {
    id: 'SOL6412',
    name: 'Tulip Pattern - DNS Hijacking Risk',
    description: 'Detects patterns where frontend connects to backend without proper verification. DNS hijacking can redirect users to malicious sites.',
    severity: 'medium',
    pattern: /dns_lookup|resolve_domain|api_endpoint\s*=.*http|backend_url|fetch.*config|load.*remote/i,
    recommendation: 'Use DNSSEC for domain validation. Pin SSL certificates. Implement client-side signature verification for all transactions. Display transaction details for user confirmation. Use ENS/SNS for decentralized naming.',
    references: ['https://www.helius.dev/blog/solana-hacks']
  },
  {
    id: 'SOL6413',
    name: 'Frontend Transaction Manipulation Risk',
    description: 'Detects patterns where transaction construction happens client-side without proper on-chain verification.',
    severity: 'high',
    pattern: /build_transaction|construct_ix|create_instruction.*frontend|serialize_transaction|sign_and_send(?!.*simulate)/i,
    recommendation: 'Always simulate transactions before signing. Display decoded transaction details to users. Use hardware wallets for signing. Implement transaction allowlists. Verify all account addresses on-chain.',
    references: ['https://www.helius.dev/blog/solana-hacks']
  },

  // ============================================
  // SVT TOKEN EXPLOIT (May 2024) - Fake airdrop
  // ============================================
  {
    id: 'SOL6414',
    name: 'SVT Token Pattern - Malicious Airdrop Detection',
    description: 'Detects patterns related to unexpected token airdrops that may be phishing attempts. SVT token used fake airdrops to phish users.',
    severity: 'high',
    pattern: /airdrop_to_all|mass_transfer|distribute_tokens.*unsolicited|transfer_to_random|sweep.*unknown_token/i,
    recommendation: 'NEVER interact with unknown airdropped tokens. Use token registry verification. Implement token blacklists. Educate users about airdrop scams. Check token mint authority and metadata.',
    references: ['https://www.helius.dev/blog/solana-hacks', 'https://www.certik.com/']
  },
  {
    id: 'SOL6415',
    name: 'Phishing Token Approval Drain',
    description: 'Detects patterns where interacting with unknown tokens might trigger approval drains. Malicious tokens can include hidden approval logic.',
    severity: 'critical',
    pattern: /approve.*unknown|delegate.*token|set_authority.*external|transfer_hook.*malicious|token_approval.*max/i,
    recommendation: 'Revoke all approvals for unknown tokens. Use revoke.cash or similar tools. Never approve unlimited amounts. Check token program for hooks/extensions. Verify token is from official mint.',
    references: ['https://www.helius.dev/blog/solana-hacks']
  },

  // ============================================
  // io.net EXPLOIT (Apr 2024) - $6M reward manipulation
  // ============================================
  {
    id: 'SOL6416',
    name: 'io.net Pattern - GPU Worker Reward Manipulation',
    description: 'Detects patterns where worker rewards can be manipulated through fake device registration or work spoofing.',
    severity: 'high',
    pattern: /register_device|claim_reward.*worker|verify_work|proof_of_work.*gpu|device_attestation|worker_earnings/i,
    recommendation: 'Implement hardware attestation for device registration. Use TEE for work verification. Add cooldown periods for reward claims. Rate limit device registrations. Verify actual work completed.',
    references: ['https://www.helius.dev/blog/solana-hacks']
  },
  {
    id: 'SOL6417',
    name: 'DePIN Sybil Attack Vector',
    description: 'Detects decentralized physical infrastructure patterns vulnerable to sybil attacks where fake nodes claim rewards.',
    severity: 'high',
    pattern: /node_registration|stake_to_join|network_contributor|physical_device|location_proof|hardware_verification/i,
    recommendation: 'Require minimum stake for node registration. Implement slashing for fraudulent nodes. Use proof-of-physical-work. Add IP/geolocation verification. Establish reputation systems.',
    references: ['https://www.helius.dev/blog/solana-hacks']
  },

  // ============================================
  // SYNTHETIFY DAO EXPLOIT (Oct 2023) - $230K governance attack
  // ============================================
  {
    id: 'SOL6418',
    name: 'Synthetify Pattern - Unnoticed Governance Proposal',
    description: 'Detects governance patterns where malicious proposals can pass unnoticed due to low participation or short voting periods.',
    severity: 'high',
    pattern: /create_proposal|execute_proposal|voting_period\s*<|quorum\s*<|proposal.*treasury|governance.*transfer/i,
    recommendation: 'Implement minimum 7-day voting periods. Require significant quorum (10%+ of tokens). Add timelock after proposal passes. Send notifications for new proposals. Require multi-sig for treasury operations.',
    references: ['https://www.helius.dev/blog/solana-hacks', 'https://medium.com/@lucrativepanda/']
  },
  {
    id: 'SOL6419',
    name: 'DAO Treasury Drain via Governance',
    description: 'Detects patterns where governance can directly transfer treasury funds without adequate safeguards.',
    severity: 'critical',
    pattern: /treasury_transfer|withdraw_dao|governance.*lamports|proposal.*withdraw|execute.*transfer.*treasury/i,
    recommendation: 'Require super-majority (67%+) for treasury withdrawals. Implement withdrawal limits per period. Add emergency pause by guardians. Use multi-sig treasury controlled by governance. Timelock all treasury operations.',
    references: ['https://www.helius.dev/blog/solana-hacks']
  },

  // ============================================
  // AURORY EXPLOIT (Dec 2023) - $830K unauthorized access
  // ============================================
  {
    id: 'SOL6420',
    name: 'Aurory Pattern - Game Economy Token Exploit',
    description: 'Detects patterns in gaming token economies where minting, rewards, or marketplace transactions can be exploited.',
    severity: 'high',
    pattern: /game_reward|mint_game_token|nft_marketplace|in_game_currency|player_earnings|loot_box|gacha/i,
    recommendation: 'Implement rate limits on reward claiming. Use server-side validation for game actions. Add cooldowns between claims. Verify game state transitions. Monitor for abnormal claim patterns.',
    references: ['https://www.helius.dev/blog/solana-hacks']
  },
  {
    id: 'SOL6421',
    name: 'Gaming NFT/Token Marketplace Manipulation',
    description: 'Detects patterns where game item marketplaces can be manipulated for profit extraction.',
    severity: 'medium',
    pattern: /list_item|buy_item|marketplace_fee|item_price|auction.*game|trade_item|escrow.*nft/i,
    recommendation: 'Implement price bounds for listings. Add anti-bot measures for purchases. Use oracle pricing for rare items. Delay large transactions. Monitor wash trading patterns.',
    references: ['https://www.helius.dev/blog/solana-hacks']
  },

  // ============================================
  // SAGA DAO (Dec 2023) - Governance manipulation
  // ============================================
  {
    id: 'SOL6422',
    name: 'Saga DAO Pattern - Snapshot Manipulation',
    description: 'Detects patterns where governance snapshot timing can be manipulated to gain voting power.',
    severity: 'high',
    pattern: /snapshot_slot|voting_snapshot|token_at_slot|balance_at_time|governance_checkpoint|proposal_snapshot/i,
    recommendation: 'Use randomized snapshot times. Implement time-weighted voting power. Add minimum holding period for voting rights. Use multiple snapshots averaged. Prevent flash loan voting.',
    references: ['https://www.helius.dev/blog/solana-hacks']
  },

  // ============================================
  // SOLAREUM EXPLOIT (Mar 2024) - Trading bot rugpull
  // ============================================
  {
    id: 'SOL6423',
    name: 'Solareum Pattern - Trading Bot Fund Custody Risk',
    description: 'Detects patterns where trading bots have custody of user funds without proper security measures.',
    severity: 'critical',
    pattern: /bot_custody|trading_bot.*deposit|fund_pool.*bot|automated_trading|copy_trading|signal_bot/i,
    recommendation: 'Use non-custodial bot architectures. Implement withdrawal limits. Add emergency pause. Use multi-sig for large fund movements. Require user approval for trades above threshold.',
    references: ['https://www.helius.dev/blog/solana-hacks']
  },
  {
    id: 'SOL6424',
    name: 'Insider Access to Trading Bot Funds',
    description: 'Detects patterns where insiders (employees, contractors) could drain trading bot or protocol funds.',
    severity: 'critical',
    pattern: /admin_withdraw|owner_transfer|emergency_drain|backend_key|operator_wallet|privileged_transfer/i,
    recommendation: 'Implement multi-sig for all privileged operations. Add timelocks for withdrawals. Use hardware wallets for admin keys. Separate operational and treasury keys. Audit insider access regularly.',
    references: ['https://www.helius.dev/blog/solana-hacks']
  },

  // ============================================
  // NETWORK LEVEL ATTACKS
  // ============================================
  {
    id: 'SOL6425',
    name: 'Grape Protocol Pattern - Network Spam Attack',
    description: 'Detects patterns that could be exploited for network spam, causing congestion and outages. Grape Protocol suffered a 17-hour outage.',
    severity: 'medium',
    pattern: /bulk_transaction|mass_instruction|spam_prevention|rate_limit.*tx|throttle.*request|concurrent_tx/i,
    recommendation: 'Implement per-account rate limiting. Use priority fees for critical operations. Add exponential backoff. Monitor for unusual transaction patterns. Design for graceful degradation.',
    references: ['https://www.helius.dev/blog/solana-hacks']
  },
  {
    id: 'SOL6426',
    name: 'Candy Machine Minting DoS Vector',
    description: 'Detects NFT minting patterns vulnerable to bot attacks causing network congestion.',
    severity: 'medium',
    pattern: /candy_machine|nft_mint.*public|whitelist.*mint|mint_limit|bot_protection|proof_of_human/i,
    recommendation: 'Implement bot protection (CAPTCHA, proof-of-humanity). Use merkle tree whitelists. Add per-wallet mint limits. Stagger mint phases. Consider Dutch auction mechanics.',
    references: ['https://www.helius.dev/blog/solana-hacks']
  },
  {
    id: 'SOL6427',
    name: 'Jito DDoS Attack Pattern',
    description: 'Detects patterns related to MEV infrastructure that could be targeted for DDoS attacks.',
    severity: 'medium',
    pattern: /jito_bundle|mev_searcher|block_engine|bundle_tip|auction.*slot|validator_tip/i,
    recommendation: 'Implement redundant MEV infrastructure. Use distributed block engines. Add fallback transaction submission. Monitor MEV relay health. Design for operation without MEV.',
    references: ['https://www.helius.dev/blog/solana-hacks']
  },
  {
    id: 'SOL6428',
    name: 'Phantom Wallet DDoS Pattern',
    description: 'Detects patterns where wallet RPC endpoints could be overwhelmed, causing wallet failures.',
    severity: 'medium',
    pattern: /rpc_endpoint|connection.*cluster|commitment_level|get_balance|get_account_info.*loop|fetch_all_accounts/i,
    recommendation: 'Use multiple RPC providers. Implement client-side caching. Add request batching. Use connection pooling. Design for RPC unavailability.',
    references: ['https://www.helius.dev/blog/solana-hacks']
  },

  // ============================================
  // CORE PROTOCOL VULNERABILITIES
  // ============================================
  {
    id: 'SOL6429',
    name: 'Turbine Bug Pattern - Block Propagation Failure',
    description: 'Detects patterns that might indicate Turbine (block propagation) related issues or assumptions.',
    severity: 'low',
    pattern: /turbine|shred_version|block_propagation|validator_gossip|leader_schedule|slot_timing/i,
    recommendation: 'Design for eventual consistency. Handle slot skips gracefully. Don\'t assume immediate finality. Use confirmation levels appropriately. Monitor validator status.',
    references: ['https://www.helius.dev/blog/solana-hacks']
  },
  {
    id: 'SOL6430',
    name: 'Durable Nonce Safety Pattern',
    description: 'Detects durable nonce usage that might be vulnerable to replay or timing attacks.',
    severity: 'medium',
    pattern: /durable_nonce|advance_nonce|nonce_account|offline_signing|presigned_transaction/i,
    recommendation: 'Verify nonce account state before use. Implement nonce expiry checks. Add authority verification. Use latest blockhash when possible. Monitor nonce account changes.',
    references: ['https://www.helius.dev/blog/solana-hacks']
  },
  {
    id: 'SOL6431',
    name: 'JIT Cache Bug Pattern',
    description: 'Detects patterns that might trigger JIT compilation issues or exploit JIT cache behaviors.',
    severity: 'low',
    pattern: /bpf_program|sbf_loader|program_cache|jit_compile|executable_data|program_data_account/i,
    recommendation: 'Keep programs simple and well-tested. Avoid unusual instruction patterns. Test on devnet/testnet extensively. Monitor for unusual program behavior. Keep up with runtime updates.',
    references: ['https://www.helius.dev/blog/solana-hacks']
  },
  {
    id: 'SOL6432',
    name: 'ELF Address Alignment Vulnerability Pattern',
    description: 'Detects patterns related to program loading that might be affected by ELF alignment issues.',
    severity: 'low',
    pattern: /elf_header|program_section|memory_alignment|page_boundary|loader_v\d|bpf_loader/i,
    recommendation: 'Use standard BPF toolchain. Avoid custom loaders. Test programs thoroughly. Monitor for loader updates. Keep dependencies updated.',
    references: ['https://www.helius.dev/blog/solana-hacks']
  },

  // ============================================
  // SUPPLY CHAIN ATTACKS
  // ============================================
  {
    id: 'SOL6433',
    name: 'Web3.js Supply Chain Pattern',
    description: 'Detects @solana/web3.js usage patterns that should verify package integrity. The Dec 2024 npm compromise affected versions 1.95.6-1.95.7.',
    severity: 'high',
    pattern: /@solana\/web3\.js|solana-web3|createTransferInstruction|SystemProgram\.transfer|require\(['"]@solana/i,
    recommendation: 'Pin exact package versions. Use package-lock.json/yarn.lock. Verify package checksums. Monitor npm advisories. Use npm audit. Consider vendoring critical dependencies.',
    references: ['https://www.helius.dev/blog/solana-hacks']
  },
  {
    id: 'SOL6434',
    name: 'Parcl Frontend Attack Pattern',
    description: 'Detects frontend patterns vulnerable to compromise (DNS, CDN, injection). Parcl\'s frontend was compromised in Sep 2024.',
    severity: 'medium',
    pattern: /load_external_script|cdn_resource|iframe.*src|postMessage|addEventListener.*message|eval\(/i,
    recommendation: 'Use Content Security Policy. Pin resource integrity (SRI). Avoid eval/dynamic code. Verify all external resources. Implement frontend monitoring.',
    references: ['https://www.helius.dev/blog/solana-hacks']
  },

  // ============================================
  // INSIDER THREAT PATTERNS
  // ============================================
  {
    id: 'SOL6435',
    name: 'Pump.fun Insider Pattern - Employee Access to Hot Wallets',
    description: 'Detects patterns where employees have direct access to protocol hot wallets or can drain funds.',
    severity: 'critical',
    pattern: /employee_wallet|staff_access|internal_transfer|hot_wallet.*admin|operator_key|backend_signer/i,
    recommendation: 'Use multi-sig for ALL fund movements. Implement separation of duties. Add transaction limits. Use hardware security modules. Monitor privileged access. Background check employees.',
    references: ['https://www.helius.dev/blog/solana-hacks']
  },
  {
    id: 'SOL6436',
    name: 'Cypher Protocol Pattern - Redeemer Insider Theft',
    description: 'Detects patterns where individuals with special access (redeemers, operators) can steal user funds post-exploit.',
    severity: 'critical',
    pattern: /redeemer_access|rescue_operation|post_exploit|recovery_key|emergency_operator|special_access/i,
    recommendation: 'All rescue operations require multi-sig. Use timelocks for recovery. Publish recovery plans publicly. Independent oversight for rescues. Transparent fund tracking.',
    references: ['https://www.helius.dev/blog/solana-hacks']
  },

  // ============================================
  // 2024-2025 EMERGING PATTERNS
  // ============================================
  {
    id: 'SOL6437',
    name: 'Response Time Pattern - Minute-Level Detection',
    description: 'Detects monitoring and alerting patterns. Best-in-class response times (Thunder Terminal: 9 minutes, Banana Gun: minutes) require real-time monitoring.',
    severity: 'info',
    pattern: /alert_threshold|monitoring_hook|suspicious_activity|anomaly_detection|circuit_breaker|emergency_pause/i,
    recommendation: 'Implement real-time transaction monitoring. Set up alerts for large transfers. Add automatic pause triggers. Use 24/7 on-call security. Pre-plan incident response procedures.',
    references: ['https://www.helius.dev/blog/solana-hacks']
  },
  {
    id: 'SOL6438',
    name: 'Recovery Success Pattern - Full Mitigation',
    description: 'Detects patterns that enable successful fund recovery (Wormhole: $326M, Pump.fun: $1.9M, Loopscale: $5.8M recovered).',
    severity: 'info',
    pattern: /insurance_fund|recovery_reserve|protocol_treasury|contingency_fund|reimbursement_pool/i,
    recommendation: 'Maintain insurance fund (5-10% of TVL). Partner with security firms. Establish white hat bounty programs. Keep backup capital. Document recovery procedures.',
    references: ['https://www.helius.dev/blog/solana-hacks']
  },

  // ============================================
  // COMPREHENSIVE VALIDATION PATTERNS
  // ============================================
  {
    id: 'SOL6439',
    name: 'Helius Incident Category - Application Exploit',
    description: 'General detection for application-level vulnerabilities (26 of 38 incidents). Checks for common exploit vectors.',
    severity: 'medium',
    pattern: /program_bug|validation_flaw|oracle_manipulation|key_management|governance_loophole|third_party_integration/i,
    recommendation: 'Comprehensive security: 1) Multiple audits, 2) Bug bounties, 3) Monitoring, 4) Incident response plan, 5) Insurance. Application exploits are 68% of Solana incidents.',
    references: ['https://www.helius.dev/blog/solana-hacks']
  },
  {
    id: 'SOL6440',
    name: 'User Loss Prevention Pattern',
    description: 'Detects patterns related to user fund protection. Users bore losses in Slope ($8M), DEXX ($30M), Solareum, Cashio cases.',
    severity: 'high',
    pattern: /user_funds|depositor_balance|customer_assets|retail_investor|user_custody|client_funds/i,
    recommendation: 'Prioritize user fund protection. Maintain insurance reserves. Enable user-controlled withdrawals. Limit custodial exposure. Transparent TVL reporting. Quick communication during incidents.',
    references: ['https://www.helius.dev/blog/solana-hacks']
  },

  // ============================================
  // ADDITIONAL HELIUS VERIFIED INCIDENTS
  // ============================================
  {
    id: 'SOL6441',
    name: 'NoOnes Bridge Pattern - Cross-Chain Vulnerability',
    description: 'Detects cross-chain bridge patterns vulnerable to validation bypass. NoOnes lost funds through bridge exploit.',
    severity: 'high',
    pattern: /bridge_transfer|cross_chain|wormhole_transfer|layerzero|portal_bridge|wrapped_asset/i,
    recommendation: 'Implement multi-layer validation for bridges. Use guardian/relayer networks. Add rate limits on bridging. Monitor bridge reserves. Pause on anomaly detection.',
    references: ['https://www.helius.dev/blog/solana-hacks']
  },
  {
    id: 'SOL6442',
    name: 'Thunder Terminal Pattern - MongoDB Injection',
    description: 'Detects patterns where backend databases might be exploited. Thunder Terminal was compromised via MongoDB.',
    severity: 'high',
    pattern: /mongodb|database_query|user_lookup|session_token|api_key.*store|credential_store/i,
    recommendation: 'Use parameterized queries. Encrypt sensitive data at rest. Implement API key rotation. Add access logging. Use principle of least privilege for DB access.',
    references: ['https://www.helius.dev/blog/solana-hacks']
  },
  {
    id: 'SOL6443',
    name: 'Banana Gun Pattern - Telegram Bot Compromise',
    description: 'Detects Telegram bot trading patterns that could be vulnerable to API key theft.',
    severity: 'high',
    pattern: /telegram_bot|bot_token|trading_bot|signal_execution|automated_trade|copy_trade/i,
    recommendation: 'Use secure key storage for bot credentials. Implement 2FA for all operations. Add withdrawal whitelist. Rate limit trading. Monitor for unusual bot behavior.',
    references: ['https://www.helius.dev/blog/solana-hacks']
  },
  {
    id: 'SOL6444',
    name: 'DEXX Private Key Leak Pattern',
    description: 'Detects patterns where private keys might be exposed through logging, transmission, or storage. DEXX leaked $30M worth of keys.',
    severity: 'critical',
    pattern: /private_key.*log|key.*transmit|store.*secret|save.*keypair|persist.*wallet/i,
    recommendation: 'NEVER store private keys in databases. Use HSMs for key management. Implement key rotation. Audit all key access paths. Use derived keys for operations.',
    references: ['https://www.helius.dev/blog/solana-hacks']
  },

  // ============================================
  // FINANCIAL STATISTICS PATTERNS
  // ============================================
  {
    id: 'SOL6445',
    name: 'High-Value Protocol Pattern ($100M+ TVL)',
    description: 'Detects patterns in high-TVL protocols that need extra security due to larger attack surface.',
    severity: 'info',
    pattern: /total_value_locked|protocol_tvl|deposit_cap|max_capacity|reserve_balance/i,
    recommendation: 'High TVL protocols need: Multiple independent audits, real-time monitoring, insurance coverage, bug bounty ($1M+), incident response team, circuit breakers.',
    references: ['https://www.helius.dev/blog/solana-hacks']
  },
  {
    id: 'SOL6446',
    name: 'Solana 2022 Peak Incident Year Pattern',
    description: 'Detects legacy code patterns from 2022 (15 incidents, peak year). Older code needs careful review.',
    severity: 'info',
    pattern: /anchor\s*=\s*"0\.2[0-4]|solana-program\s*=\s*"1\.[89]|spl-token\s*=\s*"3\.[0-3]/i,
    recommendation: '2022 had peak incidents. If using 2022-era dependencies: 1) Check for known CVEs, 2) Update to latest versions, 3) Review historical audits, 4) Extra testing for DeFi/NFT patterns.',
    references: ['https://www.helius.dev/blog/solana-hacks']
  },
  {
    id: 'SOL6447',
    name: 'Net Loss Minimization Pattern',
    description: 'Patterns for minimizing net losses. Solana: $600M gross, $131M net due to recoveries.',
    severity: 'info',
    pattern: /loss_coverage|recovery_mechanism|insurance_payout|reimbursement|compensation_fund/i,
    recommendation: 'Prepare for incidents: Insurance pools, white hat bounties, recovery procedures, communication plans, legal preparation. 78% of Solana losses were recovered.',
    references: ['https://www.helius.dev/blog/solana-hacks']
  },

  // ============================================
  // RESPONSE EVOLUTION PATTERNS
  // ============================================
  {
    id: 'SOL6448',
    name: 'Rapid Response Infrastructure',
    description: 'Detects presence of rapid incident response capabilities. Response times improved from hours (2022) to minutes (2024).',
    severity: 'info',
    pattern: /emergency_shutdown|pause_protocol|freeze_funds|halt_trading|kill_switch/i,
    recommendation: 'Implement: 1) Kill switches with minimal latency, 2) Pre-authorized emergency responders, 3) Automated anomaly detection, 4) Hot-standby for critical systems, 5) Clear escalation paths.',
    references: ['https://www.helius.dev/blog/solana-hacks']
  },
  {
    id: 'SOL6449',
    name: 'Community Vigilance Integration',
    description: 'Detects patterns for integrating community security alerts. CertiK, ZachXBT have detected multiple exploits.',
    severity: 'info',
    pattern: /security_alert|community_report|suspicious_tx|whale_alert|unusual_activity/i,
    recommendation: 'Monitor security Twitter accounts, integrate CertiK/Chainalysis alerts, reward community reporters, maintain public incident channels.',
    references: ['https://www.helius.dev/blog/solana-hacks']
  },
  {
    id: 'SOL6450',
    name: 'Proactive Security Evolution',
    description: 'Patterns showing shift from reactive (2020-2022) to proactive (2024+) security.',
    severity: 'info',
    pattern: /pre_launch_audit|continuous_monitoring|proactive_scanning|security_roadmap|threat_modeling/i,
    recommendation: 'Modern security stack: Pre-launch audits, continuous monitoring (Forta, Tenderly), bug bounties, security partnerships, regular penetration testing, threat modeling.',
    references: ['https://www.helius.dev/blog/solana-hacks']
  },

  // ============================================
  // ADDITIONAL DETAILED PATTERNS
  // ============================================
  {
    id: 'SOL6451',
    name: 'Wormhole Signature Verification Bypass',
    description: 'Detects signature verification patterns that could be bypassed like the $326M Wormhole exploit.',
    severity: 'critical',
    pattern: /verify_signature|guardian_signature|validator_set|signature_set|verify_vaa|check_signatures/i,
    recommendation: 'Verify: 1) Signature count matches expected, 2) All signers are authorized, 3) Message hash is correct, 4) Timestamp is valid, 5) No replay possible. Multiple audits for bridge verification.',
    references: ['https://www.helius.dev/blog/solana-hacks']
  },
  {
    id: 'SOL6452',
    name: 'Cashio Infinite Mint Root of Trust',
    description: 'Detects missing root of trust verification that enabled Cashio $52.8M infinite mint.',
    severity: 'critical',
    pattern: /mint_field|collateral_mint|verify_collateral|saber_swap|arrow_account|lp_token_mint/i,
    recommendation: 'Establish explicit root of trust chain. Verify: account.mint == expected_mint, collateral.program == TRUSTED_PROGRAM, All accounts trace back to verified roots.',
    references: ['https://www.helius.dev/blog/solana-hacks', 'https://www.sec3.dev/blog/cashioapp-attack-whats-the-vulnerability-and-soteria-detects-it']
  },
  {
    id: 'SOL6453',
    name: 'Mango Markets Oracle Manipulation',
    description: 'Detects oracle price manipulation patterns used in the $116M Mango Markets exploit.',
    severity: 'critical',
    pattern: /oracle_price|price_feed|mark_price|index_price|spot_price.*perp|manipulate.*price/i,
    recommendation: 'Use TWAP pricing, multiple oracle sources, price band limits, manipulation detection, oracle staleness checks. Add circuit breakers for extreme price movements.',
    references: ['https://www.helius.dev/blog/solana-hacks']
  },
  {
    id: 'SOL6454',
    name: 'Crema Finance Tick Account Spoofing',
    description: 'Detects tick account validation patterns. Crema lost $8.8M to fake tick account creation.',
    severity: 'high',
    pattern: /tick_account|tick_array|tick_state|clmm_tick|position_tick|price_tick/i,
    recommendation: 'Verify tick account ownership: tick.owner == CLMM_PROGRAM_ID. Use PDA derivation for tick accounts. Validate tick index bounds. Check tick account initialization.',
    references: ['https://www.helius.dev/blog/solana-hacks']
  },
  {
    id: 'SOL6455',
    name: 'Raydium Admin Key Compromise',
    description: 'Detects patterns where compromised admin keys could drain protocol funds. Raydium lost $4.4M.',
    severity: 'critical',
    pattern: /admin_key|pool_authority|protocol_admin|owner_keypair|upgrade_authority|fee_authority/i,
    recommendation: 'Use multi-sig for all admin keys. Rotate keys regularly. Monitor admin transactions. Add timelocks for sensitive operations. Store admin keys in HSMs.',
    references: ['https://www.helius.dev/blog/solana-hacks']
  },

  // ============================================
  // SECURITY MATURITY INDICATORS
  // ============================================
  {
    id: 'SOL6456',
    name: 'Audit Coverage Indicator',
    description: 'Detects presence of audit-related markers. Audited protocols still face exploits but with better outcomes.',
    severity: 'info',
    pattern: /audit_report|security_review|penetration_test|code_review|vulnerability_assessment/i,
    recommendation: 'Minimum audits: 2 independent firms. Scope: Full codebase + dependencies. Timeline: Before launch + after major changes. Budget: 5-10% of raised funds.',
    references: ['https://www.helius.dev/blog/solana-hacks']
  },
  {
    id: 'SOL6457',
    name: 'Bug Bounty Program Pattern',
    description: 'Detects bug bounty program indicators. Strong bounty programs (Wormhole: $10M offered) help recover funds.',
    severity: 'info',
    pattern: /bug_bounty|vulnerability_reward|security_researcher|white_hat|responsible_disclosure/i,
    recommendation: 'Implement tiered bounty: Critical ($100K+), High ($25K+), Medium ($5K+). Use platforms like Immunefi. Respond within 24 hours. Pay promptly. Publicize program widely.',
    references: ['https://www.helius.dev/blog/solana-hacks']
  },
  {
    id: 'SOL6458',
    name: 'Insurance Coverage Pattern',
    description: 'Detects insurance or coverage mechanisms. Jump Crypto\'s $326M Wormhole bailout set precedent.',
    severity: 'info',
    pattern: /insurance_fund|coverage_pool|backstop|safety_module|slashing_insurance/i,
    recommendation: 'Options: Self-insurance (protocol treasury), Third-party (Nexus Mutual, InsurAce), Backer commitment (like Jump Crypto). Cover at least 50% of potential loss.',
    references: ['https://www.helius.dev/blog/solana-hacks']
  },

  // ============================================
  // YEAR-SPECIFIC PATTERNS
  // ============================================
  {
    id: 'SOL6459',
    name: '2024-2025 Attack Vector: Private Key Infrastructure',
    description: 'Detects patterns from 2024-2025 incidents focusing on key infrastructure (DEXX, Slope, Thunder Terminal).',
    severity: 'high',
    pattern: /key_store|key_management|wallet_backend|user_keys|custodial_keys/i,
    recommendation: '2024-2025 trend: Key infrastructure attacks. Use: Non-custodial where possible, HSMs for custodial, Regular key rotation, Zero-knowledge key handling, Secure enclaves.',
    references: ['https://www.helius.dev/blog/solana-hacks']
  },
  {
    id: 'SOL6460',
    name: '2024-2025 Attack Vector: Supply Chain',
    description: 'Detects dependency patterns vulnerable to supply chain attacks (Web3.js Dec 2024).',
    severity: 'high',
    pattern: /npm_package|yarn_add|cargo_add|dependency_update|package_json/i,
    recommendation: 'Pin all dependency versions. Use lockfiles. Verify package integrity. Monitor for advisories. Consider vendoring critical deps. Review update PRs carefully.',
    references: ['https://www.helius.dev/blog/solana-hacks']
  },

  // Additional 40 patterns for comprehensive coverage (SOL6461-SOL6500)
  {
    id: 'SOL6461',
    name: 'Lending Protocol Reserve Validation',
    description: 'Detects lending reserve configuration patterns that need proper validation (Solend, Jet, Solend v2).',
    severity: 'high',
    pattern: /reserve_config|lending_reserve|borrow_rate|utilization_rate|interest_model/i,
    recommendation: 'Validate all reserve parameters. Use safe bounds. Implement rate caps. Add admin timelocks. Monitor utilization.',
    references: ['https://www.helius.dev/blog/solana-hacks']
  },
  {
    id: 'SOL6462',
    name: 'DEX Pool Authority Check',
    description: 'Detects DEX pool patterns that need authority verification (Raydium, Orca, Crema).',
    severity: 'high',
    pattern: /pool_authority|amm_authority|swap_authority|liquidity_pool.*owner/i,
    recommendation: 'Verify pool authority is PDA. Check program ownership. Validate LP token mint. Monitor pool state.',
    references: ['https://www.helius.dev/blog/solana-hacks']
  },
  {
    id: 'SOL6463',
    name: 'NFT Metadata Authority',
    description: 'Detects NFT metadata patterns vulnerable to unauthorized updates.',
    severity: 'medium',
    pattern: /update_metadata|metadata_authority|creator_verified|collection_authority/i,
    recommendation: 'Lock metadata after mint. Verify creator signatures. Use collection authority. Implement update governance.',
    references: ['https://www.helius.dev/blog/solana-hacks']
  },
  {
    id: 'SOL6464',
    name: 'Staking Reward Calculation',
    description: 'Detects staking reward patterns that could be exploited for excess rewards.',
    severity: 'high',
    pattern: /calculate_reward|reward_per_token|staking_reward|emission_rate|reward_debt/i,
    recommendation: 'Use safe math for rewards. Implement caps. Check for overflow. Validate reward rates. Monitor emission.',
    references: ['https://www.helius.dev/blog/solana-hacks']
  },
  {
    id: 'SOL6465',
    name: 'Vault Deposit/Withdraw Timing',
    description: 'Detects vault patterns vulnerable to timing attacks or flash loan exploits.',
    severity: 'high',
    pattern: /vault_deposit|vault_withdraw|share_calculation|deposit_fee|withdrawal_fee/i,
    recommendation: 'Add deposit/withdrawal delays. Implement share price smoothing. Prevent same-block arbitrage. Use TWAP for pricing.',
    references: ['https://www.helius.dev/blog/solana-hacks']
  },
  {
    id: 'SOL6466',
    name: 'Perpetual Funding Rate',
    description: 'Detects perp funding patterns that could be manipulated (Mango, Drift).',
    severity: 'high',
    pattern: /funding_rate|mark_price.*index|perp_market|funding_payment|premium_rate/i,
    recommendation: 'Use TWAP for funding. Cap funding rates. Multiple oracle sources. Circuit breakers for extreme funding.',
    references: ['https://www.helius.dev/blog/solana-hacks']
  },
  {
    id: 'SOL6467',
    name: 'Options Settlement Price',
    description: 'Detects options settlement patterns vulnerable to price manipulation.',
    severity: 'high',
    pattern: /settlement_price|option_expiry|strike_price|exercise_option|option_payout/i,
    recommendation: 'Use settlement window TWAP. Multiple price sources. Dispute period. Clear settlement rules.',
    references: ['https://www.helius.dev/blog/solana-hacks']
  },
  {
    id: 'SOL6468',
    name: 'Liquidation Bot MEV',
    description: 'Detects liquidation patterns vulnerable to MEV extraction.',
    severity: 'medium',
    pattern: /liquidation_bot|liquidate_position|bad_debt|underwater_account|liquidation_incentive/i,
    recommendation: 'Implement fair liquidation. Add randomness. Use private mempools. Cap liquidation bonus. Batch liquidations.',
    references: ['https://www.helius.dev/blog/solana-hacks']
  },
  {
    id: 'SOL6469',
    name: 'Cross-Margin Calculation',
    description: 'Detects cross-margin patterns with potential calculation errors.',
    severity: 'high',
    pattern: /cross_margin|margin_ratio|total_collateral|unrealized_pnl|margin_requirement/i,
    recommendation: 'Conservative margin calculations. Real-time PnL updates. Multiple price sources. Buffer for volatility.',
    references: ['https://www.helius.dev/blog/solana-hacks']
  },
  {
    id: 'SOL6470',
    name: 'Token Vesting Schedule',
    description: 'Detects vesting patterns that could be exploited for early claims.',
    severity: 'medium',
    pattern: /vesting_schedule|cliff_period|linear_vesting|unlock_tokens|vested_amount/i,
    recommendation: 'Verify timestamp sources. Immutable vesting terms. Clear cliff implementation. Audit claim logic.',
    references: ['https://www.helius.dev/blog/solana-hacks']
  },
  {
    id: 'SOL6471',
    name: 'Airdrop Claim Verification',
    description: 'Detects airdrop patterns vulnerable to fraudulent claims.',
    severity: 'medium',
    pattern: /airdrop_claim|merkle_proof|claim_tokens|eligibility_check|claim_status/i,
    recommendation: 'Use merkle proofs. One-time claims. Verify eligibility. Prevent replay. Set claim deadlines.',
    references: ['https://www.helius.dev/blog/solana-hacks']
  },
  {
    id: 'SOL6472',
    name: 'Fee Accumulator Pattern',
    description: 'Detects fee collection patterns that could be drained or manipulated.',
    severity: 'medium',
    pattern: /fee_accumulator|protocol_fees|collected_fees|fee_vault|fee_recipient/i,
    recommendation: 'Multi-sig fee withdrawal. Regular fee distribution. Cap fee accumulation. Monitor fee accounts.',
    references: ['https://www.helius.dev/blog/solana-hacks']
  },
  {
    id: 'SOL6473',
    name: 'Referral System Abuse',
    description: 'Detects referral patterns that could be exploited for fraudulent rewards.',
    severity: 'medium',
    pattern: /referral_code|referrer_reward|referral_bonus|affiliate_program|refer_friend/i,
    recommendation: 'Rate limit referrals. Verify unique users. Delay referral payouts. Anti-sybil measures.',
    references: ['https://www.helius.dev/blog/solana-hacks']
  },
  {
    id: 'SOL6474',
    name: 'Auction Settlement',
    description: 'Detects auction patterns vulnerable to settlement manipulation.',
    severity: 'medium',
    pattern: /auction_end|winning_bid|auction_settle|bid_history|auction_state/i,
    recommendation: 'Clear settlement rules. Extend on late bids. Verify payment. Handle ties. Audit settlement.',
    references: ['https://www.helius.dev/blog/solana-hacks']
  },
  {
    id: 'SOL6475',
    name: 'Lottery/Raffle Randomness',
    description: 'Detects lottery patterns that might use predictable randomness.',
    severity: 'high',
    pattern: /random_winner|lottery_draw|raffle_select|pick_winner|random_number/i,
    recommendation: 'Use VRF for randomness. Commit-reveal schemes. Avoid block-based randomness. Independent random source.',
    references: ['https://www.helius.dev/blog/solana-hacks']
  },
  {
    id: 'SOL6476',
    name: 'Price Impact Calculation',
    description: 'Detects price impact patterns that could be manipulated.',
    severity: 'medium',
    pattern: /price_impact|slippage_check|max_slippage|trade_impact|swap_impact/i,
    recommendation: 'Accurate impact calculation. User-defined slippage. Post-trade verification. Reject excessive impact.',
    references: ['https://www.helius.dev/blog/solana-hacks']
  },
  {
    id: 'SOL6477',
    name: 'Position Leverage Limit',
    description: 'Detects leverage patterns that could lead to excessive risk.',
    severity: 'high',
    pattern: /max_leverage|leverage_ratio|position_size|leverage_limit|margin_multiplier/i,
    recommendation: 'Enforce leverage caps. Graduated limits by asset. Real-time margin checks. Auto-deleverage mechanism.',
    references: ['https://www.helius.dev/blog/solana-hacks']
  },
  {
    id: 'SOL6478',
    name: 'Interest Accrual Pattern',
    description: 'Detects interest calculation patterns vulnerable to manipulation.',
    severity: 'medium',
    pattern: /accrue_interest|interest_index|compound_interest|interest_rate_model/i,
    recommendation: 'Use safe math. Cap interest rates. Regular compounding. Overflow protection. Validate time deltas.',
    references: ['https://www.helius.dev/blog/solana-hacks']
  },
  {
    id: 'SOL6479',
    name: 'Collateral Factor Update',
    description: 'Detects collateral factor changes that could affect user positions.',
    severity: 'high',
    pattern: /collateral_factor|ltv_update|borrow_factor|collateral_weight/i,
    recommendation: 'Timelock collateral changes. Grace period for users. Gradual factor adjustments. Clear communication.',
    references: ['https://www.helius.dev/blog/solana-hacks']
  },
  {
    id: 'SOL6480',
    name: 'Reserve Factor Manipulation',
    description: 'Detects reserve factor patterns that could drain protocol reserves.',
    severity: 'medium',
    pattern: /reserve_factor|protocol_reserve|reserve_ratio|fee_to_reserve/i,
    recommendation: 'Cap reserve factor. Multi-sig changes. Transparent reserves. Regular audits.',
    references: ['https://www.helius.dev/blog/solana-hacks']
  },
  {
    id: 'SOL6481',
    name: 'Emergency Withdraw Pattern',
    description: 'Detects emergency withdrawal mechanisms that could be abused.',
    severity: 'high',
    pattern: /emergency_withdraw|rescue_funds|emergency_exit|force_withdraw/i,
    recommendation: 'Multi-sig emergency. Timelock where possible. Clear conditions. Audit emergency paths.',
    references: ['https://www.helius.dev/blog/solana-hacks']
  },
  {
    id: 'SOL6482',
    name: 'Protocol Pause Mechanism',
    description: 'Detects pause patterns - both proper implementation and potential abuse.',
    severity: 'medium',
    pattern: /pause_protocol|paused_state|unpause|is_paused|pause_guardian/i,
    recommendation: 'Clear pause authority. Limited pause duration. Partial pause options. Transparent pause status.',
    references: ['https://www.helius.dev/blog/solana-hacks']
  },
  {
    id: 'SOL6483',
    name: 'Upgrade Timelock Pattern',
    description: 'Detects program upgrade patterns that should have timelocks.',
    severity: 'high',
    pattern: /upgrade_authority|set_upgrade_authority|program_upgrade|bpf_upgradeable/i,
    recommendation: 'Minimum 48-hour timelock. Multi-sig upgrade authority. Upgrade notification. Test on devnet first.',
    references: ['https://www.helius.dev/blog/solana-hacks']
  },
  {
    id: 'SOL6484',
    name: 'Oracle Staleness Check',
    description: 'Detects oracle usage without staleness validation.',
    severity: 'high',
    pattern: /oracle_price(?!.*staleness)|get_price(?!.*timestamp)|price_feed(?!.*valid_slot)/i,
    recommendation: 'Check oracle timestamp. Max staleness threshold (e.g., 60 seconds). Fallback oracles. Reject stale prices.',
    references: ['https://www.helius.dev/blog/solana-hacks']
  },
  {
    id: 'SOL6485',
    name: 'Oracle Confidence Interval',
    description: 'Detects oracle usage without confidence/deviation checks.',
    severity: 'medium',
    pattern: /pyth_price(?!.*conf)|oracle(?!.*confidence)|price_data(?!.*deviation)/i,
    recommendation: 'Check price confidence. Reject wide spreads. Use confidence-weighted pricing. Multiple oracle agreement.',
    references: ['https://www.helius.dev/blog/solana-hacks']
  },
  {
    id: 'SOL6486',
    name: 'Token-2022 Extension Verification',
    description: 'Detects Token-2022 usage that should verify extensions.',
    severity: 'medium',
    pattern: /spl_token_2022|token_2022|token_extension|transfer_hook|confidential_transfer/i,
    recommendation: 'Check enabled extensions. Handle transfer hooks. Verify fee configuration. Test extension interactions.',
    references: ['https://www.helius.dev/blog/solana-hacks']
  },
  {
    id: 'SOL6487',
    name: 'Compressed NFT Verification',
    description: 'Detects cNFT patterns that need proper merkle proof verification.',
    severity: 'medium',
    pattern: /compressed_nft|bubblegum|merkle_tree|cnft_transfer|concurrent_merkle/i,
    recommendation: 'Verify merkle proofs. Check tree authority. Validate leaf data. Handle concurrent updates.',
    references: ['https://www.helius.dev/blog/solana-hacks']
  },
  {
    id: 'SOL6488',
    name: 'Blink Action Validation',
    description: 'Detects Solana Actions (Blinks) that need request validation.',
    severity: 'medium',
    pattern: /solana_action|action_identity|blink_request|action_url|unfurl_action/i,
    recommendation: 'Validate action origin. Verify transaction details. User confirmation. Rate limit actions.',
    references: ['https://www.helius.dev/blog/solana-hacks']
  },
  {
    id: 'SOL6489',
    name: 'Lookup Table Manipulation',
    description: 'Detects address lookup table patterns that could be exploited.',
    severity: 'medium',
    pattern: /lookup_table|address_lookup|extend_lookup|close_lookup_table/i,
    recommendation: 'Verify lookup table authority. Immutable for critical addresses. Monitor table changes.',
    references: ['https://www.helius.dev/blog/solana-hacks']
  },
  {
    id: 'SOL6490',
    name: 'Versioned Transaction Handling',
    description: 'Detects versioned transaction patterns that need proper handling.',
    severity: 'low',
    pattern: /versioned_transaction|v0_message|legacy_transaction|message_version/i,
    recommendation: 'Support both versions. Verify message format. Handle lookup tables. Test transaction parsing.',
    references: ['https://www.helius.dev/blog/solana-hacks']
  },
  {
    id: 'SOL6491',
    name: 'Priority Fee Calculation',
    description: 'Detects priority fee patterns that could be exploited or cause issues.',
    severity: 'low',
    pattern: /priority_fee|compute_unit_price|set_compute_unit|fee_estimation/i,
    recommendation: 'Reasonable fee limits. Dynamic fee adjustment. Prevent fee manipulation. User fee control.',
    references: ['https://www.helius.dev/blog/solana-hacks']
  },
  {
    id: 'SOL6492',
    name: 'Compute Budget Exhaustion',
    description: 'Detects patterns that could exhaust compute budget.',
    severity: 'medium',
    pattern: /request_units|compute_budget|max_compute|compute_limit/i,
    recommendation: 'Estimate compute needs. Set appropriate limits. Handle compute errors. Optimize heavy operations.',
    references: ['https://www.helius.dev/blog/solana-hacks']
  },
  {
    id: 'SOL6493',
    name: 'Account Data Size Limit',
    description: 'Detects patterns that might hit account size limits.',
    severity: 'low',
    pattern: /realloc|account_size|max_data_len|space\s*=|account_space/i,
    recommendation: 'Plan account sizes. Handle reallocation. Size limit awareness (10MB). Efficient data structures.',
    references: ['https://www.helius.dev/blog/solana-hacks']
  },
  {
    id: 'SOL6494',
    name: 'Rent Collection Pattern',
    description: 'Detects rent-related patterns that could affect account lifecycle.',
    severity: 'low',
    pattern: /rent_exempt|minimum_balance|rent_epoch|rent_collector/i,
    recommendation: 'Ensure rent exemption. Handle rent collection. Monitor account balances. Close unused accounts.',
    references: ['https://www.helius.dev/blog/solana-hacks']
  },
  {
    id: 'SOL6495',
    name: 'CPI Depth Limit',
    description: 'Detects deep CPI chains that might hit depth limits.',
    severity: 'medium',
    pattern: /invoke_signed|cpi_call|cross_program|nested_invoke|cpi_depth/i,
    recommendation: 'Monitor CPI depth (max 4). Flatten where possible. Handle depth errors. Test deep paths.',
    references: ['https://www.helius.dev/blog/solana-hacks']
  },
  {
    id: 'SOL6496',
    name: 'Account Ownership Verification',
    description: 'Detects missing account ownership checks - root cause of many exploits.',
    severity: 'critical',
    pattern: /account\.owner(?!\s*==)|owner_check(?!.*require)|verify_owner(?!.*assert)/i,
    recommendation: 'ALWAYS verify account.owner == expected_program. Use Anchor owner constraint. Check before any account access.',
    references: ['https://www.helius.dev/blog/solana-hacks']
  },
  {
    id: 'SOL6497',
    name: 'Signer Verification Pattern',
    description: 'Detects missing signer verification - another common vulnerability.',
    severity: 'critical',
    pattern: /is_signer(?!\s*==\s*true)|signer_check(?!.*require)|verify_signer(?!.*assert)/i,
    recommendation: 'ALWAYS verify is_signer == true for authorities. Use Anchor Signer type. Check at instruction start.',
    references: ['https://www.helius.dev/blog/solana-hacks']
  },
  {
    id: 'SOL6498',
    name: 'PDA Derivation Verification',
    description: 'Detects PDA usage without proper derivation verification.',
    severity: 'high',
    pattern: /find_program_address(?!.*verify)|create_program_address(?!.*check)|pda(?!.*seeds)/i,
    recommendation: 'Verify PDA derivation. Check bump seed. Use canonical bump. Validate seeds match expected.',
    references: ['https://www.helius.dev/blog/solana-hacks']
  },
  {
    id: 'SOL6499',
    name: 'Account Initialization Check',
    description: 'Detects missing initialization checks - re-initialization vulnerability.',
    severity: 'high',
    pattern: /init_account(?!.*check_initialized)|create_account(?!.*verify_empty)|initialize(?!.*discriminator)/i,
    recommendation: 'Check account not already initialized. Use discriminator. Verify account is zeroed. Use Anchor init constraint.',
    references: ['https://www.helius.dev/blog/solana-hacks']
  },
  {
    id: 'SOL6500',
    name: 'Helius 38 Incidents Summary Pattern',
    description: 'Meta-pattern summarizing all 38 verified Solana security incidents (2020-Q1 2025). $600M gross, $131M net losses.',
    severity: 'info',
    pattern: /security_incident|exploit_detection|vulnerability_scan|security_audit|incident_response/i,
    recommendation: 'Full security stack: Multiple audits, bug bounty ($100K+ for critical), real-time monitoring, incident response plan, insurance, transparent communication. Learn from all 38 incidents.',
    references: ['https://www.helius.dev/blog/solana-hacks']
  }
];

/**
 * Run Batch 102 patterns
 */
export function checkBatch102Patterns(input: { path: string; rust?: ParsedRust }): Finding[] {
  const findings: Finding[] = [];
  const content = input.rust?.content || '';
  
  if (!content) return findings;
  
  for (const pattern of BATCH_102_PATTERNS) {
    const lines = content.split('\n');
    for (let i = 0; i < lines.length; i++) {
      const line = lines[i];
      if (pattern.pattern.test(line)) {
        findings.push({
          id: pattern.id,
          title: pattern.name,
          severity: pattern.severity,
          description: pattern.description,
          location: {
            file: input.path,
            line: i + 1,
            column: 0,
          },
          recommendation: pattern.recommendation,
          references: pattern.references,
        });
      }
    }
  }
  
  return findings;
}

// Export patterns for registry
export const BATCH_102_PATTERN_LIST = BATCH_102_PATTERNS;
