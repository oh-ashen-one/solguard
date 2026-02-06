/**
 * SolGuard Batch 79 Security Patterns
 * Based on: Helius Complete History (38 incidents, $600M), Sec3 2025 Report, Insider Threats
 * 
 * Pattern IDs: SOL3976 - SOL4075 (100 patterns)
 * Created: Feb 6, 2026 1:30 AM CST
 * 
 * Sources:
 * - Helius "Solana Hacks, Bugs, and Exploits: A Complete History" (Q1 2025)
 * - Sec3 2025 Security Ecosystem Review (163 audits, 1,669 vulnerabilities)
 * - Insider Threat Incidents (Pump.fun $1.9M, Cypher $317K, Saga DAO $1.5M)
 * - Network-Level Attack Patterns (Jito DDoS, Phantom DoS, Turbine)
 * - Cross-Chain Bridge Evolution (Wormhole $326M patterns)
 */

import type { Finding, PatternInput } from './index.js';

// ============================================================================
// INSIDER THREAT PATTERNS (Emerging 2024-2025 vector)
// ============================================================================

const INSIDER_THREAT_PATTERNS: {
  id: string;
  name: string;
  severity: 'critical' | 'high' | 'medium' | 'low' | 'info';
  pattern: RegExp;
  description: string;
  recommendation: string;
}[] = [
  {
    id: 'SOL3976',
    name: 'Pump.fun - Employee Bonding Curve Access',
    severity: 'critical',
    pattern: /(?:bonding_curve|token_sale|launch)[\s\S]{0,100}(?:admin|employee|staff)[\s\S]{0,50}(?:access|withdraw|modify)/i,
    description: 'Insider access to bonding curve parameters. Pump.fun employee exploited flash loans to buy tokens using borrowed SOL ($1.9M).',
    recommendation: 'Implement multi-party computation (MPC) for token launch parameters. No single insider should control funds.'
  },
  {
    id: 'SOL3977',
    name: 'Pump.fun - Flash Loan During Bonding Phase',
    severity: 'critical',
    pattern: /(?:flash_loan|borrow)[\s\S]{0,80}(?:bonding|presale|launch)[\s\S]{0,50}(?:buy|purchase|acquire)/i,
    description: 'Flash loan used during token bonding phase. Pump.fun attacker used flash loaned SOL to front-run legitimate buyers.',
    recommendation: 'Add cooldown periods between borrowing and token purchases. Implement anti-bot mechanisms.'
  },
  {
    id: 'SOL3978',
    name: 'Cypher - Credential Persistence Post-Termination',
    severity: 'critical',
    pattern: /(?:api_key|secret|credential)[\s\S]{0,100}(?:revoke|rotate|expire)[\s\S]{0,50}(?!immediately|instant|forced)/i,
    description: 'API keys not immediately revoked upon employee termination. Cypher $317K theft involved former employee retaining access.',
    recommendation: 'Implement immediate credential revocation upon any personnel change. Use just-in-time access provisioning.'
  },
  {
    id: 'SOL3979',
    name: 'Cypher - Insider Treasury Access Pattern',
    severity: 'critical',
    pattern: /(?:treasury|vault|reserve)[\s\S]{0,80}(?:single|individual|direct)[\s\S]{0,50}access/i,
    description: 'Single individual has treasury access without oversight. Cypher insider theft exploited direct treasury control.',
    recommendation: 'Require multi-party approval for all treasury operations. Implement segregation of duties.'
  },
  {
    id: 'SOL3980',
    name: 'Saga DAO - Insider Fund Manipulation',
    severity: 'critical',
    pattern: /(?:dao|governance)[\s\S]{0,100}(?:treasury|fund)[\s\S]{0,50}(?:single|one)[\s\S]{0,30}(?:member|signer)/i,
    description: 'DAO funds controlled by single member. Saga DAO $1.5M loss involved leadership role abuse.',
    recommendation: 'Implement on-chain governance for all fund movements. Use time-locked proposals with community veto.'
  },
  {
    id: 'SOL3981',
    name: 'Insider Role Assignment Without Timelock',
    severity: 'high',
    pattern: /(?:role|permission)[\s\S]{0,80}(?:assign|grant|give)[\s\S]{0,50}(?!timelock|delay|pending)/i,
    description: 'Role assignments happen immediately without cooling period. Enables rapid insider privilege escalation.',
    recommendation: 'Add minimum 24-48 hour timelock for all role changes. Emit events for monitoring.'
  },
  {
    id: 'SOL3982',
    name: 'No Background Check Verification',
    severity: 'medium',
    pattern: /(?:employee|contractor|team)[\s\S]{0,100}(?:add|onboard|create)[\s\S]{0,50}(?:access|permission)/i,
    description: 'Access granted without verification. Multiple insider attacks stem from insufficient vetting.',
    recommendation: 'Implement progressive trust model. New team members get limited access initially.'
  },
  {
    id: 'SOL3983',
    name: 'Missing Access Audit Trail',
    severity: 'high',
    pattern: /(?:admin|authority|privileged)[\s\S]{0,80}(?:action|operation)[\s\S]{0,50}(?!log|audit|emit|event)/i,
    description: 'Privileged actions not logged. Makes insider threat detection and forensics difficult.',
    recommendation: 'Log all privileged operations with timestamp, actor, and action details. Use immutable logs.'
  },

  // ============================================================================
  // NETWORK-LEVEL ATTACK PATTERNS (DDoS, Congestion, Infrastructure)
  // ============================================================================

  {
    id: 'SOL3984',
    name: 'Jito DDoS - Bundle Spam Attack',
    severity: 'high',
    pattern: /(?:jito|bundle|mev)[\s\S]{0,100}(?:spam|flood|mass)[\s\S]{0,50}(?:submit|send)/i,
    description: 'MEV bundle spam causing network degradation. Jito DDoS (Feb 2024) involved malicious bundle flooding.',
    recommendation: 'Implement rate limiting per searcher. Add bundle quality scoring and filtering.'
  },
  {
    id: 'SOL3985',
    name: 'Phantom DoS - Transaction Simulation Flood',
    severity: 'high',
    pattern: /(?:simulate|preview)[\s\S]{0,80}(?:transaction|tx)[\s\S]{0,50}(?:mass|batch|many)/i,
    description: 'Mass transaction simulation requests causing wallet DoS. Phantom wallet DoS (Mar 2024) degraded user experience.',
    recommendation: 'Rate limit simulation requests. Implement request queuing and prioritization.'
  },
  {
    id: 'SOL3986',
    name: 'Candy Machine Minting DoS',
    severity: 'high',
    pattern: /(?:candy_machine|nft_mint|collection)[\s\S]{0,100}(?:mass|flood|bot)[\s\S]{0,50}(?:mint|request)/i,
    description: 'Botted NFT mint requests causing network congestion. Multiple 2021-2022 incidents degraded Solana performance.',
    recommendation: 'Implement fair launch mechanisms: captcha, allowlists, random selection.'
  },
  {
    id: 'SOL3987',
    name: 'Grape Protocol - Fee Market Attack',
    severity: 'medium',
    pattern: /(?:priority_fee|fee)[\s\S]{0,80}(?:spike|manipulate|exploit)/i,
    description: 'Fee market manipulation causing transaction delays. Grape Protocol incident showed fee-based attacks.',
    recommendation: 'Implement fee caps and surge protection. Use fee estimation with bounds.'
  },
  {
    id: 'SOL3988',
    name: 'Turbine Propagation Failure Pattern',
    severity: 'critical',
    pattern: /(?:turbine|shred|propagate)[\s\S]{0,100}(?:fail|timeout|loss)/i,
    description: 'Block propagation failures causing network instability. Core protocol vulnerability affected entire network.',
    recommendation: 'Implement redundant propagation paths. Add automatic failover mechanisms.'
  },
  {
    id: 'SOL3989',
    name: 'JIT Cache Corruption Risk',
    severity: 'high',
    pattern: /(?:jit|cache|compile)[\s\S]{0,80}(?:corrupt|overflow|invalid)/i,
    description: 'JIT cache bugs can cause validator crashes. 5-hour outage in 2022 from cache corruption.',
    recommendation: 'Implement cache validation and integrity checks. Add automatic recovery.'
  },

  // ============================================================================
  // RESPONSE TIME EVOLUTION PATTERNS (Detection improvement)
  // ============================================================================

  {
    id: 'SOL3990',
    name: 'Missing Real-Time Monitoring',
    severity: 'high',
    pattern: /(?:monitor|watch|alert)[\s\S]{0,100}(?:manual|periodic|daily)[\s\S]{0,50}(?!realtime|instant|continuous)/i,
    description: 'No real-time monitoring for anomalies. Modern exploits detected in minutes (Thunder Terminal: 9 min), not hours.',
    recommendation: 'Implement real-time monitoring with sub-minute alerting. Use ML-based anomaly detection.'
  },
  {
    id: 'SOL3991',
    name: 'No Automated Circuit Breaker',
    severity: 'critical',
    pattern: /(?:withdraw|transfer|drain)[\s\S]{0,100}(?:large|unusual|abnormal)[\s\S]{0,50}(?!pause|halt|freeze)/i,
    description: 'No automatic halt on suspicious activity. Modern protocols pause within minutes of detection.',
    recommendation: 'Implement automated circuit breakers that trigger on anomaly detection.'
  },
  {
    id: 'SOL3992',
    name: 'Missing Community Alert Integration',
    severity: 'medium',
    pattern: /(?:alert|notify|report)[\s\S]{0,80}(?!certik|zachxbt|community|twitter)/i,
    description: 'No integration with community security researchers. CertiK (SVT), ZachXBT (NoOnes) alerted protocols early.',
    recommendation: 'Monitor security researcher channels. Implement rapid response to community alerts.'
  },

  // ============================================================================
  // CROSS-CHAIN BRIDGE SECURITY (Wormhole $326M lessons)
  // ============================================================================

  {
    id: 'SOL3993',
    name: 'Wormhole - Guardian Signature Verification Bypass',
    severity: 'critical',
    pattern: /(?:verify|validate)[\s\S]{0,80}(?:signature|guardian|quorum)[\s\S]{0,50}(?:skip|bypass|missing)/i,
    description: 'Signature verification bypass in bridge. Wormhole $326M exploit forged valid guardian signatures.',
    recommendation: 'Implement defense-in-depth for signature verification. Multiple independent checks required.'
  },
  {
    id: 'SOL3994',
    name: 'Wormhole - SignatureSet Account Spoofing',
    severity: 'critical',
    pattern: /(?:signature_set|guardian_set)[\s\S]{0,100}(?:account|address)[\s\S]{0,50}(?!owner_check|verify_owner)/i,
    description: 'SignatureSet account owner not verified. Attacker created fake SignatureSet to bypass validation.',
    recommendation: 'Always verify account owner matches expected program. Check all reference-only accounts.'
  },
  {
    id: 'SOL3995',
    name: 'Bridge VAA Validation Incomplete',
    severity: 'critical',
    pattern: /(?:vaa|message|payload)[\s\S]{0,100}(?:validate|verify)[\s\S]{0,50}(?!all_fields|complete|full)/i,
    description: 'Incomplete VAA (Verified Action Approval) validation. Partial validation enables bypass attacks.',
    recommendation: 'Validate ALL VAA fields: nonce, timestamp, emitter, sequence, consistency level, payload.'
  },
  {
    id: 'SOL3996',
    name: 'Bridge Message Replay Without Nonce',
    severity: 'critical',
    pattern: /(?:bridge|cross_chain)[\s\S]{0,100}(?:message|transfer)[\s\S]{0,50}(?!nonce|sequence|replay_check)/i,
    description: 'Bridge messages can be replayed. Missing sequence/nonce tracking enables double-spending.',
    recommendation: 'Track processed message sequences. Mark messages as consumed after processing.'
  },
  {
    id: 'SOL3997',
    name: 'Bridge Finality Assumption',
    severity: 'high',
    pattern: /(?:bridge|cross_chain)[\s\S]{0,80}(?:finality|confirm)[\s\S]{0,50}(?:instant|immediate|single)/i,
    description: 'Assuming instant finality on source chain. Reorgs can invalidate bridged transactions.',
    recommendation: 'Wait for sufficient confirmations based on source chain finality characteristics.'
  },
  {
    id: 'SOL3998',
    name: 'Bridge Rate Limit Missing',
    severity: 'high',
    pattern: /(?:bridge|mint|transfer)[\s\S]{0,100}(?:amount|volume)[\s\S]{0,50}(?!limit|cap|max)/i,
    description: 'No rate limiting on bridge transfers. Enables rapid draining in exploit scenarios.',
    recommendation: 'Implement hourly/daily rate limits. Require governance for limit increases.'
  },

  // ============================================================================
  // ORACLE MANIPULATION PATTERNS (Mango $116M lessons)
  // ============================================================================

  {
    id: 'SOL3999',
    name: 'Mango Markets - Single Oracle Dependency',
    severity: 'critical',
    pattern: /(?:oracle|price_feed)[\s\S]{0,100}(?:single|one|only)[\s\S]{0,50}(?:source|provider)/i,
    description: 'Single oracle source for price data. Mango $116M exploit manipulated thin liquidity markets.',
    recommendation: 'Use multiple oracle sources. Aggregate with weighted median or outlier rejection.'
  },
  {
    id: 'SOL4000',
    name: 'Mango Markets - Missing Confidence Interval',
    severity: 'high',
    pattern: /(?:oracle|price)[\s\S]{0,80}(?:use|fetch)[\s\S]{0,50}(?!confidence|deviation|band)/i,
    description: 'Using oracle price without confidence check. Wide confidence = potentially manipulated.',
    recommendation: 'Always check Pyth confidence intervals. Reject prices with >2% confidence spread.'
  },
  {
    id: 'SOL4001',
    name: 'Oracle TWAP Window Too Short',
    severity: 'high',
    pattern: /(?:twap|time_weighted)[\s\S]{0,80}(?:window|period)[\s\S]{0,50}(?:30|60|120)[\s\S]{0,20}(?:second|sec)/i,
    description: 'TWAP window too short for manipulation resistance. Sub-minute TWAPs easily gamed.',
    recommendation: 'Use minimum 5-minute TWAP windows. Consider 15-30 minutes for large value decisions.'
  },
  {
    id: 'SOL4002',
    name: 'LP Token Oracle Manipulation',
    severity: 'critical',
    pattern: /(?:lp_token|pool_share)[\s\S]{0,100}(?:price|value)[\s\S]{0,50}(?:reserves|spot)/i,
    description: 'Valuing LP tokens using spot reserves. OtterSec "$200M Bluff" showed reserve manipulation.',
    recommendation: 'Use fair LP token pricing: geometric mean of reserves * sqrt(k). Never use spot reserves.'
  },

  // ============================================================================
  // PRIVATE KEY EXPOSURE PATTERNS (DEXX $30M, Slope $8M)
  // ============================================================================

  {
    id: 'SOL4003',
    name: 'DEXX - Private Key Server Storage',
    severity: 'critical',
    pattern: /(?:private_key|secret_key|seed_phrase)[\s\S]{0,100}(?:store|save|persist)[\s\S]{0,50}(?:server|database|cloud)/i,
    description: 'Private keys stored on server. DEXX $30M exploit - keys stored in centralized server were leaked.',
    recommendation: 'NEVER store user private keys server-side. Use client-side encryption only.'
  },
  {
    id: 'SOL4004',
    name: 'Slope Wallet - Seed Phrase Logging',
    severity: 'critical',
    pattern: /(?:seed|mnemonic|phrase)[\s\S]{0,80}(?:log|print|debug|console)/i,
    description: 'Seed phrases logged to external service. Slope Wallet $8M - seeds sent to Sentry telemetry.',
    recommendation: 'Never log sensitive data. Audit all logging and telemetry integrations.'
  },
  {
    id: 'SOL4005',
    name: 'Trading Bot Custody Risk',
    severity: 'critical',
    pattern: /(?:trading_bot|bot|automated)[\s\S]{0,100}(?:full_access|unlimited|custody)[\s\S]{0,50}(?:wallet|funds)/i,
    description: 'Trading bots with full wallet custody. Banana Gun $1.4M - bot compromise drained user funds.',
    recommendation: 'Use delegated signing with operation limits. Implement withdrawal address whitelists.'
  },
  {
    id: 'SOL4006',
    name: 'Hot Wallet Key Single Point of Failure',
    severity: 'critical',
    pattern: /(?:hot_wallet|operational)[\s\S]{0,80}(?:single|one)[\s\S]{0,50}(?:key|signer)/i,
    description: 'Hot wallet with single key. Multiple exploits target hot wallet compromise.',
    recommendation: 'Use threshold signatures (TSS) for hot wallets. Implement time-delayed withdrawals.'
  },

  // ============================================================================
  // SUPPLY CHAIN ATTACK PATTERNS (Web3.js, Parcl)
  // ============================================================================

  {
    id: 'SOL4007',
    name: 'Web3.js Supply Chain - NPM Backdoor',
    severity: 'critical',
    pattern: /(?:@solana\/web3|web3\.js)[\s\S]{0,100}(?:version|dependency)[\s\S]{0,50}(?!\d+\.\d+\.\d+|pinned|locked)/i,
    description: 'Unpinned Web3.js version. Dec 2024 supply chain attack injected malicious code into npm package.',
    recommendation: 'Pin all dependency versions. Use package-lock.json with integrity hashes.'
  },
  {
    id: 'SOL4008',
    name: 'Supply Chain - Postinstall Script Risk',
    severity: 'high',
    pattern: /(?:postinstall|preinstall)[\s\S]{0,80}(?:script|hook)/i,
    description: 'NPM install scripts can execute arbitrary code. Web3.js attack used postinstall to exfiltrate.',
    recommendation: 'Audit all dependency install scripts. Use npm audit and security scanning.'
  },
  {
    id: 'SOL4009',
    name: 'Parcl Frontend - CDN/Hosting Compromise',
    severity: 'high',
    pattern: /(?:frontend|cdn|hosting)[\s\S]{0,100}(?:inject|modify|replace)[\s\S]{0,50}(?:script|code)/i,
    description: 'Frontend code modified via CDN compromise. Parcl attack injected malicious transaction preview.',
    recommendation: 'Use SRI (Subresource Integrity) for all external scripts. Monitor for unauthorized changes.'
  },
  {
    id: 'SOL4010',
    name: 'Missing Build Reproducibility',
    severity: 'medium',
    pattern: /(?:build|compile|deploy)[\s\S]{0,80}(?!reproducible|verifiable|deterministic)/i,
    description: 'Non-reproducible builds enable supply chain injection. Cannot verify deployed code matches source.',
    recommendation: 'Implement reproducible builds. Publish build attestations.'
  },

  // ============================================================================
  // APPLICATION EXPLOIT PATTERNS (26 incidents analyzed)
  // ============================================================================

  {
    id: 'SOL4011',
    name: 'Solend Auth Bypass - UpdateReserveConfig',
    severity: 'critical',
    pattern: /(?:update|modify)[\s\S]{0,80}(?:reserve|config|param)[\s\S]{0,50}(?:auth|owner)[\s\S]{0,30}(?!strict|verify)/i,
    description: 'Reserve config update with loose auth check. Solend 2021 - attacker bypassed admin by creating fake lending market.',
    recommendation: 'Verify ALL authority paths lead to trusted root. No alternate authority accounts.'
  },
  {
    id: 'SOL4012',
    name: 'Solend - Liquidation Threshold Manipulation',
    severity: 'critical',
    pattern: /(?:liquidation)[\s\S]{0,80}(?:threshold|ratio|factor)[\s\S]{0,50}(?:set|update|change)/i,
    description: 'Liquidation threshold can be arbitrarily changed. Solend attack lowered thresholds to liquidate users.',
    recommendation: 'Add bounds and rate limits on liquidation parameter changes. Use governance for changes.'
  },
  {
    id: 'SOL4013',
    name: 'Crema Finance - Tick Account Owner Bypass',
    severity: 'critical',
    pattern: /(?:tick|position)[\s\S]{0,100}(?:account)[\s\S]{0,50}(?:owner)[\s\S]{0,30}(?!check|verify|assert)/i,
    description: 'CLMM tick account owner not verified. Crema $8.8M - fake tick account claimed inflated fees.',
    recommendation: 'Verify tick account owner matches CLMM program. Check all position data accounts.'
  },
  {
    id: 'SOL4014',
    name: 'Cashio Infinite Mint - Missing Root of Trust',
    severity: 'critical',
    pattern: /(?:collateral|backing)[\s\S]{0,100}(?:mint|token)[\s\S]{0,50}(?!whitelist|verify|root_of_trust)/i,
    description: 'Collateral mint not validated against whitelist. Cashio $52M - attacker used worthless fake collateral.',
    recommendation: 'Establish explicit root of trust for all collateral. Whitelist allowed mint addresses.'
  },
  {
    id: 'SOL4015',
    name: 'OptiFi - Accidental Program Close',
    severity: 'critical',
    pattern: /(?:program|close|shutdown)[\s\S]{0,80}(?:authority|admin)[\s\S]{0,50}(?!confirmation|multi_step)/i,
    description: 'Program close without confirmation. OptiFi $661K - accidentally closed program, locking user funds.',
    recommendation: 'Implement multi-step close with timelock. Require governance approval for program operations.'
  },
  {
    id: 'SOL4016',
    name: 'Raydium - Pool Admin Drain',
    severity: 'critical',
    pattern: /(?:pool|amm)[\s\S]{0,80}(?:admin|authority)[\s\S]{0,50}(?:withdraw|drain|sweep)/i,
    description: 'Pool admin can drain funds. Raydium $4.4M - compromised admin key drained pools.',
    recommendation: 'Admin operations should require timelocks. Implement withdrawal limits and monitoring.'
  },
  {
    id: 'SOL4017',
    name: 'Audius - Governance Storage Slot Collision',
    severity: 'critical',
    pattern: /(?:governance|vote)[\s\S]{0,100}(?:storage|state)[\s\S]{0,50}(?:slot|index)[\s\S]{0,30}(?:init|config)/i,
    description: 'Governance storage layout collision. Audius $6.1M - proxy storage collision enabled unauthorized access.',
    recommendation: 'Use EIP-1967 style storage slots. Audit all proxy/upgrade storage layouts.'
  },
  {
    id: 'SOL4018',
    name: 'Nirvana - Bonding Curve Flash Loan Attack',
    severity: 'critical',
    pattern: /(?:bonding_curve|ana_token)[\s\S]{0,100}(?:flash_loan|borrow)[\s\S]{0,50}(?:arbitrage|manipulate)/i,
    description: 'Bonding curve exploited via flash loan. Nirvana $3.5M - flash loan manipulated curve for profit.',
    recommendation: 'Add flash loan protection to bonding curves. Implement execution deadlines and slippage.'
  },

  // ============================================================================
  // THIRD-PARTY INTEGRATION PATTERNS (Thunder Terminal, io.net)
  // ============================================================================

  {
    id: 'SOL4019',
    name: 'Thunder Terminal - MongoDB Connection String Exposure',
    severity: 'critical',
    pattern: /(?:mongodb|database)[\s\S]{0,100}(?:connection|url|string)[\s\S]{0,50}(?:env|config|exposed)/i,
    description: 'Database credentials exposed. Thunder Terminal $240K - MongoDB injection via exposed connection.',
    recommendation: 'Use secret management (Vault, AWS Secrets). Never expose DB credentials in config.'
  },
  {
    id: 'SOL4020',
    name: 'Thunder Terminal - Session Token Theft',
    severity: 'critical',
    pattern: /(?:session|auth)[\s\S]{0,80}(?:token|cookie)[\s\S]{0,50}(?:storage|persist)[\s\S]{0,30}(?!encrypted|secure)/i,
    description: 'Session tokens stored insecurely. Thunder Terminal attack stole session tokens for user impersonation.',
    recommendation: 'Encrypt session tokens at rest. Implement short expiry and rotation.'
  },
  {
    id: 'SOL4021',
    name: 'io.net - API Key Exposure in Logs',
    severity: 'high',
    pattern: /(?:api_key|secret)[\s\S]{0,80}(?:log|print|output|debug)/i,
    description: 'API keys leaked in logs. io.net incident exposed keys through improper logging.',
    recommendation: 'Implement log scrubbing for sensitive data. Use structured logging with redaction.'
  },
  {
    id: 'SOL4022',
    name: 'Third-Party Dependency Audit Missing',
    severity: 'high',
    pattern: /(?:dependency|package|library)[\s\S]{0,100}(?!audit|scan|check|verify)/i,
    description: 'Third-party dependencies not audited. Multiple supply chain attacks exploit unaudited deps.',
    recommendation: 'Run npm audit, cargo audit. Use Snyk or similar for continuous vulnerability scanning.'
  },

  // ============================================================================
  // PROTOCOL-SPECIFIC ADVANCED PATTERNS
  // ============================================================================

  {
    id: 'SOL4023',
    name: 'Tulip Flash Loan Vault Manipulation',
    severity: 'high',
    pattern: /(?:vault|strategy)[\s\S]{0,100}(?:flash_loan)[\s\S]{0,50}(?:deposit|withdraw|rebalance)/i,
    description: 'Vault strategies manipulated via flash loans. Tulip $5.2M - flash loan affected vault share calculations.',
    recommendation: 'Protect vault operations from same-block flash loan manipulation. Add share price bounds.'
  },
  {
    id: 'SOL4024',
    name: 'UXD Stablecoin Collateral Depeg Risk',
    severity: 'high',
    pattern: /(?:stablecoin|usd)[\s\S]{0,100}(?:collateral)[\s\S]{0,50}(?:single|concentrated)/i,
    description: 'Stablecoin backed by concentrated collateral. UXD $3.9M at risk from delta-neutral position depeg.',
    recommendation: 'Diversify collateral across multiple assets and protocols. Monitor concentration risk.'
  },
  {
    id: 'SOL4025',
    name: 'Aurory Game Marketplace Exploit',
    severity: 'high',
    pattern: /(?:game|marketplace)[\s\S]{0,100}(?:item|nft)[\s\S]{0,50}(?:duplicate|clone|spoof)/i,
    description: 'Gaming marketplace item duplication. Aurory $830K - off-chain balance race condition.',
    recommendation: 'Implement atomic off-chain balance updates. Add deduplication checks.'
  },
  {
    id: 'SOL4026',
    name: 'Synthetify DAO Treasury Heist Pattern',
    severity: 'critical',
    pattern: /(?:dao|governance)[\s\S]{0,100}(?:treasury|fund)[\s\S]{0,50}(?:proposal|execute)[\s\S]{0,30}(?!delay|timelock)/i,
    description: 'DAO treasury drained without timelock. Synthetify $230K - governance proposals executed immediately.',
    recommendation: 'Enforce minimum 24-72 hour timelock on all treasury operations. Add veto period.'
  },
  {
    id: 'SOL4027',
    name: 'SVT Token Unclaimed Airdrop Vulnerability',
    severity: 'high',
    pattern: /(?:airdrop|claim)[\s\S]{0,100}(?:unclaimed|pending)[\s\S]{0,50}(?:access|recover)/i,
    description: 'Unclaimed airdrop tokens exploitable. SVT $1M - vulnerability in unclaimed token handling.',
    recommendation: 'Implement proper access controls for unclaimed tokens. Add claim deadlines.'
  },
  {
    id: 'SOL4028',
    name: 'NoOnes P2P Escrow Withdrawal Bypass',
    severity: 'critical',
    pattern: /(?:escrow|p2p)[\s\S]{0,100}(?:withdraw|release)[\s\S]{0,50}(?:verify|confirm)[\s\S]{0,30}(?!both_parties|mutual)/i,
    description: 'P2P escrow withdrawal without proper verification. NoOnes $8.5M - withdrawal verification bypassed.',
    recommendation: 'Require cryptographic proof from both parties before escrow release.'
  },
  {
    id: 'SOL4029',
    name: 'Solareum Rug Pull Pattern',
    severity: 'critical',
    pattern: /(?:liquidity|pool)[\s\S]{0,100}(?:remove|withdraw|pull)[\s\S]{0,50}(?:admin|owner)[\s\S]{0,30}(?!locked|timelocked)/i,
    description: 'Liquidity removable by admin without restrictions. Solareum $523K rug pull.',
    recommendation: 'Lock liquidity or implement gradual unlock schedules. Use LP token burns.'
  },

  // ============================================================================
  // 2025-2026 EMERGING VECTORS
  // ============================================================================

  {
    id: 'SOL4030',
    name: 'Blinks Action URL Manipulation',
    severity: 'high',
    pattern: /(?:blink|action)[\s\S]{0,100}(?:url|link)[\s\S]{0,50}(?!validate|verify|whitelist)/i,
    description: 'Solana Actions (Blinks) URL not validated. Malicious URLs can trigger unintended transactions.',
    recommendation: 'Whitelist allowed action URLs. Implement strict URL validation and preview.'
  },
  {
    id: 'SOL4031',
    name: 'cNFT Merkle Proof Validation Missing',
    severity: 'critical',
    pattern: /(?:compressed|cnft|bubblegum)[\s\S]{0,100}(?:proof|merkle)[\s\S]{0,50}(?!verify|validate|check)/i,
    description: 'Compressed NFT proof not validated. Invalid proofs can claim or transfer NFTs.',
    recommendation: 'Always verify Merkle proofs against root. Check canopy data integrity.'
  },
  {
    id: 'SOL4032',
    name: 'Token-2022 Transfer Hook Reentrancy',
    severity: 'critical',
    pattern: /(?:transfer_hook|token-2022)[\s\S]{0,100}(?:callback|hook)[\s\S]{0,50}(?!reentrancy|guard|lock)/i,
    description: 'Transfer hooks can enable reentrancy. New Token-2022 attack vector.',
    recommendation: 'Implement reentrancy guards for all transfer hook handlers.'
  },
  {
    id: 'SOL4033',
    name: 'Lookup Table Poisoning',
    severity: 'high',
    pattern: /(?:lookup_table|address_table)[\s\S]{0,100}(?:add|extend)[\s\S]{0,50}(?!verify|validate)/i,
    description: 'Address lookup tables can be poisoned with malicious addresses.',
    recommendation: 'Verify lookup table authority. Validate all addresses before adding.'
  },
  {
    id: 'SOL4034',
    name: 'Stake Pool Rate Manipulation',
    severity: 'high',
    pattern: /(?:stake_pool|lst)[\s\S]{0,100}(?:rate|exchange)[\s\S]{0,50}(?:update|change)[\s\S]{0,30}(?!bounded|limited)/i,
    description: 'Stake pool exchange rate manipulatable. Semantic inconsistency vulnerability.',
    recommendation: 'Bound rate changes per epoch. Implement gradual rate updates.'
  },
  {
    id: 'SOL4035',
    name: 'DePIN Worker Spoofing',
    severity: 'high',
    pattern: /(?:depin|worker|node)[\s\S]{0,100}(?:verify|attest)[\s\S]{0,50}(?!proof_of_work|hardware_attestation)/i,
    description: 'DePIN worker identity spoofable. io.net GPU spoofing incident.',
    recommendation: 'Implement hardware attestation. Use proof-of-physical-work verification.'
  },

  // ============================================================================
  // DEFENSIVE PATTERNS (Best Practices)
  // ============================================================================

  {
    id: 'SOL4036',
    name: 'Missing 2FA for Admin Operations',
    severity: 'high',
    pattern: /(?:admin|authority)[\s\S]{0,100}(?:action|operation)[\s\S]{0,50}(?!2fa|mfa|multi_factor)/i,
    description: 'Admin operations without 2FA. Step Finance, Raydium compromises involved single-factor auth.',
    recommendation: 'Require hardware key 2FA for all admin operations. Use Yubikey or similar.'
  },
  {
    id: 'SOL4037',
    name: 'No Insurance Fund',
    severity: 'medium',
    pattern: /(?:protocol|platform)[\s\S]{0,100}(?:fund|reserve)[\s\S]{0,50}(?!insurance|coverage|protection)/i,
    description: 'No insurance fund for user protection. Cashio, Solareum collapsed without user recovery.',
    recommendation: 'Build insurance fund from protocol fees. Partner with DeFi insurance providers.'
  },
  {
    id: 'SOL4038',
    name: 'Missing Incident Response Plan',
    severity: 'medium',
    pattern: /(?:incident|breach|hack)[\s\S]{0,100}(?:response|plan|procedure)[\s\S]{0,50}(?!documented|tested)/i,
    description: 'No documented incident response. Fast response (Thunder Terminal 9min) requires preparation.',
    recommendation: 'Document and test incident response procedures. Assign clear roles and escalation paths.'
  },
  {
    id: 'SOL4039',
    name: 'No Bug Bounty Program',
    severity: 'medium',
    pattern: /(?:vulnerability|bug)[\s\S]{0,100}(?:report|disclosure)[\s\S]{0,50}(?!bounty|reward|immunefi)/i,
    description: 'No bug bounty incentivizes responsible disclosure. Wormhole offered $10M bounty post-exploit.',
    recommendation: 'Establish bug bounty program before launch. Use Immunefi or similar platforms.'
  },
  {
    id: 'SOL4040',
    name: 'Audit-Only Security (No Continuous)',
    severity: 'medium',
    pattern: /(?:audit|review)[\s\S]{0,100}(?:one_time|single|launch)[\s\S]{0,50}(?!continuous|ongoing|monitoring)/i,
    description: 'Security stops at launch audit. 99.4% of Sec3 audits found vulnerabilities - code changes need re-audit.',
    recommendation: 'Implement continuous security monitoring. Re-audit after significant code changes.'
  },

  // ============================================================================
  // DATA INTEGRITY & ARITHMETIC (8.9% of Sec3 findings)
  // ============================================================================

  {
    id: 'SOL4041',
    name: 'Division Before Multiplication Precision Loss',
    severity: 'high',
    pattern: /(?:\/|\bdiv\b)[\s\S]{0,30}(?:\*|\bmul\b)/i,
    description: 'Division before multiplication causes precision loss. Common in fee and reward calculations.',
    recommendation: 'Always multiply before dividing. Use fixed-point math libraries.'
  },
  {
    id: 'SOL4042',
    name: 'Rounding Direction Inconsistent',
    severity: 'high',
    pattern: /(?:round|floor|ceil)[\s\S]{0,80}(?!consistent|favor_protocol|documented)/i,
    description: 'Inconsistent rounding exploitable. SPL Lending $2.6B at risk from rounding direction attack.',
    recommendation: 'Always round in protocol\'s favor. Document rounding direction for each operation.'
  },
  {
    id: 'SOL4043',
    name: 'Integer Overflow Without Checked Math',
    severity: 'high',
    pattern: /(?:let|const)[\s\S]{0,30}(?:\+|\*|-|<<)[\s\S]{0,30}(?!checked_|saturating_|\.overflowing_)/i,
    description: 'Arithmetic without overflow protection. Rust release builds don\'t panic on overflow.',
    recommendation: 'Use checked_add, checked_mul, checked_sub. Or saturating_ variants.'
  },
  {
    id: 'SOL4044',
    name: 'Share Inflation / First Depositor Attack',
    severity: 'critical',
    pattern: /(?:shares|deposit)[\s\S]{0,100}(?:first|initial)[\s\S]{0,50}(?:mint|issue)[\s\S]{0,30}(?!minimum|dead_shares)/i,
    description: 'First depositor can inflate share price. Classic vault attack vector.',
    recommendation: 'Mint dead shares to zero address on initialization. Set minimum deposit amounts.'
  },
  {
    id: 'SOL4045',
    name: 'Balance Invariant Not Enforced',
    severity: 'high',
    pattern: /(?:balance|amount)[\s\S]{0,100}(?:transfer|move)[\s\S]{0,50}(?!invariant|assert_eq|verify_sum)/i,
    description: 'Balance conservation not verified. Enables hidden inflation or theft.',
    recommendation: 'Assert balance invariants: sum of debits = sum of credits in each operation.'
  },

  // ============================================================================
  // DENIAL OF SERVICE & LIVENESS (8.5% of Sec3 findings)
  // ============================================================================

  {
    id: 'SOL4046',
    name: 'Unbounded Iteration DoS',
    severity: 'high',
    pattern: /(?:for|while|loop)[\s\S]{0,80}(?:iter|range)[\s\S]{0,50}(?!bounded|limit|max|take\()/i,
    description: 'Unbounded loops cause compute exhaustion. Common DoS vector.',
    recommendation: 'Bound all iterations. Use pagination for large datasets.'
  },
  {
    id: 'SOL4047',
    name: 'Compute Budget Not Managed',
    severity: 'medium',
    pattern: /(?:instruction|handler)[\s\S]{0,100}(?!compute_budget|ComputeBudget)/i,
    description: 'No compute budget management. Complex operations may fail unpredictably.',
    recommendation: 'Request appropriate compute units. Add compute estimation.'
  },
  {
    id: 'SOL4048',
    name: 'Oracle Fallback Missing',
    severity: 'high',
    pattern: /(?:oracle|price_feed)[\s\S]{0,100}(?:fetch|get)[\s\S]{0,50}(?!fallback|backup|alternative)/i,
    description: 'No fallback when oracle fails. Protocol becomes unusable if oracle down.',
    recommendation: 'Implement oracle fallback chain. Consider last-good-price with staleness limit.'
  },
  {
    id: 'SOL4049',
    name: 'Account Reallocation DoS',
    severity: 'medium',
    pattern: /(?:realloc|resize)[\s\S]{0,80}(?:account|data)[\s\S]{0,50}(?!limit|max_size|bounded)/i,
    description: 'Unbounded reallocation enables rent griefing. Attacker can inflate rent costs.',
    recommendation: 'Set maximum account sizes. Bound reallocation per transaction.'
  },
  {
    id: 'SOL4050',
    name: 'Event Emission in Loop',
    severity: 'low',
    pattern: /(?:for|while|loop)[\s\S]{0,100}(?:emit|log|event)/i,
    description: 'Events emitted in loops waste compute. May cause transaction failure.',
    recommendation: 'Batch events or emit summary after loop completion.'
  },

  // ============================================================================
  // ADDITIONAL HIGH-IMPACT PATTERNS
  // ============================================================================

  {
    id: 'SOL4051',
    name: 'Remaining Accounts Unbounded',
    severity: 'high',
    pattern: /(?:remaining_accounts|ctx\.remaining)[\s\S]{0,80}(?:iter|for_each)[\s\S]{0,50}(?!bounded|limit|take)/i,
    description: 'Processing unbounded remaining accounts. Attacker can pass many accounts to exhaust compute.',
    recommendation: 'Limit number of remaining accounts processed. Add explicit bounds.'
  },
  {
    id: 'SOL4052',
    name: 'CPI Depth Exhaustion',
    severity: 'medium',
    pattern: /(?:invoke|cpi)[\s\S]{0,100}(?:depth|level)[\s\S]{0,50}(?!check|limit|max_depth)/i,
    description: 'Recursive CPI can exhaust call depth. Solana has 4-level CPI limit.',
    recommendation: 'Check CPI depth before invocation. Avoid deep CPI chains.'
  },
  {
    id: 'SOL4053',
    name: 'PDA Seed Collision Risk',
    severity: 'high',
    pattern: /(?:find_program_address|create_program_address)[\s\S]{0,100}(?:seed)[\s\S]{0,50}(?!unique|distinct|discriminator)/i,
    description: 'PDA seeds may collide across different account types. Enables account confusion.',
    recommendation: 'Include account type discriminator in PDA seeds. Ensure seed uniqueness.'
  },
  {
    id: 'SOL4054',
    name: 'Signer Seeds Not Validated',
    severity: 'critical',
    pattern: /(?:signer_seeds|seeds)[\s\S]{0,100}(?:invoke_signed)[\s\S]{0,50}(?!validate|verify|check)/i,
    description: 'Signer seeds passed without validation. May sign for wrong PDA.',
    recommendation: 'Validate PDA address matches expected before signing. Check all seed components.'
  },
  {
    id: 'SOL4055',
    name: 'Account Close Without Lamport Drain',
    severity: 'high',
    pattern: /(?:close|zero)[\s\S]{0,80}(?:account)[\s\S]{0,50}(?!lamports|rent)/i,
    description: 'Closing account without properly draining lamports. May leave dust or enable revival.',
    recommendation: 'Transfer all lamports before closing. Zero account data.'
  },

  // ============================================================================
  // BUSINESS LOGIC PATTERNS (38.5% of Sec3 findings - highest category)
  // ============================================================================

  {
    id: 'SOL4056',
    name: 'State Machine Skip',
    severity: 'high',
    pattern: /(?:state|status)[\s\S]{0,100}(?:transition|change)[\s\S]{0,50}(?!valid_from|allowed_states|sequential)/i,
    description: 'State transitions can skip required states. Enables bypassing required steps.',
    recommendation: 'Enforce sequential state transitions. Validate from-state for each transition.'
  },
  {
    id: 'SOL4057',
    name: 'Deadline Not Enforced',
    severity: 'high',
    pattern: /(?:deadline|expiry|valid_until)[\s\S]{0,100}(?!check|verify|require|assert)/i,
    description: 'Deadline specified but not enforced. Operations can execute after expiry.',
    recommendation: 'Always check timestamps against deadlines. Use Clock sysvar.'
  },
  {
    id: 'SOL4058',
    name: 'Fee Precision Loss',
    severity: 'medium',
    pattern: /(?:fee|commission)[\s\S]{0,80}(?:calculate|compute)[\s\S]{0,50}(?:\/|\bdiv\b)/i,
    description: 'Fee calculation loses precision to rounding. Small fees may round to zero.',
    recommendation: 'Use basis points (10000 = 100%). Calculate fees before division.'
  },
  {
    id: 'SOL4059',
    name: 'Reward Accumulation Drift',
    severity: 'high',
    pattern: /(?:reward|yield)[\s\S]{0,100}(?:accumulate|accrue)[\s\S]{0,50}(?!checkpoint|snapshot|per_share)/i,
    description: 'Reward calculations drift over time. Users may lose earned rewards.',
    recommendation: 'Use reward-per-share model. Update global state on each interaction.'
  },
  {
    id: 'SOL4060',
    name: 'Partial Fill Edge Case',
    severity: 'medium',
    pattern: /(?:order|fill)[\s\S]{0,100}(?:partial)[\s\S]{0,50}(?!minimum|dust|threshold)/i,
    description: 'Partial fills without minimum size. Dust orders waste compute and state.',
    recommendation: 'Enforce minimum fill sizes. Auto-complete orders below dust threshold.'
  },

  // ============================================================================
  // ACCESS CONTROL PATTERNS (19% of Sec3 findings)
  // ============================================================================

  {
    id: 'SOL4061',
    name: 'Role Hierarchy Not Enforced',
    severity: 'high',
    pattern: /(?:role|permission)[\s\S]{0,100}(?:admin|operator|user)[\s\S]{0,50}(?!hierarchy|inherit|include)/i,
    description: 'Role permissions not hierarchical. Lower roles may have unintended access.',
    recommendation: 'Implement proper role hierarchy. Higher roles inherit lower role permissions.'
  },
  {
    id: 'SOL4062',
    name: 'Emergency Mode Without Bounds',
    severity: 'high',
    pattern: /(?:emergency|paused)[\s\S]{0,100}(?:mode|state)[\s\S]{0,50}(?!timeout|expiry|auto_disable)/i,
    description: 'Emergency mode can be indefinite. May permanently lock user funds.',
    recommendation: 'Add timeout to emergency mode. Require governance to extend.'
  },
  {
    id: 'SOL4063',
    name: 'Ownership Transfer Immediate',
    severity: 'high',
    pattern: /(?:owner|authority)[\s\S]{0,100}(?:transfer|change)[\s\S]{0,50}(?!pending|accept|two_step)/i,
    description: 'Ownership transfers immediately. Compromised key instantly takes control.',
    recommendation: 'Implement two-step ownership transfer. New owner must accept.'
  },
  {
    id: 'SOL4064',
    name: 'CPI Privilege Escalation',
    severity: 'critical',
    pattern: /(?:cpi|invoke)[\s\S]{0,100}(?:signer)[\s\S]{0,50}(?!validate_caller|check_program)/i,
    description: 'CPI may escalate caller privileges. Callee trusts any signer.',
    recommendation: 'Validate CPI caller program. Don\'t trust signers from unknown programs.'
  },
  {
    id: 'SOL4065',
    name: 'Token Metadata Authority Spoof',
    severity: 'high',
    pattern: /(?:metadata|collection)[\s\S]{0,100}(?:authority|creator)[\s\S]{0,50}(?!verify|check_owner)/i,
    description: 'Metadata authority not verified. Fake metadata for legitimate collections.',
    recommendation: 'Verify metadata authority matches collection. Check creator verified flag.'
  },

  // ============================================================================
  // INPUT VALIDATION PATTERNS (25% of Sec3 findings)
  // ============================================================================

  {
    id: 'SOL4066',
    name: 'Pubkey Zero Check Missing',
    severity: 'high',
    pattern: /(?:Pubkey|address)[\s\S]{0,80}(?:param|input|arg)[\s\S]{0,50}(?!!=.*default|zero|system_program)/i,
    description: 'Pubkey not checked for zero/default. May accidentally use system program.',
    recommendation: 'Reject zero/default pubkeys for user-supplied addresses.'
  },
  {
    id: 'SOL4067',
    name: 'String Length DoS',
    severity: 'medium',
    pattern: /(?:String|str)[\s\S]{0,80}(?:len|length)[\s\S]{0,50}(?!max|limit|bounded)/i,
    description: 'String length unbounded. Long strings exhaust memory and compute.',
    recommendation: 'Enforce maximum string lengths. Validate before processing.'
  },
  {
    id: 'SOL4068',
    name: 'Array Index Without Bounds',
    severity: 'high',
    pattern: /\[[\s\S]{0,20}\][\s\S]{0,30}(?!get\(|\.get\(|bounded|checked)/i,
    description: 'Array access without bounds check. Panic on out-of-bounds access.',
    recommendation: 'Use .get() with proper error handling. Validate indices.'
  },
  {
    id: 'SOL4069',
    name: 'Timestamp Future Check Missing',
    severity: 'medium',
    pattern: /(?:timestamp|time)[\s\S]{0,80}(?:input|param)[\s\S]{0,50}(?!<=.*clock|future|max_time)/i,
    description: 'Timestamp not checked for future values. May break time-dependent logic.',
    recommendation: 'Reject timestamps too far in the future. Allow small clock drift tolerance.'
  },
  {
    id: 'SOL4070',
    name: 'Memo Injection Risk',
    severity: 'low',
    pattern: /(?:memo|note|message)[\s\S]{0,80}(?:bytes|data)[\s\S]{0,50}(?!sanitize|escape|validate)/i,
    description: 'Memo data not sanitized. May contain malicious content for display.',
    recommendation: 'Sanitize memo data for display. Limit length and character set.'
  },

  // ============================================================================
  // FINAL BATCH - COMPREHENSIVE SECURITY
  // ============================================================================

  {
    id: 'SOL4071',
    name: 'Versioned Transaction Confusion',
    severity: 'medium',
    pattern: /(?:transaction|tx)[\s\S]{0,80}(?:version)[\s\S]{0,50}(?!check|validate|expected)/i,
    description: 'Transaction version not validated. V0 vs legacy may have different behavior.',
    recommendation: 'Explicitly handle transaction versions. Validate expected version.'
  },
  {
    id: 'SOL4072',
    name: 'Durable Nonce Expiry Risk',
    severity: 'medium',
    pattern: /(?:durable_nonce|nonce)[\s\S]{0,100}(?:advance)[\s\S]{0,50}(?!expiry|timeout|max_age)/i,
    description: 'Durable nonces can be advanced to invalidate pending transactions.',
    recommendation: 'Monitor nonce advances. Implement transaction timeout checks.'
  },
  {
    id: 'SOL4073',
    name: 'Program Data Account Exposure',
    severity: 'medium',
    pattern: /(?:program_data|upgrade)[\s\S]{0,80}(?:account)[\s\S]{0,50}(?!restrict|protect)/i,
    description: 'Program data account may reveal deployment information.',
    recommendation: 'Restrict program data account access in sensitive contexts.'
  },
  {
    id: 'SOL4074',
    name: 'Syscall Security Validation',
    severity: 'high',
    pattern: /(?:syscall|sol_)[\s\S]{0,80}(?:invoke|call)[\s\S]{0,50}(?!validate|check|sanitize)/i,
    description: 'Syscall inputs not validated. May cause unexpected behavior.',
    recommendation: 'Validate all syscall parameters. Handle errors properly.'
  },
  {
    id: 'SOL4075',
    name: 'Cross-Program State Dependency',
    severity: 'medium',
    pattern: /(?:cpi|invoke)[\s\S]{0,100}(?:state|account)[\s\S]{0,50}(?:depend|require)[\s\S]{0,30}(?!refresh|reload)/i,
    description: 'Depending on external program state without refresh. State may be stale.',
    recommendation: 'Refresh external state within transaction. Don\'t cache cross-program data.'
  }
];

// Export all patterns as array
export const BATCH_79_PATTERNS = [...INSIDER_THREAT_PATTERNS];

// Pattern scanner function
export function scanBatch79(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  const lines = input.content.split('\n');

  for (const pattern of BATCH_79_PATTERNS) {
    // Search each line for matches
    for (let i = 0; i < lines.length; i++) {
      const line = lines[i];
      // Also check multi-line context (current + next 3 lines)
      const context = lines.slice(i, Math.min(i + 4, lines.length)).join('\n');
      
      if (pattern.pattern.test(context)) {
        findings.push({
          id: pattern.id,
          name: pattern.name,
          severity: pattern.severity,
          file: input.file,
          line: i + 1,
          column: 1,
          description: pattern.description,
          snippet: line.substring(0, 100),
          recommendation: pattern.recommendation
        });
        break; // One finding per pattern per file
      }
    }
  }

  return findings;
}

export default BATCH_79_PATTERNS;
