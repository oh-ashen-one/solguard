/**
 * SolGuard Batched Patterns 52 - SOL1931-SOL2000
 * Real-World Exploit Deep Dives + Advanced Attack Vectors
 * Added: Feb 5, 2026 1:30 PM CST
 * 
 * Sources: Helius Complete History, Sec3 2025, sannykim/solsec, arXiv
 */

import type { Finding } from '../commands/audit.js';
import type { PatternInput } from './index.js';

interface PatternDef {
  id: string;
  name: string;
  severity: 'critical' | 'high' | 'medium' | 'low' | 'info';
  pattern: RegExp;
  description: string;
  recommendation: string;
  cwe?: string;
  exploit?: string;
}

const PATTERNS: PatternDef[] = [
  // === WORMHOLE DEEP DIVE ($326M) ===
  {
    id: 'SOL1931',
    name: 'Wormhole-Style SignatureSet Spoofing',
    severity: 'critical',
    pattern: /signature_set[\s\S]{0,100}(?!verify_signatures|guardian_set_index)/i,
    description: 'Wormhole ($326M): SignatureSet account could be fabricated without proper guardian verification.',
    recommendation: 'Always verify SignatureSet was created by authorized program with valid guardian signatures.',
    cwe: 'CWE-287',
    exploit: 'Wormhole Feb 2022 - $326M'
  },
  {
    id: 'SOL1932',
    name: 'Guardian Signature Verification Bypass',
    severity: 'critical',
    pattern: /verify_signatures[\s\S]{0,100}(?!guardian_set|quorum|threshold)/i,
    description: 'Wormhole: Verify signatures must check guardian set membership and quorum.',
    recommendation: 'Verify: all signers are in current guardian set AND count >= quorum threshold.',
    cwe: 'CWE-287',
    exploit: 'Wormhole Feb 2022'
  },
  {
    id: 'SOL1933',
    name: 'VAA (Verified Action Approval) Missing Checks',
    severity: 'critical',
    pattern: /vaa[\s\S]{0,100}(process|execute|parse)(?![\s\S]{0,200}verify|[\s\S]{0,200}guardian)/i,
    description: 'Bridge VAA processing without full verification chain.',
    recommendation: 'Verify VAA: guardian signatures, emitter chain/address, sequence number, payload hash.',
    cwe: 'CWE-345',
    exploit: 'Wormhole Feb 2022'
  },

  // === MANGO MARKETS DEEP DIVE ($116M) ===
  {
    id: 'SOL1934',
    name: 'Mango-Style Self-Trading Attack',
    severity: 'critical',
    pattern: /order[\s\S]{0,100}(maker|taker)[\s\S]{0,100}(?!maker\s*!=\s*taker|self_trade)/i,
    description: 'Mango ($116M): Self-trading allowed attacker to manipulate mark price.',
    recommendation: 'Prevent self-trading: require!(order.maker != order.taker, SelfTradeNotAllowed)',
    cwe: 'CWE-284',
    exploit: 'Mango Markets Oct 2022 - $116M'
  },
  {
    id: 'SOL1935',
    name: 'Oracle Price Manipulation via Thin Liquidity',
    severity: 'critical',
    pattern: /mark_price[\s\S]{0,100}(?!twap|window|volume_weighted)/i,
    description: 'Mango: Mark price from spot market with thin liquidity enabled manipulation.',
    recommendation: 'Use TWAP or volume-weighted pricing for mark price, not instantaneous spot.',
    cwe: 'CWE-682',
    exploit: 'Mango Markets Oct 2022'
  },
  {
    id: 'SOL1936',
    name: 'Unrealized PnL as Collateral',
    severity: 'high',
    pattern: /unrealized[\s\S]{0,50}(pnl|profit)[\s\S]{0,100}collateral/i,
    description: 'Mango: Using unrealized PnL as collateral before settlement enables attacks.',
    recommendation: 'Only count realized/settled PnL towards collateral value.',
    cwe: 'CWE-682',
    exploit: 'Mango Markets Oct 2022'
  },
  {
    id: 'SOL1937',
    name: 'Position Size Without Market Depth Check',
    severity: 'high',
    pattern: /position[\s\S]{0,50}size(?![\s\S]{0,150}max_position|[\s\S]{0,150}open_interest|[\s\S]{0,150}liquidity)/i,
    description: 'Mango: Large positions without market depth limits enabled manipulation.',
    recommendation: 'Limit position size relative to available liquidity and open interest.',
    cwe: 'CWE-682',
    exploit: 'Mango Markets Oct 2022'
  },

  // === CASHIO DEEP DIVE ($52.8M) ===
  {
    id: 'SOL1938',
    name: 'Cashio-Style Root of Trust Missing',
    severity: 'critical',
    pattern: /collateral[\s\S]{0,100}mint(?![\s\S]{0,200}whitelist|[\s\S]{0,200}allowed_mints|[\s\S]{0,200}verify_mint)/i,
    description: 'Cashio ($52.8M): No root of trust validation - any account passed as collateral.',
    recommendation: 'Verify collateral mint is in explicit whitelist: require!(ALLOWED_MINTS.contains(&mint.key()))',
    cwe: 'CWE-346',
    exploit: 'Cashio Mar 2022 - $52.8M'
  },
  {
    id: 'SOL1939',
    name: 'Nested Account Chain Without Full Validation',
    severity: 'critical',
    pattern: /pool[\s\S]{0,50}lp[\s\S]{0,50}token(?![\s\S]{0,200}underlying|[\s\S]{0,200}reserve)/i,
    description: 'Cashio: LP token accepted without verifying underlying pool reserves.',
    recommendation: 'Validate entire chain: LP token → pool → underlying mints are all trusted.',
    cwe: 'CWE-346',
    exploit: 'Cashio Mar 2022'
  },
  {
    id: 'SOL1940',
    name: 'Infinite Mint Through Fake Collateral',
    severity: 'critical',
    pattern: /mint_to[\s\S]{0,100}collateral[\s\S]{0,100}(?!verify|whitelist|check_mint)/i,
    description: 'Cashio: Minting stablecoins against unverified collateral enabled infinite mint.',
    recommendation: 'Gate all minting on verified collateral: require!(is_valid_collateral(&mint.key()))',
    cwe: 'CWE-284',
    exploit: 'Cashio Mar 2022'
  },

  // === CREMA FINANCE DEEP DIVE ($8.8M) ===
  {
    id: 'SOL1941',
    name: 'Crema-Style Fake Tick Account',
    severity: 'critical',
    pattern: /tick[\s\S]{0,50}account(?![\s\S]{0,150}owner\s*==|[\s\S]{0,150}seeds|[\s\S]{0,150}pda)/i,
    description: 'Crema ($8.8M): Attacker created fake tick account with manipulated fee data.',
    recommendation: 'Verify tick accounts: owner == program_id AND seeds match expected derivation.',
    cwe: 'CWE-346',
    exploit: 'Crema Finance Jul 2022 - $8.8M'
  },
  {
    id: 'SOL1942',
    name: 'Fee Accumulator Manipulation',
    severity: 'high',
    pattern: /fee[\s\S]{0,50}(accumulator|growth|accrued)(?![\s\S]{0,150}verify|[\s\S]{0,150}owner_check)/i,
    description: 'Crema: Fee growth data in tick accounts was manipulated through spoofed accounts.',
    recommendation: 'All fee data accounts must be program-owned PDAs with verified seeds.',
    cwe: 'CWE-682',
    exploit: 'Crema Finance Jul 2022'
  },
  {
    id: 'SOL1943',
    name: 'Flash Loan Fee Claim',
    severity: 'high',
    pattern: /claim[\s\S]{0,50}fee[\s\S]{0,100}flash(?![\s\S]{0,150}repay|[\s\S]{0,150}callback)/i,
    description: 'Crema: Flash loan used to inflate position before claiming accumulated fees.',
    recommendation: 'Track position duration or use time-weighted averages for fee claims.',
    cwe: 'CWE-362',
    exploit: 'Crema Finance Jul 2022'
  },

  // === SLOPE WALLET DEEP DIVE ($8M) ===
  {
    id: 'SOL1944',
    name: 'Slope-Style Seed Phrase Logging',
    severity: 'critical',
    pattern: /(mnemonic|seed_phrase|secret_key)[\s\S]{0,50}(log|send|post|http)/i,
    description: 'Slope ($8M): Seed phrases sent to centralized logging server.',
    recommendation: 'NEVER log, transmit, or store seed phrases/private keys outside secure enclaves.',
    cwe: 'CWE-532',
    exploit: 'Slope Wallet Aug 2022 - $8M'
  },
  {
    id: 'SOL1945',
    name: 'Unencrypted Key Storage',
    severity: 'critical',
    pattern: /private_key[\s\S]{0,30}=[\s\S]{0,20}(store|save|write)(?![\s\S]{0,100}encrypt)/i,
    description: 'Slope: Private keys stored without encryption enabled mass theft.',
    recommendation: 'Always encrypt private keys at rest with user-derived key.',
    cwe: 'CWE-311',
    exploit: 'Slope Wallet Aug 2022'
  },
  {
    id: 'SOL1946',
    name: 'Telemetry Including Sensitive Data',
    severity: 'high',
    pattern: /telemetry[\s\S]{0,100}(key|secret|password|mnemonic)/i,
    description: 'Slope: Telemetry/analytics captured sensitive wallet data.',
    recommendation: 'Audit all telemetry to ensure no sensitive data is collected.',
    cwe: 'CWE-532',
    exploit: 'Slope Wallet Aug 2022'
  },

  // === NIRVANA FINANCE DEEP DIVE ($3.5M) ===
  {
    id: 'SOL1947',
    name: 'Nirvana-Style Bonding Curve Flash Loan',
    severity: 'critical',
    pattern: /bonding_curve[\s\S]{0,100}(price|mint)(?![\s\S]{0,200}flash_loan_guard|[\s\S]{0,200}same_block)/i,
    description: 'Nirvana ($3.5M): Flash loan manipulated bonding curve to mint at manipulated price.',
    recommendation: 'Add flash loan protection: track last modification block and add cooldown.',
    cwe: 'CWE-362',
    exploit: 'Nirvana Finance Jul 2022 - $3.5M'
  },
  {
    id: 'SOL1948',
    name: 'Instant Price Impact Without Cooldown',
    severity: 'high',
    pattern: /price[\s\S]{0,50}=[\s\S]{0,50}(reserve|supply)(?![\s\S]{0,150}twap|[\s\S]{0,150}smooth)/i,
    description: 'Nirvana: Instantaneous price from reserves enabled single-block manipulation.',
    recommendation: 'Use time-weighted or smoothed pricing for bonding curves.',
    cwe: 'CWE-682',
    exploit: 'Nirvana Finance Jul 2022'
  },

  // === RAYDIUM DEEP DIVE ($4.4M) ===
  {
    id: 'SOL1949',
    name: 'Raydium-Style Admin Key Compromise',
    severity: 'critical',
    pattern: /admin[\s\S]{0,50}key[\s\S]{0,50}(withdraw|transfer)(?![\s\S]{0,200}multisig|[\s\S]{0,200}timelock)/i,
    description: 'Raydium ($4.4M): Single admin key compromise enabled pool draining.',
    recommendation: 'Use multisig for admin operations with timelock for withdrawals.',
    cwe: 'CWE-287',
    exploit: 'Raydium Dec 2022 - $4.4M'
  },
  {
    id: 'SOL1950',
    name: 'Trojan Horse Upgrade Authority',
    severity: 'critical',
    pattern: /upgrade[\s\S]{0,50}authority(?![\s\S]{0,150}multisig|[\s\S]{0,150}dao|[\s\S]{0,150}immutable)/i,
    description: 'Raydium: Compromised upgrade authority pushed malicious program update.',
    recommendation: 'Use DAO-controlled upgrade authority with timelock, or make immutable.',
    cwe: 'CWE-287',
    exploit: 'Raydium Dec 2022'
  },

  // === DEXX DEEP DIVE ($30M) ===
  {
    id: 'SOL1951',
    name: 'DEXX-Style Hot Wallet Exposure',
    severity: 'critical',
    pattern: /hot_wallet[\s\S]{0,50}(private|key|secret)(?![\s\S]{0,100}hsm|[\s\S]{0,100}enclave)/i,
    description: 'DEXX ($30M): Hot wallet private keys exposed through server compromise.',
    recommendation: 'Use HSM or secure enclave for hot wallet keys. Implement MPC where possible.',
    cwe: 'CWE-522',
    exploit: 'DEXX Nov 2024 - $30M'
  },
  {
    id: 'SOL1952',
    name: 'Centralized Custody Without Limits',
    severity: 'critical',
    pattern: /custody[\s\S]{0,100}(deposit|withdraw)(?![\s\S]{0,200}limit|[\s\S]{0,200}rate_limit|[\s\S]{0,200}threshold)/i,
    description: 'DEXX: No withdrawal limits on centralized custody enabled full drain.',
    recommendation: 'Implement tiered withdrawal limits and anomaly detection.',
    cwe: 'CWE-770',
    exploit: 'DEXX Nov 2024'
  },
  {
    id: 'SOL1953',
    name: 'Commingled User Funds',
    severity: 'high',
    pattern: /pool[\s\S]{0,50}(deposit|user)[\s\S]{0,100}(?!isolated|segregated|separate)/i,
    description: 'DEXX: User funds commingled in single hot wallet increased blast radius.',
    recommendation: 'Segregate user funds into individual accounts or use merkle-based accounting.',
    cwe: 'CWE-284',
    exploit: 'DEXX Nov 2024'
  },

  // === LOOPSCALE/RATEX DEEP DIVE ($5.8M) ===
  {
    id: 'SOL1954',
    name: 'Loopscale-Style PT Token Pricing Flaw',
    severity: 'critical',
    pattern: /pt[\s\S]{0,30}(token|price)[\s\S]{0,100}(?!maturity|discount|yield)/i,
    description: 'Loopscale ($5.8M): Principal Token pricing function had critical flaw.',
    recommendation: 'PT token price must account for time to maturity and yield curve.',
    cwe: 'CWE-682',
    exploit: 'Loopscale Apr 2025 - $5.8M'
  },
  {
    id: 'SOL1955',
    name: 'Undercollateralization Check Bypass',
    severity: 'critical',
    pattern: /collateral[\s\S]{0,100}(ratio|factor)[\s\S]{0,100}(?!require!|assert!|check)/i,
    description: 'Loopscale: Collateralization checks bypassed through pricing manipulation.',
    recommendation: 'Always verify: require!(collateral_value >= debt_value * MIN_COLLATERAL_RATIO)',
    cwe: 'CWE-682',
    exploit: 'Loopscale Apr 2025'
  },

  // === PUMP.FUN DEEP DIVE ($1.9M) ===
  {
    id: 'SOL1956',
    name: 'Pump.fun-Style Insider Wallet Access',
    severity: 'critical',
    pattern: /privileged[\s\S]{0,50}wallet[\s\S]{0,100}(?!multisig|audit|monitoring)/i,
    description: 'Pump.fun ($1.9M): Employee with privileged wallet access exploited the protocol.',
    recommendation: 'Use multisig for privileged operations, implement audit logging and monitoring.',
    cwe: 'CWE-269',
    exploit: 'Pump.fun May 2024 - $1.9M'
  },
  {
    id: 'SOL1957',
    name: 'Bonding Curve Migration Flash Loan',
    severity: 'high',
    pattern: /migration[\s\S]{0,100}(bonding|curve|raydium)(?![\s\S]{0,200}flash_guard|[\s\S]{0,200}delay)/i,
    description: 'Pump.fun: Flash loan during migration to Raydium enabled profit extraction.',
    recommendation: 'Add migration delay and flash loan protection during curve transitions.',
    cwe: 'CWE-362',
    exploit: 'Pump.fun May 2024'
  },

  // === AUDIUS DEEP DIVE ($6.1M) ===
  {
    id: 'SOL1958',
    name: 'Audius-Style Governance Proposal Hijack',
    severity: 'critical',
    pattern: /governance[\s\S]{0,100}proposal[\s\S]{0,100}(?!guardian|admin_override|veto)/i,
    description: 'Audius ($6.1M): Malicious governance proposal passed without adequate oversight.',
    recommendation: 'Implement guardian/admin veto power for proposals and extended review periods.',
    cwe: 'CWE-862',
    exploit: 'Audius Jul 2022 - $6.1M'
  },
  {
    id: 'SOL1959',
    name: 'Treasury Permission Reconfiguration',
    severity: 'critical',
    pattern: /treasury[\s\S]{0,100}(permission|authority|config)[\s\S]{0,100}(?!timelock|multisig)/i,
    description: 'Audius: Governance proposal changed treasury permissions to drain funds.',
    recommendation: 'Treasury configuration changes require extended timelock (7+ days) and multisig.',
    cwe: 'CWE-285',
    exploit: 'Audius Jul 2022'
  },

  // === CYPHER PROTOCOL DEEP DIVE ($1.35M) ===
  {
    id: 'SOL1960',
    name: 'Cypher-Style Sub-Account Isolation Failure',
    severity: 'critical',
    pattern: /sub[\s\S]{0,30}account[\s\S]{0,100}(?!isolat|separate|independent)/i,
    description: 'Cypher ($1.35M): Sub-account isolation failed allowing cross-contamination.',
    recommendation: 'Ensure sub-accounts are truly isolated with independent authority checks.',
    cwe: 'CWE-653',
    exploit: 'Cypher Protocol Aug 2023 - $1.35M'
  },
  {
    id: 'SOL1961',
    name: 'Internal Bad Actor Without Audit',
    severity: 'high',
    pattern: /team[\s\S]{0,50}(wallet|key|access)(?![\s\S]{0,150}audit|[\s\S]{0,150}monitor|[\s\S]{0,150}log)/i,
    description: 'Cypher: Internal team member exploited access without audit trail.',
    recommendation: 'Implement comprehensive audit logging for all privileged operations.',
    cwe: 'CWE-778',
    exploit: 'Cypher Protocol Aug 2023'
  },

  // === WEB3.JS SUPPLY CHAIN ($164K) ===
  {
    id: 'SOL1962',
    name: 'Web3.js-Style NPM Package Compromise',
    severity: 'critical',
    pattern: /@solana\/web3\.js[\s\S]{0,30}(1\.95\.4|1\.95\.5|1\.95\.6)/,
    description: 'Web3.js ($164K): Compromised NPM versions exfiltrated private keys.',
    recommendation: 'Pin dependencies to known-good versions, use lockfiles, verify checksums.',
    cwe: 'CWE-494',
    exploit: 'Web3.js Dec 2024 - $164K'
  },
  {
    id: 'SOL1963',
    name: 'Dependency Key Exfiltration',
    severity: 'critical',
    pattern: /(require|import)[\s\S]{0,100}(private_key|secret_key)[\s\S]{0,50}(fetch|http|socket)/i,
    description: 'Web3.js: Malicious dependency sent keys to attacker server.',
    recommendation: 'Audit all dependencies, use npm audit, and implement egress controls.',
    cwe: 'CWE-506',
    exploit: 'Web3.js Dec 2024'
  },

  // === IO.NET SYBIL ATTACK ===
  {
    id: 'SOL1964',
    name: 'io.net-Style GPU Sybil Detection',
    severity: 'high',
    pattern: /(gpu|compute|worker)[\s\S]{0,50}(register|verify)(?![\s\S]{0,200}proof_of_work|[\s\S]{0,200}stake)/i,
    description: 'io.net: Fake GPU registrations inflated network capacity.',
    recommendation: 'Require proof of computational work or stake for resource registration.',
    cwe: 'CWE-346',
    exploit: 'io.net Sybil 2024'
  },
  {
    id: 'SOL1965',
    name: 'Resource Spoofing Without Verification',
    severity: 'medium',
    pattern: /(capacity|resource|hardware)[\s\S]{0,50}report(?![\s\S]{0,150}verify|[\s\S]{0,150}attest|[\s\S]{0,150}proof)/i,
    description: 'io.net: Self-reported resources without on-chain verification.',
    recommendation: 'Implement cryptographic attestation or on-chain verification for reported resources.',
    cwe: 'CWE-346',
    exploit: 'io.net Sybil 2024'
  },

  // === BANANA GUN ($1.4M) ===
  {
    id: 'SOL1966',
    name: 'Banana Gun-Style Bot Backend Exposure',
    severity: 'critical',
    pattern: /(bot|backend)[\s\S]{0,50}(key|secret)[\s\S]{0,50}(api|endpoint)/i,
    description: 'Banana Gun ($1.4M): Trading bot backend keys exposed through infrastructure attack.',
    recommendation: 'Use rotating API keys, implement IP allowlists, and monitor for anomalies.',
    cwe: 'CWE-522',
    exploit: 'Banana Gun Sep 2024 - $1.4M'
  },
  {
    id: 'SOL1967',
    name: 'Trading Bot Oracle Manipulation',
    severity: 'high',
    pattern: /trading[\s\S]{0,50}bot[\s\S]{0,100}(price|oracle)(?![\s\S]{0,150}verify|[\s\S]{0,150}twap)/i,
    description: 'Banana Gun: Bots susceptible to oracle manipulation attacks.',
    recommendation: 'Use multiple price sources and implement sanity checks in trading bots.',
    cwe: 'CWE-346',
    exploit: 'Banana Gun Sep 2024'
  },

  // === ADDITIONAL REAL EXPLOITS ===
  {
    id: 'SOL1968',
    name: 'OptiFi-Style Program Close with Funds',
    severity: 'critical',
    pattern: /close[\s\S]{0,50}program(?![\s\S]{0,200}withdraw|[\s\S]{0,200}transfer|[\s\S]{0,200}empty)/i,
    description: 'OptiFi ($661K): Program closed with user funds still locked.',
    recommendation: 'Ensure all funds are withdrawn before program close operations.',
    cwe: 'CWE-404',
    exploit: 'OptiFi Aug 2022 - $661K'
  },
  {
    id: 'SOL1969',
    name: 'Thunder Terminal MongoDB Injection',
    severity: 'critical',
    pattern: /mongodb[\s\S]{0,100}(query|find|update)[\s\S]{0,50}\$(?![\s\S]{0,50}sanitize)/i,
    description: 'Thunder Terminal ($240K): MongoDB injection enabled fund theft.',
    recommendation: 'Sanitize all database inputs and use parameterized queries.',
    cwe: 'CWE-943',
    exploit: 'Thunder Terminal Dec 2023 - $240K'
  },
  {
    id: 'SOL1970',
    name: 'Solareum Bot Payment Exploit',
    severity: 'high',
    pattern: /payment[\s\S]{0,50}bot[\s\S]{0,100}(?!verify|signature|confirm)/i,
    description: 'Solareum ($500K+): Bot payment verification bypassed.',
    recommendation: 'Always verify payment transactions before crediting user accounts.',
    cwe: 'CWE-284',
    exploit: 'Solareum 2023 - $500K+'
  },

  // === ADDITIONAL SECURITY PATTERNS ===
  {
    id: 'SOL1971',
    name: 'Saga DAO Governance Attack',
    severity: 'high',
    pattern: /dao[\s\S]{0,50}vote[\s\S]{0,100}(?!snapshot|lock|checkpoint)/i,
    description: 'Saga DAO ($230K): Flash-borrowed tokens used for governance vote.',
    recommendation: 'Use snapshot-based voting power, not live token balances.',
    cwe: 'CWE-362',
    exploit: 'Saga DAO Oct 2023 - $230K'
  },
  {
    id: 'SOL1972',
    name: 'Tulip Protocol Crank Manipulation',
    severity: 'high',
    pattern: /crank[\s\S]{0,50}(call|invoke)(?![\s\S]{0,150}rate_limit|[\s\S]{0,150}interval)/i,
    description: 'Tulip: Crank functions called with malicious timing.',
    recommendation: 'Implement rate limits and interval checks for crank operations.',
    cwe: 'CWE-362',
    exploit: 'Tulip Protocol 2022'
  },
  {
    id: 'SOL1973',
    name: 'UXD Protocol Stability Mechanism Flaw',
    severity: 'high',
    pattern: /stability[\s\S]{0,50}(module|mechanism)[\s\S]{0,100}(?!cap|limit|ceiling)/i,
    description: 'UXD ($20M at risk): Stability mechanism had unbounded exposure.',
    recommendation: 'Cap stability mechanism exposure and implement circuit breakers.',
    cwe: 'CWE-770',
    exploit: 'UXD Protocol 2022'
  },
  {
    id: 'SOL1974',
    name: 'Parcl Frontend Phishing',
    severity: 'medium',
    pattern: /frontend[\s\S]{0,50}(url|domain)(?![\s\S]{0,100}verify|[\s\S]{0,100}pin)/i,
    description: 'Parcl: Frontend compromised for phishing attack.',
    recommendation: 'Implement frontend integrity checks and subresource integrity (SRI).',
    cwe: 'CWE-494',
    exploit: 'Parcl 2024'
  },
  {
    id: 'SOL1975',
    name: 'Jito DDoS Vulnerability',
    severity: 'medium',
    pattern: /jito[\s\S]{0,50}bundle(?![\s\S]{0,150}validate|[\s\S]{0,150}filter)/i,
    description: 'Jito: Bundle spam could cause denial of service.',
    recommendation: 'Implement bundle validation and rate limiting.',
    cwe: 'CWE-400',
    exploit: 'Jito DDoS 2024'
  },
  {
    id: 'SOL1976',
    name: 'Phantom Wallet Spam/DDoS',
    severity: 'low',
    pattern: /wallet[\s\S]{0,50}spam[\s\S]{0,50}(?!filter|block)/i,
    description: 'Phantom: Wallet spam transactions caused performance issues.',
    recommendation: 'Implement transaction filtering and spam detection.',
    cwe: 'CWE-400',
    exploit: 'Phantom 2023'
  },
  {
    id: 'SOL1977',
    name: 'Candy Machine Zero-Account DoS',
    severity: 'medium',
    pattern: /candy[\s\S]{0,50}machine[\s\S]{0,100}(?!whitelist|limit|cap)/i,
    description: 'Candy Machine: Bots could exhaust mints leaving zero for legitimate users.',
    recommendation: 'Implement bot protection: allowlist, CAPTCHA, or gradual release.',
    cwe: 'CWE-400',
    exploit: 'Candy Machine 2022'
  },
  {
    id: 'SOL1978',
    name: 'Grape Protocol Network DoS',
    severity: 'medium',
    pattern: /grape[\s\S]{0,50}(protocol|network)[\s\S]{0,50}(?!rate_limit)/i,
    description: 'Grape: Network could be DoSed through spam.',
    recommendation: 'Implement rate limiting and proof-of-work for network operations.',
    cwe: 'CWE-400',
    exploit: 'Grape Protocol 2022'
  },

  // === ADVANCED ATTACK VECTORS ===
  {
    id: 'SOL1979',
    name: 'Just-In-Time Liquidity Attack',
    severity: 'high',
    pattern: /liquidity[\s\S]{0,50}add[\s\S]{0,100}(?!lock|cooldown|delay)/i,
    description: 'JIT liquidity added moments before large swap to extract value.',
    recommendation: 'Implement liquidity addition cooldowns or use time-weighted LP shares.',
    cwe: 'CWE-362'
  },
  {
    id: 'SOL1980',
    name: 'Order Flow Auction Manipulation',
    severity: 'medium',
    pattern: /order[\s\S]{0,50}flow[\s\S]{0,50}auction(?![\s\S]{0,150}fair|[\s\S]{0,150}random)/i,
    description: 'Order flow auctions can be gamed without fairness mechanisms.',
    recommendation: 'Use fair ordering (FCFS, random, or encrypted) for order flow auctions.',
    cwe: 'CWE-330'
  },
  {
    id: 'SOL1981',
    name: 'MEV Boost Relay Manipulation',
    severity: 'medium',
    pattern: /mev[\s\S]{0,50}(boost|relay)(?![\s\S]{0,150}verify|[\s\S]{0,150}trusted)/i,
    description: 'MEV relays can be manipulated to censor or reorder transactions.',
    recommendation: 'Use trusted MEV relays with reputation systems.',
    cwe: 'CWE-346'
  },
  {
    id: 'SOL1982',
    name: 'Sequencer Centralization Risk',
    severity: 'high',
    pattern: /sequencer[\s\S]{0,100}(?!decentralized|multiple|backup)/i,
    description: 'Single sequencer creates censorship and liveness risks.',
    recommendation: 'Use decentralized sequencer network or implement fallback mechanisms.',
    cwe: 'CWE-284'
  },
  {
    id: 'SOL1983',
    name: 'Time-Bandit Attack Vector',
    severity: 'high',
    pattern: /reorg[\s\S]{0,50}(attack|profit)(?![\s\S]{0,150}finality|[\s\S]{0,150}confirm)/i,
    description: 'Large value transactions could incentivize chain reorganization.',
    recommendation: 'Wait for finality before processing high-value withdrawals.',
    cwe: 'CWE-362'
  },
  {
    id: 'SOL1984',
    name: 'Proposer-Builder Separation Exploitation',
    severity: 'medium',
    pattern: /builder[\s\S]{0,50}(block|bundle)(?![\s\S]{0,150}verify|[\s\S]{0,150}commit)/i,
    description: 'PBS can be exploited for MEV extraction or censorship.',
    recommendation: 'Implement builder reputation and use encrypted mempools.',
    cwe: 'CWE-284'
  },
  
  // === PROTOCOL-SPECIFIC DEEP PATTERNS ===
  {
    id: 'SOL1985',
    name: 'Pyth Confidence Band Exploitation',
    severity: 'high',
    pattern: /pyth[\s\S]{0,100}price(?![\s\S]{0,200}confidence|[\s\S]{0,200}conf)/i,
    description: 'Pyth prices without confidence band checks can be exploited.',
    recommendation: 'Always check: require!(price.confidence < price.price * MAX_CONFIDENCE_RATIO)',
    cwe: 'CWE-754'
  },
  {
    id: 'SOL1986',
    name: 'Switchboard Staleness Attack',
    severity: 'high',
    pattern: /switchboard[\s\S]{0,100}(feed|oracle)(?![\s\S]{0,200}staleness|[\s\S]{0,200}timestamp)/i,
    description: 'Switchboard feeds without staleness check can be outdated.',
    recommendation: 'Verify: require!(clock.unix_timestamp - feed.timestamp < MAX_STALENESS)',
    cwe: 'CWE-613'
  },
  {
    id: 'SOL1987',
    name: 'Marinade Stake Ticket Manipulation',
    severity: 'high',
    pattern: /marinade[\s\S]{0,100}ticket(?![\s\S]{0,200}verify|[\s\S]{0,200}owner)/i,
    description: 'Marinade stake tickets need ownership and validity verification.',
    recommendation: 'Verify ticket ownership and epoch validity before processing.',
    cwe: 'CWE-346'
  },
  {
    id: 'SOL1988',
    name: 'Jupiter Route Manipulation',
    severity: 'high',
    pattern: /jupiter[\s\S]{0,100}route(?![\s\S]{0,200}verify|[\s\S]{0,200}slippage)/i,
    description: 'Jupiter routes can be manipulated for worse execution.',
    recommendation: 'Always enforce slippage limits and verify route authenticity.',
    cwe: 'CWE-346'
  },
  {
    id: 'SOL1989',
    name: 'cNFT Merkle Proof Manipulation',
    severity: 'high',
    pattern: /cnft[\s\S]{0,100}(proof|merkle)(?![\s\S]{0,200}verify|[\s\S]{0,200}validate)/i,
    description: 'Compressed NFT merkle proofs need proper validation.',
    recommendation: 'Use Bubblegum verify_leaf or equivalent for all cNFT operations.',
    cwe: 'CWE-345'
  },
  {
    id: 'SOL1990',
    name: 'Drift Protocol Funding Rate Manipulation',
    severity: 'high',
    pattern: /funding[\s\S]{0,50}rate(?![\s\S]{0,200}cap|[\s\S]{0,200}limit|[\s\S]{0,200}max)/i,
    description: 'Uncapped funding rates can be manipulated to extreme values.',
    recommendation: 'Cap funding rates: funding_rate = funding_rate.max(-MAX_RATE).min(MAX_RATE)',
    cwe: 'CWE-682'
  },

  // === FINAL PATTERNS ===
  {
    id: 'SOL1991',
    name: 'Solend Reserve Config Bypass',
    severity: 'critical',
    pattern: /reserve[\s\S]{0,50}config[\s\S]{0,100}update(?![\s\S]{0,200}authority|[\s\S]{0,200}owner)/i,
    description: 'Solend ($1M+ at risk): Reserve config updates need proper authority verification.',
    recommendation: 'Verify: require!(signer.key() == reserve.lending_market_owner)',
    cwe: 'CWE-863'
  },
  {
    id: 'SOL1992',
    name: 'Port Finance Max Withdraw Bug',
    severity: 'high',
    pattern: /max[\s\S]{0,30}withdraw[\s\S]{0,100}(?!ceil|round_up|checked)/i,
    description: 'Port: Max withdraw calculation had rounding bug.',
    recommendation: 'Use ceiling division for max withdraw: (amount + divisor - 1) / divisor',
    cwe: 'CWE-682'
  },
  {
    id: 'SOL1993',
    name: 'Jet Governance Vote Manipulation',
    severity: 'high',
    pattern: /jet[\s\S]{0,50}governance[\s\S]{0,50}vote(?![\s\S]{0,200}snapshot)/i,
    description: 'Jet: Governance votes without snapshotting could be manipulated.',
    recommendation: 'Snapshot voting power at proposal creation time.',
    cwe: 'CWE-362'
  },
  {
    id: 'SOL1994',
    name: 'Stake Pool Semantic Inconsistency',
    severity: 'high',
    pattern: /stake[\s\S]{0,50}pool[\s\S]{0,100}(?!consistent|atomic|verify)/i,
    description: 'Sec3: Stake pool semantic inconsistency discovered through x-ray analysis.',
    recommendation: 'Ensure atomic state updates and verify consistency after operations.',
    cwe: 'CWE-682'
  },
  {
    id: 'SOL1995',
    name: 'Token Approval Revocation Missing',
    severity: 'medium',
    pattern: /approve[\s\S]{0,100}delegate(?![\s\S]{0,200}revoke|[\s\S]{0,200}zero)/i,
    description: 'Token approvals without revocation mechanism pose risk.',
    recommendation: 'Implement revoke functionality: set delegate amount to 0 after use.',
    cwe: 'CWE-863'
  },
  {
    id: 'SOL1996',
    name: 'Cope Roulette Revert Exploit',
    severity: 'medium',
    pattern: /revert[\s\S]{0,50}(random|chance)(?![\s\S]{0,150}commitment)/i,
    description: 'Cope Roulette: Transactions could be reverted on unfavorable outcomes.',
    recommendation: 'Use commit-reveal scheme for randomness-dependent operations.',
    cwe: 'CWE-330'
  },
  {
    id: 'SOL1997',
    name: 'Simulation Detection Bypass',
    severity: 'medium',
    pattern: /simulation[\s\S]{0,50}(detect|check)(?![\s\S]{0,150}bank|[\s\S]{0,150}slot)/i,
    description: 'Some programs detect simulation to behave differently.',
    recommendation: 'Be aware that simulation detection can be bypassed; don\'t rely on it.',
    cwe: 'CWE-330'
  },
  {
    id: 'SOL1998',
    name: 'Authority Delegation Chain Vulnerability',
    severity: 'high',
    pattern: /delegate[\s\S]{0,50}authority[\s\S]{0,100}(?!verify_chain|verify_all)/i,
    description: 'Chained authority delegations can be exploited if not fully verified.',
    recommendation: 'Verify complete delegation chain back to original authority.',
    cwe: 'CWE-287'
  },
  {
    id: 'SOL1999',
    name: 'Cross-Protocol Cascade Risk',
    severity: 'high',
    pattern: /cross[\s\S]{0,30}protocol[\s\S]{0,100}(?!isolation|independent)/i,
    description: 'Tulip ($2.5M): Issues in one protocol cascaded to dependent protocols.',
    recommendation: 'Implement protocol isolation and independent state verification.',
    cwe: 'CWE-1060',
    exploit: 'Tulip Cross-Protocol 2022 - $2.5M'
  },
  {
    id: 'SOL2000',
    name: 'Neodyme SPL Lending Rounding Attack',
    severity: 'critical',
    pattern: /lending[\s\S]{0,50}(interest|rate)[\s\S]{0,100}(?!round_down|floor|ceil)/i,
    description: 'Neodyme ($2.6B at risk): Innocent-looking rounding error in SPL lending.',
    recommendation: 'Use explicit floor/ceil for all lending calculations. Review Neodyme disclosure.',
    cwe: 'CWE-682',
    exploit: 'Neodyme SPL Lending 2022 - $2.6B at risk'
  },
];

export function runBatch52Patterns(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  const content = input.rust?.content || '';
  
  if (!content) return findings;
  
  const lines = content.split('\n');
  
  for (const pattern of PATTERNS) {
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
          location: { file: input.path, line: lineNum },
          suggestion: pattern.recommendation,
          cwe: pattern.cwe,
          code: snippet.substring(0, 200),
        });
      }
    } catch (e) {
      // Skip on regex error
    }
  }
  
  return findings;
}

export const BATCH_52_COUNT = PATTERNS.length;
export { PATTERNS as BATCH_52_PATTERNS };
