import { VulnerabilityPattern } from '../types';

/**
 * Batch 54: Emerging Threats 2025-2026
 * SOL7476-SOL7525 (50 patterns)
 * Focus: AI agents, MEV, new attack vectors, cross-chain
 */
export const emergingThreatsPatterns: VulnerabilityPattern[] = [
  // AI Agent Security
  {
    id: 'SOL7476',
    name: 'AI Agent Wallet Autonomy',
    description: 'AI agent with autonomous wallet control without human oversight',
    severity: 'high',
    category: 'ai-agent',
    pattern: /agent.*wallet|autonomous.*transfer|ai.*sign/gi,
    recommendation: 'Implement human-in-the-loop controls for AI agent transactions'
  },
  {
    id: 'SOL7477',
    name: 'Agent Credential Exposure',
    description: 'AI agent credentials stored insecurely',
    severity: 'critical',
    category: 'ai-agent',
    pattern: /agent.*key|bot.*secret|automation.*credential/gi,
    recommendation: 'Use hardware security modules or secure enclaves for agent credentials'
  },
  {
    id: 'SOL7478',
    name: 'Agent Rate Limiting Missing',
    description: 'AI agent actions not rate limited',
    severity: 'high',
    category: 'ai-agent',
    pattern: /agent.*action(?!.*rate)|bot.*execute(?!.*limit)/gi,
    recommendation: 'Implement rate limiting for all agent-initiated actions'
  },
  {
    id: 'SOL7479',
    name: 'Agent Permission Scope',
    description: 'AI agent has overly broad permissions',
    severity: 'high',
    category: 'ai-agent',
    pattern: /agent.*full.*access|bot.*admin|automation.*owner/gi,
    recommendation: 'Apply principle of least privilege to agent permissions'
  },
  {
    id: 'SOL7480',
    name: 'Agent Transaction Limits',
    description: 'AI agent can execute unlimited value transactions',
    severity: 'critical',
    category: 'ai-agent',
    pattern: /agent.*transfer(?!.*limit)|bot.*withdraw(?!.*cap)/gi,
    recommendation: 'Implement per-transaction and daily limits for agent operations'
  },

  // MEV and Frontrunning (2025-2026)
  {
    id: 'SOL7481',
    name: 'Jito Bundle Manipulation',
    description: 'Transaction vulnerable to Jito bundle manipulation',
    severity: 'high',
    category: 'mev',
    pattern: /jito|bundle.*transaction|searcher/gi,
    recommendation: 'Consider private transaction submission or MEV protection'
  },
  {
    id: 'SOL7482',
    name: 'Priority Fee Exploitation',
    description: 'Transaction ordering exploitable via priority fees',
    severity: 'medium',
    category: 'mev',
    pattern: /priority.*fee|compute.*unit.*price|fee.*bump/gi,
    recommendation: 'Design for fee competition resilience'
  },
  {
    id: 'SOL7483',
    name: 'Liquidation MEV',
    description: 'Liquidations extractable by MEV searchers',
    severity: 'high',
    category: 'mev',
    pattern: /liquidate.*public|liquidation.*open/gi,
    recommendation: 'Implement MEV-resistant liquidation mechanisms'
  },
  {
    id: 'SOL7484',
    name: 'Oracle Update Frontrunning',
    description: 'Oracle updates can be frontrun for profit',
    severity: 'high',
    category: 'mev',
    pattern: /oracle.*update.*public|price.*push/gi,
    recommendation: 'Use commit-reveal or private channels for oracle updates'
  },
  {
    id: 'SOL7485',
    name: 'AMM Sandwich Vulnerability',
    description: 'AMM swaps vulnerable to sandwich attacks',
    severity: 'high',
    category: 'mev',
    pattern: /swap(?!.*slippage.*deadline)|amm(?!.*protection)/gi,
    recommendation: 'Enforce slippage limits and transaction deadlines'
  },

  // Cross-Chain Security (2025-2026)
  {
    id: 'SOL7486',
    name: 'Bridge Message Verification',
    description: 'Cross-chain message lacks proper verification',
    severity: 'critical',
    category: 'bridge',
    pattern: /bridge.*message(?!.*verify)|cross.*chain(?!.*validate)/gi,
    recommendation: 'Implement multi-signature verification for bridge messages'
  },
  {
    id: 'SOL7487',
    name: 'Bridge Finality Attack',
    description: 'Bridge accepts transactions before finality',
    severity: 'critical',
    category: 'bridge',
    pattern: /bridge(?!.*finality)|cross.*chain(?!.*confirm)/gi,
    recommendation: 'Wait for sufficient confirmations before crediting'
  },
  {
    id: 'SOL7488',
    name: 'Wrapped Asset Depegging',
    description: 'Wrapped asset can depeg from underlying',
    severity: 'critical',
    category: 'bridge',
    pattern: /wrapped.*token|bridge.*mint|peg.*ratio/gi,
    recommendation: 'Implement strict backing verification and reserve proofs'
  },
  {
    id: 'SOL7489',
    name: 'Cross-Chain Replay',
    description: 'Transaction replayable across chains',
    severity: 'critical',
    category: 'bridge',
    pattern: /cross.*chain(?!.*nonce|chain.*id)|bridge(?!.*domain)/gi,
    recommendation: 'Include chain ID and nonce in all cross-chain signatures'
  },
  {
    id: 'SOL7490',
    name: 'Bridge Oracle Manipulation',
    description: 'Bridge oracle price feed manipulable',
    severity: 'critical',
    category: 'bridge',
    pattern: /bridge.*oracle|cross.*chain.*price/gi,
    recommendation: 'Use multiple oracle sources with outlier detection'
  },

  // Intent-Based Architecture
  {
    id: 'SOL7491',
    name: 'Intent Expiration Missing',
    description: 'User intent without expiration timestamp',
    severity: 'high',
    category: 'intent',
    pattern: /intent(?!.*expire|deadline)|order(?!.*timeout)/gi,
    recommendation: 'Add expiration timestamps to all user intents'
  },
  {
    id: 'SOL7492',
    name: 'Intent Solver Manipulation',
    description: 'Intent solvers can extract excess value',
    severity: 'high',
    category: 'intent',
    pattern: /solver.*execute|filler.*intent/gi,
    recommendation: 'Implement solver competition and user-defined slippage'
  },
  {
    id: 'SOL7493',
    name: 'Intent Signature Malleability',
    description: 'Intent signatures vulnerable to malleability',
    severity: 'high',
    category: 'intent',
    pattern: /intent.*signature|signed.*order/gi,
    recommendation: 'Use EIP-712 style typed data signing for intents'
  },
  {
    id: 'SOL7494',
    name: 'Partial Fill Exploitation',
    description: 'Partial intent fills can leave user worse off',
    severity: 'medium',
    category: 'intent',
    pattern: /partial.*fill|fractional.*execute/gi,
    recommendation: 'Ensure partial fills maintain user value guarantees'
  },
  {
    id: 'SOL7495',
    name: 'Intent Nonce Collision',
    description: 'Intent nonces can collide allowing replay',
    severity: 'high',
    category: 'intent',
    pattern: /intent.*nonce|order.*id(?!.*unique)/gi,
    recommendation: 'Use globally unique nonces per user-intent pair'
  },

  // Real-Time Security (2025-2026)
  {
    id: 'SOL7496',
    name: 'Missing Circuit Breaker',
    description: 'Protocol lacks emergency circuit breaker',
    severity: 'high',
    category: 'emergency',
    pattern: /protocol(?!.*pause|circuit.*breaker)|defi(?!.*emergency)/gi,
    recommendation: 'Implement circuit breakers for anomaly detection'
  },
  {
    id: 'SOL7497',
    name: 'No Real-Time Monitoring',
    description: 'Critical operations not monitored in real-time',
    severity: 'medium',
    category: 'monitoring',
    pattern: /transfer(?!.*emit|event)|withdraw(?!.*log)/gi,
    recommendation: 'Emit events for all value-moving operations'
  },
  {
    id: 'SOL7498',
    name: 'Incident Response Gap',
    description: 'No mechanism for rapid incident response',
    severity: 'high',
    category: 'emergency',
    pattern: /admin(?!.*timelock|multisig)|owner(?!.*delay)/gi,
    recommendation: 'Implement timelocked admin actions with emergency bypass'
  },
  {
    id: 'SOL7499',
    name: 'Missing Anomaly Detection',
    description: 'No detection for unusual transaction patterns',
    severity: 'medium',
    category: 'monitoring',
    pattern: /large.*transfer(?!.*alert)|unusual(?!.*detect)/gi,
    recommendation: 'Implement on-chain anomaly detection and alerts'
  },
  {
    id: 'SOL7500',
    name: 'Recovery Mechanism Missing',
    description: 'No mechanism for fund recovery after exploit',
    severity: 'medium',
    category: 'emergency',
    pattern: /exploit(?!.*recover)|hack(?!.*rescue)/gi,
    recommendation: 'Design recovery mechanisms for white hat scenarios'
  },

  // Token Extensions (Token-2022)
  {
    id: 'SOL7501',
    name: 'Transfer Hook Exploitation',
    description: 'Token transfer hook can execute malicious code',
    severity: 'critical',
    category: 'token-2022',
    pattern: /transfer.*hook|hook.*program/gi,
    recommendation: 'Audit all transfer hooks and validate hook programs'
  },
  {
    id: 'SOL7502',
    name: 'Confidential Transfer Vulnerability',
    description: 'Confidential transfer extension misuse',
    severity: 'high',
    category: 'token-2022',
    pattern: /confidential.*transfer|zk.*token/gi,
    recommendation: 'Properly validate confidential transfer proofs'
  },
  {
    id: 'SOL7503',
    name: 'Interest-Bearing Token Abuse',
    description: 'Interest-bearing extension calculation exploitable',
    severity: 'high',
    category: 'token-2022',
    pattern: /interest.*bearing|yield.*token/gi,
    recommendation: 'Use secure interest calculation with proper rounding'
  },
  {
    id: 'SOL7504',
    name: 'Transfer Fee Bypass',
    description: 'Token transfer fee can be bypassed',
    severity: 'high',
    category: 'token-2022',
    pattern: /transfer.*fee.*token|fee.*extension/gi,
    recommendation: 'Ensure transfer fees are enforced on all transfer paths'
  },
  {
    id: 'SOL7505',
    name: 'Permanent Delegate Risk',
    description: 'Permanent delegate can drain tokens',
    severity: 'critical',
    category: 'token-2022',
    pattern: /permanent.*delegate|immutable.*authority/gi,
    recommendation: 'Carefully scope permanent delegate permissions'
  },

  // Governance (2025-2026)
  {
    id: 'SOL7506',
    name: 'Governance Token Flash Attack',
    description: 'Governance voting vulnerable to flash loan attacks',
    severity: 'critical',
    category: 'governance',
    pattern: /governance.*vote(?!.*escrow)|proposal(?!.*lock)/gi,
    recommendation: 'Use voting escrow with lock periods'
  },
  {
    id: 'SOL7507',
    name: 'Proposal Griefing',
    description: 'Proposals can be griefed through spam',
    severity: 'medium',
    category: 'governance',
    pattern: /proposal.*create(?!.*deposit)|governance(?!.*cost)/gi,
    recommendation: 'Require deposit for proposal creation'
  },
  {
    id: 'SOL7508',
    name: 'Vote Buying Vulnerability',
    description: 'Governance vulnerable to vote buying',
    severity: 'high',
    category: 'governance',
    pattern: /vote.*delegate(?!.*commit)|governance(?!.*private)/gi,
    recommendation: 'Consider shielded voting or commit-reveal'
  },
  {
    id: 'SOL7509',
    name: 'Timelock Bypass',
    description: 'Governance timelock can be bypassed',
    severity: 'critical',
    category: 'governance',
    pattern: /execute(?!.*timelock)|admin(?!.*delay)/gi,
    recommendation: 'Enforce timelock on all governance actions'
  },
  {
    id: 'SOL7510',
    name: 'Quorum Manipulation',
    description: 'Quorum can be gamed through token manipulation',
    severity: 'high',
    category: 'governance',
    pattern: /quorum.*check(?!.*snapshot)|threshold(?!.*time.*weight)/gi,
    recommendation: 'Use snapshot-based quorum calculations'
  },

  // DeFi Composability Risks
  {
    id: 'SOL7511',
    name: 'Protocol Dependency Failure',
    description: 'Protocol fails when dependency is unavailable',
    severity: 'high',
    category: 'composability',
    pattern: /external.*call(?!.*fallback)|dependency(?!.*check)/gi,
    recommendation: 'Implement fallbacks for external dependencies'
  },
  {
    id: 'SOL7512',
    name: 'Cascading Liquidation',
    description: 'Liquidations can cascade across protocols',
    severity: 'high',
    category: 'composability',
    pattern: /liquidate.*collateral|cascade.*effect/gi,
    recommendation: 'Implement circuit breakers and gradual liquidation'
  },
  {
    id: 'SOL7513',
    name: 'Flash Loan Composability',
    description: 'Flash loans enable cross-protocol attacks',
    severity: 'high',
    category: 'composability',
    pattern: /flash.*loan|same.*block.*profit/gi,
    recommendation: 'Use TWAP and implement flash loan guards'
  },
  {
    id: 'SOL7514',
    name: 'Reentrancy via Callback',
    description: 'External callback enables reentrancy',
    severity: 'critical',
    category: 'composability',
    pattern: /callback.*external|hook.*invoke/gi,
    recommendation: 'Use reentrancy guards for all callbacks'
  },
  {
    id: 'SOL7515',
    name: 'State Inconsistency Across Calls',
    description: 'State can become inconsistent across protocol calls',
    severity: 'high',
    category: 'composability',
    pattern: /cross.*program.*state|cpi.*modify/gi,
    recommendation: 'Verify state consistency after cross-program calls'
  },

  // Supply Chain and Dependencies
  {
    id: 'SOL7516',
    name: 'Malicious Dependency',
    description: 'Project uses potentially compromised dependency',
    severity: 'high',
    category: 'supply-chain',
    pattern: /crate.*untrusted|package.*unknown/gi,
    recommendation: 'Audit all dependencies and use verified crates'
  },
  {
    id: 'SOL7517',
    name: 'Typosquatting Risk',
    description: 'Dependency name vulnerable to typosquatting',
    severity: 'high',
    category: 'supply-chain',
    pattern: /solana.*web3|anchor.*lang/gi,
    recommendation: 'Verify package names match official sources exactly'
  },
  {
    id: 'SOL7518',
    name: 'Outdated Dependency',
    description: 'Using outdated dependency with known vulnerabilities',
    severity: 'medium',
    category: 'supply-chain',
    pattern: /version.*old|outdated.*crate/gi,
    recommendation: 'Keep dependencies updated and monitor advisories'
  },
  {
    id: 'SOL7519',
    name: 'Build Reproducibility',
    description: 'Build process not reproducible',
    severity: 'medium',
    category: 'supply-chain',
    pattern: /build(?!.*reproducible|verifiable)|deploy(?!.*verify)/gi,
    recommendation: 'Use reproducible builds and publish verification'
  },
  {
    id: 'SOL7520',
    name: 'Upgrade Authority Compromise',
    description: 'Program upgrade authority could be compromised',
    severity: 'critical',
    category: 'supply-chain',
    pattern: /upgrade.*authority(?!.*multisig)|program.*owner/gi,
    recommendation: 'Use multisig for upgrade authority'
  },

  // Economic Security
  {
    id: 'SOL7521',
    name: 'Tokenomics Vulnerability',
    description: 'Token economics have exploitable conditions',
    severity: 'high',
    category: 'economic',
    pattern: /infinite.*mint|uncapped.*supply|rebase.*exploit/gi,
    recommendation: 'Conduct economic security review of tokenomics'
  },
  {
    id: 'SOL7522',
    name: 'Yield Manipulation',
    description: 'Yield calculations can be manipulated',
    severity: 'high',
    category: 'economic',
    pattern: /apy.*calculate|yield.*compute(?!.*twap)/gi,
    recommendation: 'Use time-weighted calculations for yield'
  },
  {
    id: 'SOL7523',
    name: 'Fee Extraction',
    description: 'Protocol fees can be extracted or evaded',
    severity: 'medium',
    category: 'economic',
    pattern: /fee.*bypass|protocol.*fee(?!.*enforce)/gi,
    recommendation: 'Enforce fees on all paths and audit fee logic'
  },
  {
    id: 'SOL7524',
    name: 'Incentive Misalignment',
    description: 'Economic incentives are misaligned',
    severity: 'medium',
    category: 'economic',
    pattern: /reward.*gaming|incentive(?!.*align)/gi,
    recommendation: 'Review incentive structures for gaming vectors'
  },
  {
    id: 'SOL7525',
    name: 'Market Manipulation Vector',
    description: 'Protocol vulnerable to market manipulation',
    severity: 'high',
    category: 'economic',
    pattern: /price.*impact(?!.*limit)|market(?!.*protection)/gi,
    recommendation: 'Implement price impact limits and manipulation detection'
  }
];

export default emergingThreatsPatterns;
