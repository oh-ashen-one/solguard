/**
 * SolGuard Pattern Batch 38
 * Deep DeFi and Protocol-Specific Vulnerabilities
 * Patterns SOL961-SOL1020
 */

import type { PatternInput, Finding } from './index.js';

interface BatchPattern {
  id: string;
  name: string;
  severity: 'critical' | 'high' | 'medium' | 'low' | 'info';
  category: string;
  description: string;
  detection: {
    patterns: RegExp[];
  };
  recommendation: string;
  references: string[];
}

const batchedPatterns38: BatchPattern[] = [
  // Perpetual DEX Specific Vulnerabilities
  {
    id: 'SOL961',
    name: 'Perpetual Funding Rate Manipulation',
    severity: 'critical',
    category: 'perpetual',
    description: 'Funding rate calculation can be manipulated to drain traders.',
    detection: {
      patterns: [
        /funding.*rate/i,
        /funding.*payment/i,
        /perp.*funding/i,
        /rate.*calc/i
      ]
    },
    recommendation: 'Use robust funding rate formulas. Implement rate limits. Add manipulation detection.',
    references: ['https://solanasec25.sec3.dev/']
  },
  {
    id: 'SOL962',
    name: 'Liquidation Price Manipulation',
    severity: 'critical',
    category: 'perpetual',
    description: 'Liquidation triggers can be manipulated through oracle/price attacks.',
    detection: {
      patterns: [
        /liquidation.*price/i,
        /liq.*threshold/i,
        /margin.*call/i,
        /maintenance.*margin/i
      ]
    },
    recommendation: 'Use TWAP for liquidation prices. Add grace periods. Implement insurance fund.',
    references: ['https://solanasec25.sec3.dev/']
  },
  {
    id: 'SOL963',
    name: 'Position Size Limit Bypass',
    severity: 'high',
    category: 'perpetual',
    description: 'Position size limits can be bypassed through multiple accounts.',
    detection: {
      patterns: [
        /position.*size/i,
        /max.*position/i,
        /size.*limit/i,
        /notional.*limit/i
      ]
    },
    recommendation: 'Implement protocol-wide position tracking. Add account linking detection.',
    references: ['https://solanasec25.sec3.dev/']
  },
  {
    id: 'SOL964',
    name: 'Mark Price Deviation',
    severity: 'critical',
    category: 'perpetual',
    description: 'Mark price deviates from fair value enabling manipulation.',
    detection: {
      patterns: [
        /mark.*price/i,
        /index.*price/i,
        /fair.*value/i,
        /price.*deviation/i
      ]
    },
    recommendation: 'Bound mark price to index. Use multiple price sources. Implement circuit breakers.',
    references: ['https://solanasec25.sec3.dev/']
  },
  {
    id: 'SOL965',
    name: 'ADL (Auto-Deleverage) Gaming',
    severity: 'high',
    category: 'perpetual',
    description: 'Auto-deleveraging system can be gamed for profit.',
    detection: {
      patterns: [
        /auto.*deleverage/i,
        /adl/i,
        /deleverage.*queue/i,
        /profit.*ranking/i
      ]
    },
    recommendation: 'Randomize ADL selection. Add fairness mechanisms. Implement ADL prevention strategies.',
    references: ['https://solanasec25.sec3.dev/']
  },
  
  // Options Protocol Vulnerabilities
  {
    id: 'SOL966',
    name: 'Options Premium Mispricing',
    severity: 'high',
    category: 'options',
    description: 'Options premium calculation errors enable arbitrage.',
    detection: {
      patterns: [
        /premium.*calc/i,
        /option.*price/i,
        /black.*scholes/i,
        /iv.*implied/i
      ]
    },
    recommendation: 'Use robust pricing models. Validate against market prices. Add premium bounds.',
    references: ['https://solanasec25.sec3.dev/']
  },
  {
    id: 'SOL967',
    name: 'Options Settlement Manipulation',
    severity: 'critical',
    category: 'options',
    description: 'Options settlement price can be manipulated near expiry.',
    detection: {
      patterns: [
        /settlement.*price/i,
        /expiry.*price/i,
        /exercise/i,
        /strike.*price/i
      ]
    },
    recommendation: 'Use TWAP for settlement. Add settlement window. Multiple oracle sources.',
    references: ['https://solanasec25.sec3.dev/']
  },
  {
    id: 'SOL968',
    name: 'Vault Collateral Manipulation',
    severity: 'critical',
    category: 'options',
    description: 'Option vault collateral can be drained through specific strategies.',
    detection: {
      patterns: [
        /vault.*collateral/i,
        /option.*vault/i,
        /covered.*call/i,
        /put.*spread/i
      ]
    },
    recommendation: 'Implement strict collateral requirements. Add position limits. Monitor vault health.',
    references: ['https://solanasec25.sec3.dev/']
  },
  
  // Yield Aggregator Vulnerabilities
  {
    id: 'SOL969',
    name: 'Yield Strategy Exploit',
    severity: 'critical',
    category: 'yield',
    description: 'Yield strategies can be exploited through deposit/withdraw manipulation.',
    detection: {
      patterns: [
        /strategy.*deposit/i,
        /yield.*vault/i,
        /auto.*compound/i,
        /harvest.*reward/i
      ]
    },
    recommendation: 'Add deposit/withdraw delays. Implement fair share calculation. Monitor TVL changes.',
    references: ['https://solanasec25.sec3.dev/']
  },
  {
    id: 'SOL970',
    name: 'Share Price Manipulation',
    severity: 'critical',
    category: 'yield',
    description: 'Vault share prices can be manipulated through donation attacks.',
    detection: {
      patterns: [
        /share.*price/i,
        /price.*per.*share/i,
        /vault.*token/i,
        /exchange.*rate/i
      ]
    },
    recommendation: 'Implement virtual liquidity. Use time-weighted pricing. Add donation detection.',
    references: ['https://solanasec25.sec3.dev/']
  },
  {
    id: 'SOL971',
    name: 'Reward Distribution Manipulation',
    severity: 'high',
    category: 'yield',
    description: 'Reward distribution timing can be gamed for unfair yields.',
    detection: {
      patterns: [
        /reward.*dist/i,
        /emission.*rate/i,
        /reward.*per.*token/i,
        /accumulated.*reward/i
      ]
    },
    recommendation: 'Use continuous reward accrual. Implement lock periods. Add cliff vesting.',
    references: ['https://solanasec25.sec3.dev/']
  },
  
  // Lending Protocol Deep Vulnerabilities
  {
    id: 'SOL972',
    name: 'Interest Rate Model Manipulation',
    severity: 'high',
    category: 'lending',
    description: 'Interest rate models can be manipulated through utilization changes.',
    detection: {
      patterns: [
        /interest.*rate.*model/i,
        /utilization.*rate/i,
        /borrow.*rate/i,
        /supply.*rate/i
      ]
    },
    recommendation: 'Use robust interest rate curves. Implement rate smoothing. Add utilization guards.',
    references: ['https://solanasec25.sec3.dev/']
  },
  {
    id: 'SOL973',
    name: 'Bad Debt Accumulation',
    severity: 'critical',
    category: 'lending',
    description: 'Protocol accumulates bad debt faster than insurance fund.',
    detection: {
      patterns: [
        /bad.*debt/i,
        /insurance.*fund/i,
        /shortfall/i,
        /underwater.*position/i
      ]
    },
    recommendation: 'Implement robust liquidation. Size insurance fund appropriately. Add bad debt handling.',
    references: ['https://solanasec25.sec3.dev/']
  },
  {
    id: 'SOL974',
    name: 'Isolated Pool Contagion',
    severity: 'high',
    category: 'lending',
    description: 'Isolated lending pools can affect main protocol through shared components.',
    detection: {
      patterns: [
        /isolated.*pool/i,
        /separate.*market/i,
        /pool.*isolation/i,
        /cross.*pool/i
      ]
    },
    recommendation: 'Truly isolate pools. Separate oracles. Implement pool-specific risk parameters.',
    references: ['https://solanasec25.sec3.dev/']
  },
  {
    id: 'SOL975',
    name: 'Reserve Factor Manipulation',
    severity: 'medium',
    category: 'lending',
    description: 'Reserve factor changes can unexpectedly affect depositors.',
    detection: {
      patterns: [
        /reserve.*factor/i,
        /protocol.*fee/i,
        /treasury.*cut/i,
        /fee.*percent/i
      ]
    },
    recommendation: 'Timelock reserve factor changes. Communicate changes to users. Set reasonable limits.',
    references: ['https://solanasec25.sec3.dev/']
  },
  
  // Stablecoin Specific Vulnerabilities
  {
    id: 'SOL976',
    name: 'Stablecoin Depeg Risk',
    severity: 'critical',
    category: 'stablecoin',
    description: 'Stablecoin can depeg under specific market conditions.',
    detection: {
      patterns: [
        /peg.*mechanism/i,
        /redemption/i,
        /stable.*value/i,
        /backing.*ratio/i
      ]
    },
    recommendation: 'Implement robust peg mechanisms. Over-collateralize. Add circuit breakers.',
    references: ['https://solanasec25.sec3.dev/']
  },
  {
    id: 'SOL977',
    name: 'Algorithmic Stability Failure',
    severity: 'critical',
    category: 'stablecoin',
    description: 'Algorithmic stabilization mechanisms fail under stress.',
    detection: {
      patterns: [
        /algorithmic.*stable/i,
        /mint.*burn.*stable/i,
        /rebase/i,
        /expansion.*contract/i
      ]
    },
    recommendation: 'Use hybrid mechanisms. Add collateral backing. Implement emergency procedures.',
    references: ['https://solanasec25.sec3.dev/']
  },
  {
    id: 'SOL978',
    name: 'CDP Liquidation Cascade',
    severity: 'critical',
    category: 'stablecoin',
    description: 'CDP liquidations cascade causing protocol insolvency.',
    detection: {
      patterns: [
        /cdp/i,
        /collateral.*debt/i,
        /vault.*liquidation/i,
        /stability.*fee/i
      ]
    },
    recommendation: 'Implement gradual liquidation. Add keeper incentives. Size stability pool.',
    references: ['https://solanasec25.sec3.dev/']
  },
  
  // NFT/GameFi Specific Vulnerabilities
  {
    id: 'SOL979',
    name: 'NFT Metadata Manipulation',
    severity: 'high',
    category: 'nft',
    description: 'NFT metadata can be changed post-mint affecting value.',
    detection: {
      patterns: [
        /metadata.*update/i,
        /set.*uri/i,
        /update.*metadata/i,
        /mutable.*metadata/i
      ]
    },
    recommendation: 'Make metadata immutable after mint. Use content-addressed storage. Document mutability.',
    references: ['https://solanasec25.sec3.dev/']
  },
  {
    id: 'SOL980',
    name: 'NFT Rarity Manipulation',
    severity: 'high',
    category: 'nft',
    description: 'NFT rarity attributes can be manipulated by creators.',
    detection: {
      patterns: [
        /rarity/i,
        /trait.*value/i,
        /attribute.*update/i,
        /collection.*verify/i
      ]
    },
    recommendation: 'Lock attributes after reveal. Use verifiable randomness. Implement rarity verification.',
    references: ['https://solanasec25.sec3.dev/']
  },
  {
    id: 'SOL981',
    name: 'Game Economy Inflation',
    severity: 'high',
    category: 'gaming',
    description: 'Game economy tokens can be inflated through exploits.',
    detection: {
      patterns: [
        /game.*token/i,
        /in.*game.*currency/i,
        /reward.*mint/i,
        /play.*earn/i
      ]
    },
    recommendation: 'Implement emission caps. Use burn mechanics. Add anti-bot measures.',
    references: ['https://solanasec25.sec3.dev/']
  },
  {
    id: 'SOL982',
    name: 'NFT Staking Reward Manipulation',
    severity: 'high',
    category: 'nft',
    description: 'NFT staking rewards can be manipulated through stake/unstake timing.',
    detection: {
      patterns: [
        /nft.*stake/i,
        /stake.*reward/i,
        /staking.*emission/i,
        /nft.*lock/i
      ]
    },
    recommendation: 'Use continuous reward accrual. Add unstaking delays. Implement snapshot-based rewards.',
    references: ['https://solanasec25.sec3.dev/']
  },
  
  // Cross-Chain Bridge Deep Vulnerabilities
  {
    id: 'SOL983',
    name: 'Bridge Validator Collusion',
    severity: 'critical',
    category: 'bridge',
    description: 'Bridge validators can collude to steal funds.',
    detection: {
      patterns: [
        /validator.*set/i,
        /guardian.*quorum/i,
        /multisig.*bridge/i,
        /relayer/i
      ]
    },
    recommendation: 'Diversify validator set. Implement slashing. Add fraud proofs.',
    references: ['https://solanasec25.sec3.dev/']
  },
  {
    id: 'SOL984',
    name: 'Bridge Token Mismatch',
    severity: 'critical',
    category: 'bridge',
    description: 'Bridge token representations mismatch between chains.',
    detection: {
      patterns: [
        /wrapped.*token/i,
        /bridge.*mint/i,
        /canonical.*token/i,
        /token.*mapping/i
      ]
    },
    recommendation: 'Maintain strict token mappings. Verify decimals. Implement token verification.',
    references: ['https://solanasec25.sec3.dev/']
  },
  {
    id: 'SOL985',
    name: 'Bridge Fee Extraction',
    severity: 'high',
    category: 'bridge',
    description: 'Bridge fees can be manipulated or extracted by attackers.',
    detection: {
      patterns: [
        /bridge.*fee/i,
        /cross.*chain.*fee/i,
        /relayer.*fee/i,
        /gas.*subsidy/i
      ]
    },
    recommendation: 'Cap bridge fees. Implement fee refunds. Add fee manipulation detection.',
    references: ['https://solanasec25.sec3.dev/']
  },
  
  // Governance Deep Vulnerabilities
  {
    id: 'SOL986',
    name: 'Flash Loan Governance Attack',
    severity: 'critical',
    category: 'governance',
    description: 'Flash loans used to temporarily gain voting power.',
    detection: {
      patterns: [
        /vote.*power/i,
        /snapshot.*vote/i,
        /governance.*token/i,
        /delegate.*vote/i
      ]
    },
    recommendation: 'Use time-weighted voting. Require token lock. Implement snapshot-based voting.',
    references: ['https://solanasec25.sec3.dev/']
  },
  {
    id: 'SOL987',
    name: 'Proposal Griefing',
    severity: 'medium',
    category: 'governance',
    description: 'Governance proposals blocked through griefing attacks.',
    detection: {
      patterns: [
        /proposal.*create/i,
        /vote.*against/i,
        /proposal.*cancel/i,
        /quorum.*require/i
      ]
    },
    recommendation: 'Implement proposal deposits. Add proposal filtering. Use optimistic governance.',
    references: ['https://solanasec25.sec3.dev/']
  },
  {
    id: 'SOL988',
    name: 'Timelock Bypass',
    severity: 'critical',
    category: 'governance',
    description: 'Governance timelock can be bypassed through specific paths.',
    detection: {
      patterns: [
        /timelock/i,
        /delay.*execution/i,
        /queue.*proposal/i,
        /eta.*timestamp/i
      ]
    },
    recommendation: 'Enforce timelock for all paths. Audit bypass vectors. Add emergency veto.',
    references: ['https://solanasec25.sec3.dev/']
  },
  
  // Token Launch/Fair Launch Vulnerabilities
  {
    id: 'SOL989',
    name: 'Bonding Curve Front-Running',
    severity: 'high',
    category: 'launch',
    description: 'Bonding curve launches front-run by bots.',
    detection: {
      patterns: [
        /bonding.*curve/i,
        /price.*curve/i,
        /launch.*price/i,
        /mint.*curve/i
      ]
    },
    recommendation: 'Use anti-bot mechanisms. Implement max per-wallet. Add launch delays.',
    references: ['https://solanasec25.sec3.dev/']
  },
  {
    id: 'SOL990',
    name: 'LBP (Liquidity Bootstrapping) Manipulation',
    severity: 'high',
    category: 'launch',
    description: 'LBP price discovery manipulated by large participants.',
    detection: {
      patterns: [
        /lbp/i,
        /liquidity.*bootstrap/i,
        /weight.*shift/i,
        /dutch.*auction/i
      ]
    },
    recommendation: 'Implement purchase limits. Use gradual weight shifting. Add whale detection.',
    references: ['https://solanasec25.sec3.dev/']
  },
  {
    id: 'SOL991',
    name: 'Airdrop Sybil Attack',
    severity: 'high',
    category: 'launch',
    description: 'Airdrops exploited through multiple accounts.',
    detection: {
      patterns: [
        /airdrop/i,
        /claim.*eligib/i,
        /merkle.*claim/i,
        /distribution/i
      ]
    },
    recommendation: 'Implement sybil resistance. Use activity-based criteria. Add claim verification.',
    references: ['https://solanasec25.sec3.dev/']
  },
  
  // Anchor Framework Specific
  {
    id: 'SOL992',
    name: 'Anchor Account Close Vulnerability',
    severity: 'critical',
    category: 'anchor',
    description: 'Anchor close constraint allows unauthorized account closure.',
    detection: {
      patterns: [
        /close\s*=/i,
        /#\[account\(.*close/i,
        /AccountInfo.*close/i,
        /close_account/i
      ]
    },
    recommendation: 'Verify close authority. Zero data before close. Check for account revival.',
    references: ['https://github.com/sannykim/solsec']
  },
  {
    id: 'SOL993',
    name: 'Anchor Realloc Without Bounds',
    severity: 'high',
    category: 'anchor',
    description: 'Account reallocation without proper bounds checking.',
    detection: {
      patterns: [
        /realloc\s*=/i,
        /#\[account\(.*realloc/i,
        /realloc_account/i,
        /resize.*account/i
      ]
    },
    recommendation: 'Set maximum realloc size. Validate new size. Check lamports for rent.',
    references: ['https://github.com/sannykim/solsec']
  },
  {
    id: 'SOL994',
    name: 'Anchor Seeds Collision',
    severity: 'critical',
    category: 'anchor',
    description: 'PDA seeds can collide across different account types.',
    detection: {
      patterns: [
        /seeds\s*=/i,
        /#\[account\(.*seeds/i,
        /find_program_address/i,
        /create_program_address/i
      ]
    },
    recommendation: 'Include account type in seeds. Use unique prefixes. Verify seed uniqueness.',
    references: ['https://github.com/sannykim/solsec']
  },
  {
    id: 'SOL995',
    name: 'Anchor Has One Without Owner',
    severity: 'high',
    category: 'anchor',
    description: 'has_one constraint without owner verification.',
    detection: {
      patterns: [
        /has_one\s*=/i,
        /#\[account\(.*has_one/i,
        /constraint.*==.*key/i,
        /authority.*match/i
      ]
    },
    recommendation: 'Combine has_one with owner check. Verify account program ownership.',
    references: ['https://github.com/sannykim/solsec']
  },
  
  // Native Program Vulnerabilities
  {
    id: 'SOL996',
    name: 'System Program Transfer Validation',
    severity: 'high',
    category: 'native',
    description: 'System program transfer without proper validation.',
    detection: {
      patterns: [
        /system_instruction::transfer/i,
        /SystemInstruction::Transfer/i,
        /sol_transfer/i,
        /lamports.*transfer/i
      ]
    },
    recommendation: 'Validate transfer amounts. Check balance before transfer. Use checked arithmetic.',
    references: ['https://github.com/sannykim/solsec']
  },
  {
    id: 'SOL997',
    name: 'Token Program Authority Confusion',
    severity: 'critical',
    category: 'native',
    description: 'Token program authority confused with other accounts.',
    detection: {
      patterns: [
        /token::authority/i,
        /mint_authority/i,
        /freeze_authority/i,
        /owner.*authority/i
      ]
    },
    recommendation: 'Explicitly verify authority type. Use separate authority accounts.',
    references: ['https://github.com/sannykim/solsec']
  },
  {
    id: 'SOL998',
    name: 'Associated Token Account Race',
    severity: 'high',
    category: 'native',
    description: 'ATA creation race condition allows token theft.',
    detection: {
      patterns: [
        /create_associated_token/i,
        /get_associated_token/i,
        /ata.*create/i,
        /associated.*token.*account/i
      ]
    },
    recommendation: 'Use create_idempotent. Check ATA exists before use. Handle creation atomically.',
    references: ['https://github.com/sannykim/solsec']
  },
  
  // Compute and Resource Vulnerabilities
  {
    id: 'SOL999',
    name: 'Compute Budget Exhaustion',
    severity: 'high',
    category: 'compute',
    description: 'Transaction exhausts compute budget before completion.',
    detection: {
      patterns: [
        /compute.*budget/i,
        /request.*units/i,
        /ComputeBudget/i,
        /cu.*limit/i
      ]
    },
    recommendation: 'Optimize compute usage. Add compute budget checks. Implement pagination.',
    references: ['https://github.com/sannykim/solsec']
  },
  {
    id: 'SOL1000',
    name: 'Account Size Limit Exceeded',
    severity: 'high',
    category: 'compute',
    description: 'Account data exceeds size limits causing failures.',
    detection: {
      patterns: [
        /account.*size/i,
        /max.*len/i,
        /space\s*=/i,
        /10.*MB/i
      ]
    },
    recommendation: 'Design for account size limits. Implement data pagination. Use multiple accounts.',
    references: ['https://github.com/sannykim/solsec']
  },
  
  // New 2025 Pattern Categories
  {
    id: 'SOL1001',
    name: 'Blinks Action Manipulation',
    severity: 'high',
    category: 'blinks',
    description: 'Solana Blinks actions can be manipulated through URL parameters.',
    detection: {
      patterns: [
        /blink.*action/i,
        /action.*url/i,
        /solana.*pay/i,
        /transaction.*request/i
      ]
    },
    recommendation: 'Validate all blink parameters. Implement action signing. Add request verification.',
    references: ['https://solanasec25.sec3.dev/']
  },
  {
    id: 'SOL1002',
    name: 'Intent-Based Transaction Manipulation',
    severity: 'high',
    category: 'intent',
    description: 'Intent-based transactions can be manipulated by solvers.',
    detection: {
      patterns: [
        /intent/i,
        /solver/i,
        /fill.*order/i,
        /execution.*constraint/i
      ]
    },
    recommendation: 'Define strict intent constraints. Implement solver reputation. Add fill verification.',
    references: ['https://solanasec25.sec3.dev/']
  },
  {
    id: 'SOL1003',
    name: 'Restaking Protocol Risk',
    severity: 'high',
    category: 'restaking',
    description: 'Restaking protocols compound risk across multiple layers.',
    detection: {
      patterns: [
        /restake/i,
        /liquid.*staking/i,
        /lst.*collateral/i,
        /derivative.*stake/i
      ]
    },
    recommendation: 'Audit restaking chains. Implement risk limits. Add cascade failure protection.',
    references: ['https://solanasec25.sec3.dev/']
  },
  {
    id: 'SOL1004',
    name: 'RWA (Real World Asset) Oracle Risk',
    severity: 'critical',
    category: 'rwa',
    description: 'Real world asset price oracles can be manipulated or delayed.',
    detection: {
      patterns: [
        /rwa/i,
        /real.*world.*asset/i,
        /off.*chain.*price/i,
        /asset.*valuation/i
      ]
    },
    recommendation: 'Use multiple RWA oracles. Implement price validation. Add manual verification.',
    references: ['https://solanasec25.sec3.dev/']
  },
  {
    id: 'SOL1005',
    name: 'cNFT Proof Manipulation',
    severity: 'high',
    category: 'compression',
    description: 'Compressed NFT proofs can be manipulated for unauthorized transfers.',
    detection: {
      patterns: [
        /cnft/i,
        /compressed.*nft/i,
        /merkle.*proof/i,
        /concurrent.*merkle/i
      ]
    },
    recommendation: 'Verify proof freshness. Implement canopy depth. Add proof validation.',
    references: ['https://solanasec25.sec3.dev/']
  },
  {
    id: 'SOL1006',
    name: 'Token-2022 Interest Bearing Exploit',
    severity: 'high',
    category: 'token-2022',
    description: 'Interest bearing tokens can be exploited through timing attacks.',
    detection: {
      patterns: [
        /interest.*bearing/i,
        /amount_to_ui_amount/i,
        /ui_amount_to_amount/i,
        /interest.*rate/i
      ]
    },
    recommendation: 'Use consistent timestamp handling. Validate interest calculations. Add rate limits.',
    references: ['https://solanasec25.sec3.dev/']
  },
  {
    id: 'SOL1007',
    name: 'Token-2022 Transfer Hook Reentrancy',
    severity: 'critical',
    category: 'token-2022',
    description: 'Transfer hooks can enable reentrancy attacks.',
    detection: {
      patterns: [
        /transfer.*hook/i,
        /TransferHook/i,
        /hook.*program/i,
        /execute.*transfer.*hook/i
      ]
    },
    recommendation: 'Implement reentrancy guards in hooks. Validate hook state. Add hook verification.',
    references: ['https://solanasec25.sec3.dev/']
  },
  {
    id: 'SOL1008',
    name: 'Social-Fi Platform Risk',
    severity: 'high',
    category: 'social',
    description: 'Social-Fi platforms vulnerable to manipulation and sybil attacks.',
    detection: {
      patterns: [
        /social.*token/i,
        /creator.*coin/i,
        /fan.*token/i,
        /bonding.*social/i
      ]
    },
    recommendation: 'Implement sybil resistance. Add creator verification. Use gradual unlocks.',
    references: ['https://solanasec25.sec3.dev/']
  },
  {
    id: 'SOL1009',
    name: 'Prediction Market Resolution',
    severity: 'high',
    category: 'prediction',
    description: 'Prediction market resolution can be manipulated.',
    detection: {
      patterns: [
        /market.*resolution/i,
        /outcome.*settle/i,
        /oracle.*resolve/i,
        /prediction.*payout/i
      ]
    },
    recommendation: 'Use decentralized resolution. Implement dispute mechanism. Add resolution delays.',
    references: ['https://solanasec25.sec3.dev/']
  },
  {
    id: 'SOL1010',
    name: 'DEX Aggregator Route Manipulation',
    severity: 'high',
    category: 'aggregator',
    description: 'DEX aggregator routes can be manipulated for worse execution.',
    detection: {
      patterns: [
        /route.*swap/i,
        /aggregator/i,
        /best.*path/i,
        /jupiter.*swap/i
      ]
    },
    recommendation: 'Verify route execution. Implement minimum output. Add route verification.',
    references: ['https://solanasec25.sec3.dev/']
  },
  
  // Additional Security Patterns
  {
    id: 'SOL1011',
    name: 'Cross-Program Account Confusion',
    severity: 'critical',
    category: 'cpi',
    description: 'Accounts passed to CPIs can be confused across programs.',
    detection: {
      patterns: [
        /invoke.*accounts/i,
        /cpi.*context/i,
        /remaining.*accounts/i,
        /AccountInfo.*cpi/i
      ]
    },
    recommendation: 'Explicitly verify account programs. Use typed CPI calls. Validate account ownership.',
    references: ['https://github.com/sannykim/solsec']
  },
  {
    id: 'SOL1012',
    name: 'Lookup Table Poisoning',
    severity: 'high',
    category: 'infrastructure',
    description: 'Address lookup tables can be poisoned with malicious addresses.',
    detection: {
      patterns: [
        /lookup.*table/i,
        /address.*lookup/i,
        /alt.*account/i,
        /extend.*lookup/i
      ]
    },
    recommendation: 'Verify lookup table authority. Use trusted tables only. Validate table contents.',
    references: ['https://github.com/sannykim/solsec']
  },
  {
    id: 'SOL1013',
    name: 'Versioned Transaction Confusion',
    severity: 'medium',
    category: 'transaction',
    description: 'Legacy and versioned transaction handling differs unexpectedly.',
    detection: {
      patterns: [
        /versioned.*transaction/i,
        /MessageV0/i,
        /legacy.*message/i,
        /transaction.*version/i
      ]
    },
    recommendation: 'Handle both transaction types explicitly. Test version compatibility.',
    references: ['https://github.com/sannykim/solsec']
  },
  {
    id: 'SOL1014',
    name: 'Priority Fee Griefing',
    severity: 'medium',
    category: 'mev',
    description: 'Priority fees used to grief other users transactions.',
    detection: {
      patterns: [
        /priority.*fee/i,
        /compute.*unit.*price/i,
        /base.*fee/i,
        /tip/i
      ]
    },
    recommendation: 'Implement fair ordering. Use private transaction pools. Add priority caps.',
    references: ['https://github.com/sannykim/solsec']
  },
  {
    id: 'SOL1015',
    name: 'Program Derived Address Reuse',
    severity: 'high',
    category: 'pda',
    description: 'PDAs reused across different contexts causing state pollution.',
    detection: {
      patterns: [
        /pda.*reuse/i,
        /same.*seeds/i,
        /shared.*pda/i,
        /global.*pda/i
      ]
    },
    recommendation: 'Use unique seeds per context. Include version in seeds. Add context identifiers.',
    references: ['https://github.com/sannykim/solsec']
  },
  {
    id: 'SOL1016',
    name: 'Event Emission Manipulation',
    severity: 'medium',
    category: 'event',
    description: 'Off-chain systems rely on events that can be manipulated.',
    detection: {
      patterns: [
        /emit!/i,
        /log.*event/i,
        /msg!/i,
        /sol_log_data/i
      ]
    },
    recommendation: 'Verify events on-chain when possible. Implement event ordering. Add event signatures.',
    references: ['https://github.com/sannykim/solsec']
  },
  {
    id: 'SOL1017',
    name: 'Clock Sysvar Manipulation',
    severity: 'high',
    category: 'sysvar',
    description: 'Programs relying on clock sysvar can be manipulated by validators.',
    detection: {
      patterns: [
        /Clock::get/i,
        /sysvar::clock/i,
        /unix_timestamp/i,
        /slot.*number/i
      ]
    },
    recommendation: 'Use slot-based timing. Add timestamp tolerance. Consider validator manipulation.',
    references: ['https://github.com/sannykim/solsec']
  },
  {
    id: 'SOL1018',
    name: 'Rent Sysvar Edge Cases',
    severity: 'medium',
    category: 'sysvar',
    description: 'Rent calculations have edge cases causing unexpected behavior.',
    detection: {
      patterns: [
        /Rent::get/i,
        /rent_exempt/i,
        /minimum_balance/i,
        /lamports_per/i
      ]
    },
    recommendation: 'Over-estimate rent requirements. Handle rent changes. Test edge cases.',
    references: ['https://github.com/sannykim/solsec']
  },
  {
    id: 'SOL1019',
    name: 'Instruction Sysvar Injection',
    severity: 'critical',
    category: 'sysvar',
    description: 'Instructions sysvar can be used to inject malicious instructions.',
    detection: {
      patterns: [
        /Instructions::get/i,
        /sysvar::instructions/i,
        /get_instruction_relative/i,
        /load_instruction_at/i
      ]
    },
    recommendation: 'Validate instruction sources. Check instruction program IDs. Limit instruction access.',
    references: ['https://github.com/sannykim/solsec']
  },
  {
    id: 'SOL1020',
    name: 'Epoch Info Time Sensitivity',
    severity: 'medium',
    category: 'sysvar',
    description: 'Programs using epoch info vulnerable to epoch boundary issues.',
    detection: {
      patterns: [
        /EpochInfo/i,
        /epoch.*schedule/i,
        /slots_per_epoch/i,
        /epoch.*boundary/i
      ]
    },
    recommendation: 'Handle epoch transitions gracefully. Add buffer around boundaries. Test epoch changes.',
    references: ['https://github.com/sannykim/solsec']
  }
];

export function runBatchedPatterns38(content: string, path: string): Finding[] {
  const findings: Finding[] = [];
  const lines = content.split('\n');
  
  for (const pattern of batchedPatterns38) {
    for (const regex of pattern.detection.patterns) {
      const flags = regex.flags.includes('g') ? regex.flags : regex.flags + 'g';
      const searchRegex = new RegExp(regex.source, flags);
      const matches = [...content.matchAll(searchRegex)];
      
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
        
        findings.push({
          id: pattern.id,
          title: pattern.name,
          severity: pattern.severity,
          description: pattern.description,
          location: { file: path, line: lineNum },
          recommendation: pattern.recommendation,
        });
      }
    }
  }
  
  // Deduplicate
  const seen = new Set<string>();
  return findings.filter(f => {
    const key = `${f.id}-${f.location.line}`;
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  });
}

export default batchedPatterns38;
