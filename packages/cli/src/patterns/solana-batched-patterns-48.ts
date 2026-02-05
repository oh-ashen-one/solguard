/**
 * Batch 48: Advanced Security Patterns - DeFi Deep Dive
 * IDs: SOL1651-SOL1720
 * 
 * Based on:
 * - Certora audit methodologies
 * - Accretion security research (80% critical vuln discovery rate)
 * - Hacken 2025 Yearly Security Report
 * - GetFailsafe Solana audit checklist
 */

import { SecurityPattern } from './types';

export const batchedPatterns48: SecurityPattern[] = [
  // === ADVANCED LENDING PATTERNS ===
  {
    id: 'SOL1651',
    name: 'Interest Accrual Precision Loss',
    description: 'Detects interest calculations with precision loss that can be exploited.',
    severity: 'high',
    category: 'lending',
    detector: (code: string) => {
      const patterns = [
        /interest.*\/.*10+.*then.*\*/i,
        /accrue.*truncate/i,
        /rate.*precision.*loss/i,
        /compound.*interest.*integer/i,
      ];
      return patterns.some(p => p.test(code));
    },
    recommendation: 'Use high precision math (e.g., WAD/RAY). Accumulate rounding in protocol\'s favor.',
  },
  {
    id: 'SOL1652',
    name: 'Borrow Rate Model Kink Exploit',
    description: 'Identifies interest rate model kink points that can be exploited.',
    severity: 'medium',
    category: 'lending',
    detector: (code: string) => {
      const patterns = [
        /utilization.*kink.*manipulate/i,
        /rate.*model.*discontinuity/i,
        /jump.*rate.*exploit/i,
        /kink.*threshold.*game/i,
      ];
      return patterns.some(p => p.test(code));
    },
    recommendation: 'Use smooth interest rate curves. Implement utilization caps. Add rate change limits.',
  },
  {
    id: 'SOL1653',
    name: 'Collateral Factor Too Aggressive',
    description: 'Detects collateral factors that are too high, risking protocol solvency.',
    severity: 'high',
    category: 'lending',
    detector: (code: string) => {
      const patterns = [
        /collateral.*factor.*>.*9[5-9]/i,
        /ltv.*=.*98/i,
        /borrow.*limit.*99%/i,
        /max.*collateral.*factor/i,
      ];
      return patterns.some(p => p.test(code));
    },
    recommendation: 'Use conservative collateral factors. Account for volatility and liquidation costs.',
  },
  {
    id: 'SOL1654',
    name: 'Reserve Factor Not Applied',
    description: 'Identifies lending markets without proper reserve factor application.',
    severity: 'medium',
    category: 'lending',
    detector: (code: string) => {
      const patterns = [
        /reserve.*factor.*=.*0/i,
        /interest.*no.*reserve/i,
        /protocol.*fee.*missing/i,
        /lender.*gets.*all.*interest/i,
      ];
      return patterns.some(p => p.test(code));
    },
    recommendation: 'Apply reserve factors to build protocol treasury for bad debt coverage.',
  },
  {
    id: 'SOL1655',
    name: 'Liquidation Close Factor Too High',
    description: 'Detects liquidation allowing too much position closure in single tx.',
    severity: 'high',
    category: 'lending',
    detector: (code: string) => {
      const patterns = [
        /close.*factor.*=.*100/i,
        /liquidate.*entire.*position/i,
        /full.*liquidation.*allowed/i,
        /max.*liquidate.*all/i,
      ];
      return patterns.some(p => p.test(code));
    },
    recommendation: 'Limit close factor (e.g., 50%). Implement partial liquidations. Add liquidation cooling periods.',
  },

  // === DEX/AMM ADVANCED PATTERNS ===
  {
    id: 'SOL1656',
    name: 'AMM Constant Product Invariant Violation',
    description: 'Detects potential violations of constant product invariant (x*y=k).',
    severity: 'critical',
    category: 'amm',
    detector: (code: string) => {
      const patterns = [
        /swap.*no.*invariant.*check/i,
        /k.*value.*decrease/i,
        /product.*not.*maintained/i,
        /add.*liquidity.*break.*k/i,
      ];
      return patterns.some(p => p.test(code));
    },
    recommendation: 'Verify invariant after every operation. Use before/after checks.',
  },
  {
    id: 'SOL1657',
    name: 'LP Token Inflation Attack',
    description: 'Identifies LP token minting vulnerable to inflation attacks.',
    severity: 'critical',
    category: 'amm',
    detector: (code: string) => {
      const patterns = [
        /lp.*mint.*proportional.*to.*one/i,
        /single.*sided.*deposit.*mint/i,
        /lp.*token.*no.*minimum/i,
        /mint.*lp.*before.*balance/i,
      ];
      return patterns.some(p => p.test(code));
    },
    recommendation: 'Use geometric mean for LP minting. Require minimum liquidity. Burn dead shares.',
  },
  {
    id: 'SOL1658',
    name: 'Swap Fee Bypass',
    description: 'Detects swap implementations where fees can be bypassed.',
    severity: 'high',
    category: 'amm',
    detector: (code: string) => {
      const patterns = [
        /swap.*route.*no.*fee/i,
        /direct.*pool.*access/i,
        /fee.*exempt.*condition/i,
        /protocol.*fee.*optional/i,
      ];
      return patterns.some(p => p.test(code));
    },
    recommendation: 'Enforce fees at pool level. Make fee bypass impossible.',
  },
  {
    id: 'SOL1659',
    name: 'CLMM Tick Manipulation',
    description: 'Identifies concentrated liquidity tick manipulations.',
    severity: 'high',
    category: 'amm',
    detector: (code: string) => {
      const patterns = [
        /tick.*boundary.*exploit/i,
        /price.*tick.*manipulation/i,
        /concentrated.*range.*attack/i,
        /tick.*spacing.*abuse/i,
      ];
      return patterns.some(p => p.test(code));
    },
    recommendation: 'Validate tick transitions. Add tick manipulation protections.',
  },
  {
    id: 'SOL1660',
    name: 'Virtual Reserve Manipulation',
    description: 'Detects virtual reserve/liquidity manipulation in AMMs.',
    severity: 'high',
    category: 'amm',
    detector: (code: string) => {
      const patterns = [
        /virtual.*reserve.*change/i,
        /phantom.*liquidity/i,
        /fake.*depth.*manipulation/i,
        /virtual.*balance.*exploit/i,
      ];
      return patterns.some(p => p.test(code));
    },
    recommendation: 'Audit virtual reserve mechanisms. Ensure backing for all virtual liquidity.',
  },

  // === ORACLE ADVANCED PATTERNS ===
  {
    id: 'SOL1661',
    name: 'Oracle TWAP Window Too Short',
    description: 'Identifies TWAP oracles with windows too short for manipulation resistance.',
    severity: 'high',
    category: 'oracle',
    detector: (code: string) => {
      const patterns = [
        /twap.*window.*<.*60/i,
        /time.*weighted.*1.*minute/i,
        /short.*twap.*period/i,
        /twap.*=.*30.*seconds/i,
      ];
      return patterns.some(p => p.test(code));
    },
    recommendation: 'Use longer TWAP windows (10+ minutes for critical operations).',
  },
  {
    id: 'SOL1662',
    name: 'Oracle Confidence Interval Ignored',
    description: 'Detects Pyth oracle usage ignoring confidence intervals.',
    severity: 'high',
    category: 'oracle',
    detector: (code: string) => {
      const patterns = [
        /pyth.*price\.price(?!.*conf)/i,
        /oracle.*no.*confidence.*check/i,
        /price.*feed.*ignore.*uncertainty/i,
        /get_price.*without.*conf/i,
      ];
      return patterns.some(p => p.test(code));
    },
    recommendation: 'Always check Pyth confidence intervals. Reject prices with high uncertainty.',
  },
  {
    id: 'SOL1663',
    name: 'Chainlink-Style Answer Stale Check Missing',
    description: 'Identifies oracle price feeds without staleness checks.',
    severity: 'high',
    category: 'oracle',
    detector: (code: string) => {
      const patterns = [
        /latestRoundData.*no.*timestamp/i,
        /oracle.*answer.*no.*age.*check/i,
        /price.*round.*stale.*ok/i,
        /updated.*at.*ignored/i,
      ];
      return patterns.some(p => p.test(code));
    },
    recommendation: 'Check price freshness. Implement heartbeat validation.',
  },
  {
    id: 'SOL1664',
    name: 'Oracle Sequencer Down Risk',
    description: 'Detects missing handling for L2 sequencer downtime.',
    severity: 'high',
    category: 'oracle',
    detector: (code: string) => {
      const patterns = [
        /no.*sequencer.*check/i,
        /l2.*oracle.*direct/i,
        /sequencer.*uptime.*missing/i,
        /optimistic.*rollup.*no.*delay/i,
      ];
      return patterns.some(p => p.test(code));
    },
    recommendation: 'Check sequencer uptime. Add grace period after sequencer restarts.',
  },
  {
    id: 'SOL1665',
    name: 'Oracle Decimal Mismatch',
    description: 'Identifies oracle price decimal mismatches leading to calculation errors.',
    severity: 'critical',
    category: 'oracle',
    detector: (code: string) => {
      const patterns = [
        /price.*decimals.*assumed/i,
        /oracle.*8.*decimals.*hard.*code/i,
        /token.*decimals.*!=.*price.*decimals/i,
        /price.*conversion.*no.*decimal.*check/i,
      ];
      return patterns.some(p => p.test(code));
    },
    recommendation: 'Always fetch and use oracle decimals. Normalize all prices to consistent precision.',
  },

  // === STAKING ADVANCED PATTERNS ===
  {
    id: 'SOL1666',
    name: 'Staking Reward Distribution Fairness',
    description: 'Detects unfair reward distribution in staking contracts.',
    severity: 'high',
    category: 'staking',
    detector: (code: string) => {
      const patterns = [
        /reward.*per.*share.*precision/i,
        /late.*staker.*advantage/i,
        /early.*withdraw.*bonus/i,
        /reward.*calculation.*unfair/i,
      ];
      return patterns.some(p => p.test(code));
    },
    recommendation: 'Use reward-per-token accounting. Implement checkpoints. Ensure time-weighted fairness.',
  },
  {
    id: 'SOL1667',
    name: 'Stake Slashing Conditions Unclear',
    description: 'Identifies staking with unclear or unfair slashing conditions.',
    severity: 'medium',
    category: 'staking',
    detector: (code: string) => {
      const patterns = [
        /slash.*arbitrary.*condition/i,
        /slashing.*admin.*discretion/i,
        /penalty.*undefined/i,
        /stake.*loss.*unclear/i,
      ];
      return patterns.some(p => p.test(code));
    },
    recommendation: 'Define clear slashing conditions. Implement graduated penalties. Add dispute mechanisms.',
  },
  {
    id: 'SOL1668',
    name: 'Unbonding Period Bypass',
    description: 'Detects unbonding/unstaking period bypass vulnerabilities.',
    severity: 'high',
    category: 'staking',
    detector: (code: string) => {
      const patterns = [
        /unbond.*instant.*condition/i,
        /bypass.*unstake.*delay/i,
        /emergency.*withdraw.*no.*penalty/i,
        /cooldown.*skip/i,
      ];
      return patterns.some(p => p.test(code));
    },
    recommendation: 'Enforce unbonding periods. Remove instant unstake capabilities.',
  },
  {
    id: 'SOL1669',
    name: 'Delegation Chain Trust Issue',
    description: 'Identifies delegation patterns with unclear trust chains.',
    severity: 'medium',
    category: 'staking',
    detector: (code: string) => {
      const patterns = [
        /delegate.*to.*delegate/i,
        /chain.*delegation.*uncapped/i,
        /delegatee.*redelegation/i,
        /trust.*chain.*deep/i,
      ];
      return patterns.some(p => p.test(code));
    },
    recommendation: 'Limit delegation depth. Track delegation chains. Validate delegatee trust.',
  },
  {
    id: 'SOL1670',
    name: 'Validator Set Manipulation',
    description: 'Detects liquid staking validator set manipulation risks.',
    severity: 'high',
    category: 'staking',
    detector: (code: string) => {
      const patterns = [
        /validator.*selection.*admin/i,
        /stake.*distribution.*arbitrary/i,
        /validator.*set.*single.*control/i,
        /delegation.*strategy.*changeable/i,
      ];
      return patterns.some(p => p.test(code));
    },
    recommendation: 'Use decentralized validator selection. Implement community governance.',
  },

  // === BRIDGE ADVANCED PATTERNS ===
  {
    id: 'SOL1671',
    name: 'Bridge Guardian Collusion Risk',
    description: 'Identifies bridges with guardian collusion vulnerabilities.',
    severity: 'critical',
    category: 'bridge',
    detector: (code: string) => {
      const patterns = [
        /guardian.*threshold.*low/i,
        /bridge.*2.*of.*3.*multisig/i,
        /validator.*set.*small/i,
        /attestation.*quorum.*weak/i,
      ];
      return patterns.some(p => p.test(code));
    },
    recommendation: 'Use higher thresholds (e.g., 13/19). Diversify guardian set. Add time delays.',
  },
  {
    id: 'SOL1672',
    name: 'Bridge Rate Limit Missing',
    description: 'Detects bridges without rate limiting for large transfers.',
    severity: 'high',
    category: 'bridge',
    detector: (code: string) => {
      const patterns = [
        /bridge.*no.*rate.*limit/i,
        /transfer.*unlimited.*amount/i,
        /large.*bridge.*instant/i,
        /no.*daily.*limit.*bridge/i,
      ];
      return patterns.some(p => p.test(code));
    },
    recommendation: 'Implement transfer rate limits. Add delays for large amounts. Use tiered verification.',
  },
  {
    id: 'SOL1673',
    name: 'Bridge Token Decimals Mismatch',
    description: 'Identifies cross-chain token decimal handling issues.',
    severity: 'high',
    category: 'bridge',
    detector: (code: string) => {
      const patterns = [
        /bridge.*decimals.*different/i,
        /cross.*chain.*decimal.*mismatch/i,
        /wrap.*token.*precision.*loss/i,
        /bridged.*amount.*truncate/i,
      ];
      return patterns.some(p => p.test(code));
    },
    recommendation: 'Handle decimal differences explicitly. Validate amounts don\'t lose precision.',
  },
  {
    id: 'SOL1674',
    name: 'Bridge Canonical Token Confusion',
    description: 'Detects bridges with multiple wrapped token versions.',
    severity: 'high',
    category: 'bridge',
    detector: (code: string) => {
      const patterns = [
        /multiple.*wrapped.*versions/i,
        /non.*canonical.*token.*bridge/i,
        /token.*variant.*confusion/i,
        /wrapped.*token.*not.*official/i,
      ];
      return patterns.some(p => p.test(code));
    },
    recommendation: 'Use only canonical wrapped tokens. Validate token sources.',
  },
  {
    id: 'SOL1675',
    name: 'Bridge Proof Verification Incomplete',
    description: 'Identifies incomplete merkle/state proof verification.',
    severity: 'critical',
    category: 'bridge',
    detector: (code: string) => {
      const patterns = [
        /merkle.*proof.*partial/i,
        /state.*proof.*skip.*validation/i,
        /proof.*verification.*incomplete/i,
        /root.*not.*verified/i,
      ];
      return patterns.some(p => p.test(code));
    },
    recommendation: 'Verify complete proof paths. Validate merkle roots against confirmed blocks.',
  },

  // === TOKEN SECURITY PATTERNS ===
  {
    id: 'SOL1676',
    name: 'Token Mint Authority Not Revoked',
    description: 'Detects tokens with active mint authority risking infinite inflation.',
    severity: 'high',
    category: 'token',
    detector: (code: string) => {
      const patterns = [
        /mint.*authority.*active/i,
        /can.*mint.*more.*tokens/i,
        /supply.*not.*capped/i,
        /inflation.*possible/i,
      ];
      return patterns.some(p => p.test(code));
    },
    recommendation: 'Revoke mint authority after initial supply. Document if inflation is intentional.',
  },
  {
    id: 'SOL1677',
    name: 'Token Freeze Authority Active',
    description: 'Identifies tokens with active freeze authority.',
    severity: 'medium',
    category: 'token',
    detector: (code: string) => {
      const patterns = [
        /freeze.*authority.*set/i,
        /can.*freeze.*accounts/i,
        /token.*freezable/i,
        /account.*freeze.*enabled/i,
      ];
      return patterns.some(p => p.test(code));
    },
    recommendation: 'Revoke freeze authority if not needed. Document freeze authority purpose.',
  },
  {
    id: 'SOL1678',
    name: 'Fee-on-Transfer Token Handling',
    description: 'Detects missing handling for fee-on-transfer tokens.',
    severity: 'high',
    category: 'token',
    detector: (code: string) => {
      const patterns = [
        /transfer.*amount.*=.*received/i,
        /no.*fee.*on.*transfer.*check/i,
        /token.*balance.*delta.*assumed/i,
        /amount.*in.*=.*amount.*out/i,
      ];
      return patterns.some(p => p.test(code));
    },
    recommendation: 'Use balance before/after for fee-on-transfer tokens. Don\'t assume transfer amount equals received.',
  },
  {
    id: 'SOL1679',
    name: 'Rebasing Token Integration Risk',
    description: 'Identifies protocols integrating rebasing tokens incorrectly.',
    severity: 'high',
    category: 'token',
    detector: (code: string) => {
      const patterns = [
        /rebase.*token.*balance.*cached/i,
        /store.*rebase.*amount/i,
        /rebasing.*token.*no.*wrap/i,
        /elastic.*supply.*direct/i,
      ];
      return patterns.some(p => p.test(code));
    },
    recommendation: 'Use wrapped versions of rebasing tokens. Query balance on-demand.',
  },
  {
    id: 'SOL1680',
    name: 'Token Approval Race Condition',
    description: 'Detects token approval patterns vulnerable to race conditions.',
    severity: 'medium',
    category: 'token',
    detector: (code: string) => {
      const patterns = [
        /approve.*after.*approve/i,
        /change.*allowance.*non.*zero/i,
        /approval.*race.*possible/i,
        /allowance.*overwrite/i,
      ];
      return patterns.some(p => p.test(code));
    },
    recommendation: 'Use increase/decrease allowance patterns. Set to zero before changing.',
  },

  // === GOVERNANCE ADVANCED PATTERNS ===
  {
    id: 'SOL1681',
    name: 'Governance Token Snapshot Manipulation',
    description: 'Detects governance snapshots vulnerable to manipulation.',
    severity: 'critical',
    category: 'governance',
    detector: (code: string) => {
      const patterns = [
        /snapshot.*same.*block/i,
        /voting.*power.*instant/i,
        /proposal.*no.*snapshot/i,
        /checkpoint.*manipulation/i,
      ];
      return patterns.some(p => p.test(code));
    },
    recommendation: 'Snapshot voting power before proposal. Use historical balances.',
  },
  {
    id: 'SOL1682',
    name: 'Proposal Griefing Attack',
    description: 'Identifies governance vulnerable to proposal griefing.',
    severity: 'medium',
    category: 'governance',
    detector: (code: string) => {
      const patterns = [
        /proposal.*queue.*full/i,
        /active.*proposal.*limit.*high/i,
        /proposal.*spam.*possible/i,
        /queue.*dos.*attack/i,
      ];
      return patterns.some(p => p.test(code));
    },
    recommendation: 'Limit active proposals per user. Require proposal deposits.',
  },
  {
    id: 'SOL1683',
    name: 'Vote Delegation Exploit',
    description: 'Detects vote delegation patterns that can be exploited.',
    severity: 'high',
    category: 'governance',
    detector: (code: string) => {
      const patterns = [
        /delegate.*chain.*infinite/i,
        /double.*vote.*delegation/i,
        /delegate.*then.*transfer/i,
        /delegation.*loop/i,
      ];
      return patterns.some(p => p.test(code));
    },
    recommendation: 'Prevent circular delegation. Track delegation at time of proposal.',
  },
  {
    id: 'SOL1684',
    name: 'Governance Timelock Too Short',
    description: 'Identifies governance timelocks too short for response.',
    severity: 'high',
    category: 'governance',
    detector: (code: string) => {
      const patterns = [
        /timelock.*<.*24.*hour/i,
        /execution.*delay.*1.*hour/i,
        /short.*governance.*delay/i,
        /quick.*proposal.*execution/i,
      ];
      return patterns.some(p => p.test(code));
    },
    recommendation: 'Use longer timelocks (48+ hours). Add emergency guardian for critical issues.',
  },
  {
    id: 'SOL1685',
    name: 'Quorum Too Low',
    description: 'Detects governance quorum thresholds too low for security.',
    severity: 'high',
    category: 'governance',
    detector: (code: string) => {
      const patterns = [
        /quorum.*<.*5%/i,
        /voting.*threshold.*1%/i,
        /low.*participation.*pass/i,
        /minimal.*quorum.*required/i,
      ];
      return patterns.some(p => p.test(code));
    },
    recommendation: 'Set appropriate quorum (10%+ of circulating supply). Consider dynamic quorum.',
  },

  // === SECURITY INFRASTRUCTURE PATTERNS ===
  {
    id: 'SOL1686',
    name: 'Upgrade Authority Centralized',
    description: 'Identifies programs with centralized upgrade authority.',
    severity: 'high',
    category: 'infrastructure',
    detector: (code: string) => {
      const patterns = [
        /upgrade.*authority.*single/i,
        /program.*owner.*eoa/i,
        /upgrade.*no.*timelock/i,
        /admin.*upgrade.*direct/i,
      ];
      return patterns.some(p => p.test(code));
    },
    recommendation: 'Use multisig upgrade authority. Implement upgrade timelock. Consider immutability.',
  },
  {
    id: 'SOL1687',
    name: 'Missing Access Control List',
    description: 'Detects missing role-based access control.',
    severity: 'high',
    category: 'access-control',
    detector: (code: string) => {
      const patterns = [
        /admin.*only.*single.*check/i,
        /no.*role.*separation/i,
        /all.*functions.*one.*authority/i,
        /missing.*rbac/i,
      ];
      return patterns.some(p => p.test(code));
    },
    recommendation: 'Implement role-based access control. Separate admin, operator, and guardian roles.',
  },
  {
    id: 'SOL1688',
    name: 'Two-Step Transfer Missing',
    description: 'Identifies ownership transfers without two-step process.',
    severity: 'medium',
    category: 'access-control',
    detector: (code: string) => {
      const patterns = [
        /transfer.*owner.*instant/i,
        /single.*step.*ownership/i,
        /set.*authority.*direct/i,
        /owner.*=.*new.*owner/i,
      ];
      return patterns.some(p => p.test(code));
    },
    recommendation: 'Use two-step ownership transfer (propose + accept). Add transfer delay.',
  },
  {
    id: 'SOL1689',
    name: 'Guardian Key Rotation Missing',
    description: 'Detects systems without key rotation capabilities.',
    severity: 'medium',
    category: 'access-control',
    detector: (code: string) => {
      const patterns = [
        /no.*key.*rotation/i,
        /authority.*permanent/i,
        /cannot.*change.*guardian/i,
        /fixed.*admin.*key/i,
      ];
      return patterns.some(p => p.test(code));
    },
    recommendation: 'Implement key rotation mechanisms. Plan for compromised key scenarios.',
  },
  {
    id: 'SOL1690',
    name: 'Pause Mechanism Incomplete',
    description: 'Identifies incomplete pause implementations.',
    severity: 'medium',
    category: 'safety',
    detector: (code: string) => {
      const patterns = [
        /pause.*only.*some.*functions/i,
        /emergency.*stop.*partial/i,
        /withdraw.*while.*paused/i,
        /critical.*function.*ignores.*pause/i,
      ];
      return patterns.some(p => p.test(code));
    },
    recommendation: 'Ensure pause affects all critical functions. Only allow withdrawals when paused.',
  },

  // === ECONOMIC ATTACK PATTERNS ===
  {
    id: 'SOL1691',
    name: 'Dust Attack Vulnerability',
    description: 'Detects systems vulnerable to dust attacks.',
    severity: 'low',
    category: 'economic',
    detector: (code: string) => {
      const patterns = [
        /no.*minimum.*amount/i,
        /dust.*creates.*account/i,
        /spam.*small.*deposits/i,
        /tiny.*transfer.*allowed/i,
      ];
      return patterns.some(p => p.test(code));
    },
    recommendation: 'Implement minimum transaction amounts. Consider account rent implications.',
  },
  {
    id: 'SOL1692',
    name: 'Gas Griefing Attack',
    description: 'Identifies patterns enabling gas griefing attacks.',
    severity: 'medium',
    category: 'economic',
    detector: (code: string) => {
      const patterns = [
        /gas.*forward.*all/i,
        /external.*call.*gas.*unlimited/i,
        /callback.*consumes.*gas/i,
        /griefing.*via.*compute/i,
      ];
      return patterns.some(p => p.test(code));
    },
    recommendation: 'Limit gas forwarded to external calls. Use pull over push patterns.',
  },
  {
    id: 'SOL1693',
    name: 'Economic Incentive Misalignment',
    description: 'Detects protocols with misaligned economic incentives.',
    severity: 'high',
    category: 'economic',
    detector: (code: string) => {
      const patterns = [
        /profit.*from.*failure/i,
        /incentive.*to.*attack/i,
        /reward.*exceeds.*cost/i,
        /griefing.*profitable/i,
      ];
      return patterns.some(p => p.test(code));
    },
    recommendation: 'Ensure attacking is more costly than profitable. Align user and protocol incentives.',
  },
  {
    id: 'SOL1694',
    name: 'Extraction Value Leak',
    description: 'Identifies MEV extraction opportunities leaking protocol value.',
    severity: 'high',
    category: 'mev',
    detector: (code: string) => {
      const patterns = [
        /arbitrage.*opportunity.*created/i,
        /price.*update.*exposed/i,
        /liquidation.*open.*race/i,
        /value.*leak.*to.*searchers/i,
      ];
      return patterns.some(p => p.test(code));
    },
    recommendation: 'Use private transaction submission. Implement MEV protection. Consider auction mechanisms.',
  },
  {
    id: 'SOL1695',
    name: 'Backrunning Vulnerability',
    description: 'Detects transactions vulnerable to backrunning attacks.',
    severity: 'medium',
    category: 'mev',
    detector: (code: string) => {
      const patterns = [
        /state.*change.*backrun/i,
        /predictable.*action.*arbitrage/i,
        /oracle.*update.*trade.*after/i,
        /price.*impact.*extractable/i,
      ];
      return patterns.some(p => p.test(code));
    },
    recommendation: 'Randomize execution. Use commit-reveal for sensitive operations.',
  },

  // === TESTING AND VALIDATION PATTERNS ===
  {
    id: 'SOL1696',
    name: 'Missing Invariant Checks',
    description: 'Identifies critical invariants not checked in code.',
    severity: 'high',
    category: 'validation',
    detector: (code: string) => {
      const patterns = [
        /no.*assert.*invariant/i,
        /unchecked.*protocol.*state/i,
        /missing.*sanity.*check/i,
        /invariant.*not.*enforced/i,
      ];
      return patterns.some(p => p.test(code));
    },
    recommendation: 'Add invariant checks at critical points. Use assert for invariants that should never fail.',
  },
  {
    id: 'SOL1697',
    name: 'Boundary Condition Unchecked',
    description: 'Detects missing boundary condition validation.',
    severity: 'medium',
    category: 'validation',
    detector: (code: string) => {
      const patterns = [
        /boundary.*not.*checked/i,
        /edge.*case.*missing/i,
        /max.*value.*uncapped/i,
        /min.*value.*not.*enforced/i,
      ];
      return patterns.some(p => p.test(code));
    },
    recommendation: 'Validate all boundary conditions. Test edge cases explicitly.',
  },
  {
    id: 'SOL1698',
    name: 'Error Handling Silent Failure',
    description: 'Identifies silent error handling that could mask issues.',
    severity: 'medium',
    category: 'error-handling',
    detector: (code: string) => {
      const patterns = [
        /catch.*{.*}/i,
        /error.*ignored/i,
        /silent.*fail/i,
        /swallow.*exception/i,
        /unwrap_or_default.*critical/i,
      ];
      return patterns.some(p => p.test(code));
    },
    recommendation: 'Handle all errors explicitly. Log or revert on unexpected errors.',
  },
  {
    id: 'SOL1699',
    name: 'Hardcoded Configuration',
    description: 'Detects hardcoded values that should be configurable.',
    severity: 'low',
    category: 'configuration',
    detector: (code: string) => {
      const patterns = [
        /const.*FEE.*=.*\d/i,
        /hardcoded.*threshold/i,
        /magic.*number.*critical/i,
        /fixed.*parameter.*production/i,
      ];
      return patterns.some(p => p.test(code));
    },
    recommendation: 'Make critical parameters configurable. Use upgradeable configuration.',
  },
  {
    id: 'SOL1700',
    name: 'Test Code in Production',
    description: 'Identifies test or debug code that may be in production.',
    severity: 'critical',
    category: 'security',
    detector: (code: string) => {
      const patterns = [
        /TODO.*remove/i,
        /DEBUG.*true/i,
        /test.*mode.*enabled/i,
        /FIXME.*security/i,
        /skip.*validation.*test/i,
      ];
      return patterns.some(p => p.test(code));
    },
    recommendation: 'Remove all test code before deployment. Audit for debug flags.',
  },

  // === ADDITIONAL CRITICAL PATTERNS ===
  {
    id: 'SOL1701',
    name: 'Selfdestruct-like Authority',
    description: 'Detects program authority to drain all funds.',
    severity: 'critical',
    category: 'access-control',
    detector: (code: string) => {
      const patterns = [
        /admin.*withdraw.*all/i,
        /owner.*drain.*treasury/i,
        /emergency.*extract.*funds/i,
        /backdoor.*withdrawal/i,
      ];
      return patterns.some(p => p.test(code));
    },
    recommendation: 'Remove admin drain capabilities. Use timelocked withdrawals with limits.',
  },
  {
    id: 'SOL1702',
    name: 'Signature Malleability',
    description: 'Identifies signature verification vulnerable to malleability.',
    severity: 'high',
    category: 'cryptographic',
    detector: (code: string) => {
      const patterns = [
        /signature.*no.*s.*check/i,
        /ecdsa.*malleable/i,
        /signature.*reuse.*possible/i,
        /recover.*no.*normalize/i,
      ];
      return patterns.some(p => p.test(code));
    },
    recommendation: 'Normalize signatures. Check for low-s values. Use EIP-2 compliant signatures.',
  },
  {
    id: 'SOL1703',
    name: 'Hash Collision Vulnerability',
    description: 'Detects hash usage vulnerable to collision attacks.',
    severity: 'high',
    category: 'cryptographic',
    detector: (code: string) => {
      const patterns = [
        /hash.*packed.*abi/i,
        /keccak.*concat.*variable/i,
        /hash.*length.*prefix.*missing/i,
        /collision.*possible.*hash/i,
      ];
      return patterns.some(p => p.test(code));
    },
    recommendation: 'Use length prefixes. Avoid dynamic types in hash inputs. Consider structured hashing.',
  },
  {
    id: 'SOL1704',
    name: 'Randomness from Future Block',
    description: 'Identifies randomness sourced from future blocks.',
    severity: 'high',
    category: 'randomness',
    detector: (code: string) => {
      const patterns = [
        /random.*future.*slot/i,
        /blockhash.*commit.*reveal/i,
        /randomness.*miner.*influence/i,
        /validator.*manipulate.*random/i,
      ];
      return patterns.some(p => p.test(code));
    },
    recommendation: 'Use VRF for randomness. Implement commit-reveal with bonded stake.',
  },
  {
    id: 'SOL1705',
    name: 'Insufficient Entropy',
    description: 'Detects random number generation with insufficient entropy.',
    severity: 'critical',
    category: 'randomness',
    detector: (code: string) => {
      const patterns = [
        /random.*mod.*small/i,
        /entropy.*limited.*bits/i,
        /weak.*seed.*generation/i,
        /predictable.*random.*source/i,
      ];
      return patterns.some(p => p.test(code));
    },
    recommendation: 'Use sufficient entropy (256 bits). Combine multiple entropy sources.',
  },
  {
    id: 'SOL1706',
    name: 'Cross-Domain Replay',
    description: 'Identifies signatures replayable across domains.',
    severity: 'high',
    category: 'cryptographic',
    detector: (code: string) => {
      const patterns = [
        /signature.*no.*domain/i,
        /message.*no.*chain.*id/i,
        /cross.*chain.*replay/i,
        /missing.*domain.*separator/i,
      ];
      return patterns.some(p => p.test(code));
    },
    recommendation: 'Include chain ID and contract address in signatures. Use EIP-712 typed data.',
  },
  {
    id: 'SOL1707',
    name: 'Permit Front-Running',
    description: 'Detects permit/gasless approval patterns vulnerable to front-running.',
    severity: 'medium',
    category: 'mev',
    detector: (code: string) => {
      const patterns = [
        /permit.*front.*run/i,
        /gasless.*approval.*race/i,
        /signature.*relay.*attack/i,
        /permit.*steal/i,
      ];
      return patterns.some(p => p.test(code));
    },
    recommendation: 'Combine permit with action atomically. Use permit2 with witness data.',
  },
  {
    id: 'SOL1708',
    name: 'Callback Reentrancy',
    description: 'Identifies callback patterns vulnerable to reentrancy.',
    severity: 'high',
    category: 'reentrancy',
    detector: (code: string) => {
      const patterns = [
        /callback.*before.*state/i,
        /onReceive.*reenter/i,
        /hook.*state.*inconsistent/i,
        /external.*callback.*unsafe/i,
      ];
      return patterns.some(p => p.test(code));
    },
    recommendation: 'Use reentrancy guards. Update state before callbacks. Follow CEI pattern.',
  },
  {
    id: 'SOL1709',
    name: 'Read-Only Reentrancy',
    description: 'Detects read-only reentrancy in view functions.',
    severity: 'high',
    category: 'reentrancy',
    detector: (code: string) => {
      const patterns = [
        /view.*function.*reenter/i,
        /read.*only.*reentrancy/i,
        /price.*stale.*during.*callback/i,
        /state.*inconsistent.*view/i,
      ];
      return patterns.some(p => p.test(code));
    },
    recommendation: 'Include view functions in reentrancy guards. Snapshot state before external calls.',
  },
  {
    id: 'SOL1710',
    name: 'Storage Collision in Proxy',
    description: 'Identifies storage collision risks in proxy patterns.',
    severity: 'critical',
    category: 'proxy',
    detector: (code: string) => {
      const patterns = [
        /proxy.*storage.*slot.*overlap/i,
        /implementation.*collision/i,
        /upgrade.*storage.*mismatch/i,
        /delegatecall.*storage.*corrupt/i,
      ];
      return patterns.some(p => p.test(code));
    },
    recommendation: 'Use unstructured storage for proxy data. Follow storage layout conventions.',
  },

  // === FINAL PATTERNS ===
  {
    id: 'SOL1711',
    name: 'Missing Zero Address Check',
    description: 'Detects missing validation for zero/default addresses.',
    severity: 'medium',
    category: 'validation',
    detector: (code: string) => {
      const patterns = [
        /address.*=.*0(?!x)/i,
        /no.*zero.*address.*check/i,
        /default.*pubkey.*accepted/i,
        /system.*program.*as.*authority/i,
      ];
      return patterns.some(p => p.test(code));
    },
    recommendation: 'Validate addresses are not zero/default. Check against system program.',
  },
  {
    id: 'SOL1712',
    name: 'Unchecked External Call Return',
    description: 'Identifies external call return values not checked.',
    severity: 'high',
    category: 'validation',
    detector: (code: string) => {
      const patterns = [
        /invoke.*ignore.*result/i,
        /external.*call.*no.*check/i,
        /cpi.*discard.*return/i,
        /transfer.*result.*unused/i,
      ];
      return patterns.some(p => p.test(code));
    },
    recommendation: 'Always check CPI return values. Revert on unexpected failures.',
  },
  {
    id: 'SOL1713',
    name: 'Missing Sanity Bounds',
    description: 'Detects missing sanity bounds on user inputs.',
    severity: 'medium',
    category: 'validation',
    detector: (code: string) => {
      const patterns = [
        /amount.*u64.*max/i,
        /no.*upper.*bound.*check/i,
        /unlimited.*user.*input/i,
        /sanity.*check.*missing/i,
      ];
      return patterns.some(p => p.test(code));
    },
    recommendation: 'Add reasonable bounds to all user inputs. Validate amounts are within expected ranges.',
  },
  {
    id: 'SOL1714',
    name: 'Missing Deadline Parameter',
    description: 'Identifies time-sensitive operations without deadlines.',
    severity: 'medium',
    category: 'business-logic',
    detector: (code: string) => {
      const patterns = [
        /swap.*no.*deadline/i,
        /trade.*without.*expiry/i,
        /transaction.*no.*timeout/i,
        /order.*eternal/i,
      ];
      return patterns.some(p => p.test(code));
    },
    recommendation: 'Add deadline parameters to time-sensitive operations. Reject expired transactions.',
  },
  {
    id: 'SOL1715',
    name: 'Missing Slippage Protection',
    description: 'Detects swaps/trades without slippage protection.',
    severity: 'high',
    category: 'defi',
    detector: (code: string) => {
      const patterns = [
        /swap.*no.*min.*out/i,
        /trade.*without.*slippage/i,
        /amount.*out.*unchecked/i,
        /no.*minimum.*received/i,
      ];
      return patterns.some(p => p.test(code));
    },
    recommendation: 'Require minimum output amounts. Calculate expected output with tolerance.',
  },
  {
    id: 'SOL1716',
    name: 'Missing Price Impact Check',
    description: 'Identifies large trades without price impact validation.',
    severity: 'high',
    category: 'defi',
    detector: (code: string) => {
      const patterns = [
        /trade.*no.*price.*impact/i,
        /large.*swap.*no.*check/i,
        /impact.*exceeds.*threshold/i,
        /unlimited.*trade.*size/i,
      ];
      return patterns.some(p => p.test(code));
    },
    recommendation: 'Calculate and validate price impact. Warn or reject high-impact trades.',
  },
  {
    id: 'SOL1717',
    name: 'Missing Health Factor Check',
    description: 'Detects lending operations without health factor validation.',
    severity: 'critical',
    category: 'lending',
    detector: (code: string) => {
      const patterns = [
        /borrow.*no.*health.*check/i,
        /withdraw.*collateral.*unsafe/i,
        /position.*health.*unchecked/i,
        /leverage.*no.*liquidation.*check/i,
      ];
      return patterns.some(p => p.test(code));
    },
    recommendation: 'Validate health factor after every position change. Revert if underwater.',
  },
  {
    id: 'SOL1718',
    name: 'Missing Protocol Fee Accrual',
    description: 'Identifies missing protocol fee collection.',
    severity: 'low',
    category: 'business-logic',
    detector: (code: string) => {
      const patterns = [
        /no.*protocol.*fee/i,
        /fee.*not.*collected/i,
        /revenue.*not.*accrued/i,
        /missing.*treasury.*fee/i,
      ];
      return patterns.some(p => p.test(code));
    },
    recommendation: 'Implement protocol fee collection for sustainability.',
  },
  {
    id: 'SOL1719',
    name: 'Missing Withdrawal Limit',
    description: 'Detects protocols without withdrawal rate limits.',
    severity: 'medium',
    category: 'safety',
    detector: (code: string) => {
      const patterns = [
        /withdraw.*unlimited/i,
        /no.*daily.*limit/i,
        /drain.*possible/i,
        /rate.*limit.*missing/i,
      ];
      return patterns.some(p => p.test(code));
    },
    recommendation: 'Implement withdrawal limits. Add time-based rate limiting.',
  },
  {
    id: 'SOL1720',
    name: 'Missing Admin Action Logging',
    description: 'Identifies admin actions without proper logging.',
    severity: 'low',
    category: 'logging',
    detector: (code: string) => {
      const patterns = [
        /admin.*action.*no.*log/i,
        /governance.*silent/i,
        /config.*change.*no.*event/i,
        /authority.*action.*untracked/i,
      ];
      return patterns.some(p => p.test(code));
    },
    recommendation: 'Log all admin actions with detailed events. Enable off-chain monitoring.',
  },
];

export default batchedPatterns48;
