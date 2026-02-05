/**
 * SolGuard Security Patterns - Batch 10 (SOL291-SOL350)
 * Real exploit patterns from 2022-2025 major Solana hacks
 * Based on: Helius "Solana Hacks Complete History", Sec3 2025 Report
 */

import type { Finding } from '../commands/audit.js';
import type { PatternInput } from './index.js';

// ============================================================================
// WORMHOLE EXPLOIT PATTERNS ($326M - Feb 2022)
// Root cause: Signature verification flaw in bridge program
// ============================================================================

// SOL291: Guardian Signature Verification Bypass
export function checkGuardianSignatureBypass(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  if (!input.rust) return findings;
  const content = input.rust.content;
  
  // Check for guardian/validator signature verification
  if (/guardian|validator|verify_signature|signature_set/gi.test(content)) {
    // Missing complete verification chain
    if (!/verify_signatures.*guardian_set|guardian.*quorum|threshold.*check/gi.test(content)) {
      findings.push({
        id: 'SOL291',
        severity: 'critical',
        title: 'Wormhole-Style Guardian Signature Bypass',
        description: 'Guardian/validator signature verification without complete chain validation. The $326M Wormhole hack exploited a gap in signature verification that allowed forging valid signatures.',
        location: input.path,
        recommendation: 'Implement complete signature verification chain: verify guardian set validity, check quorum threshold, validate each signature against expected signers.',
      });
    }
  }
  
  return findings;
}

// SOL292: Cross-Chain Message Validation
export function checkCrossChainMessageValidation(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  if (!input.rust) return findings;
  const content = input.rust.content;
  
  if (/bridge|cross_chain|message.*payload|vaa|relay/gi.test(content)) {
    if (!/verify_message|validate_payload|check_source_chain|emitter_check/gi.test(content)) {
      findings.push({
        id: 'SOL292',
        severity: 'critical',
        title: 'Unvalidated Cross-Chain Message',
        description: 'Cross-chain messages without proper validation can allow attackers to forge messages and mint tokens without proper collateral.',
        location: input.path,
        recommendation: 'Validate message origin chain, emitter address, sequence number, and payload integrity before processing.',
      });
    }
  }
  
  return findings;
}

// SOL293: Wrapped Token Mint Without Collateral Check
export function checkWrappedTokenMintCollateral(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  if (!input.rust) return findings;
  const content = input.rust.content;
  
  if (/wrapped|mint.*token|create.*token|bridge.*mint/gi.test(content)) {
    if (!/collateral.*check|verify.*deposit|lock.*before.*mint|reserve.*balance/gi.test(content)) {
      findings.push({
        id: 'SOL293',
        severity: 'critical',
        title: 'Token Minting Without Collateral Verification',
        description: 'Minting wrapped tokens without verifying collateral existence allows infinite mint attacks.',
        location: input.path,
        recommendation: 'Always verify collateral is locked before minting. Check source chain finality and collateral amount.',
      });
    }
  }
  
  return findings;
}

// ============================================================================
// CASHIO EXPLOIT PATTERNS ($52.8M - Mar 2022)
// Root cause: Missing collateral mint validation (infinite mint glitch)
// ============================================================================

// SOL294: Missing Collateral Mint Validation
export function checkCollateralMintValidation(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  if (!input.rust) return findings;
  const content = input.rust.content;
  
  if (/collateral|backing|arrow|lp.*token|pool.*token/gi.test(content)) {
    if (!/verify.*mint|check.*mint.*address|whitelist.*mint|valid_mints/gi.test(content)) {
      findings.push({
        id: 'SOL294',
        severity: 'critical',
        title: 'Cashio-Style Missing Mint Validation',
        description: 'The $52.8M Cashio hack exploited missing mint field validation in collateral accounts. Attacker created fake accounts with worthless collateral to mint 2 billion tokens.',
        location: input.path,
        recommendation: 'Always validate the mint field of LP tokens and collateral accounts against a whitelist. Implement root-of-trust validation.',
      });
    }
  }
  
  return findings;
}

// SOL295: Root of Trust Violation
export function checkRootOfTrust(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  if (!input.rust) return findings;
  const content = input.rust.content;
  
  // Check for nested account validation
  if (/nested.*account|sub.*account|arrow|wrapped.*pool/gi.test(content)) {
    if (!/root.*trust|parent.*verify|chain.*validation|recursive.*check/gi.test(content)) {
      findings.push({
        id: 'SOL295',
        severity: 'critical',
        title: 'Missing Root of Trust Validation',
        description: 'Nested account structures without root-of-trust validation. Cashio was exploited because attackers could create fake nested accounts that passed individual checks but lacked valid root.',
        location: input.path,
        recommendation: 'Implement chain-of-custody validation from leaf accounts back to a trusted root. Verify each link in the chain.',
      });
    }
  }
  
  return findings;
}

// SOL296: Infinite Mint Protection
export function checkInfiniteMintProtection(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  if (!input.rust) return findings;
  const content = input.rust.content;
  
  if (/mint_to|mint.*amount|token.*mint|create.*mint/gi.test(content)) {
    // Check for mint limits and supply tracking
    if (!/max.*supply|mint.*limit|total.*supply.*check|cap/gi.test(content)) {
      findings.push({
        id: 'SOL296',
        severity: 'high',
        title: 'Missing Infinite Mint Protection',
        description: 'Token minting without supply caps or limits can enable infinite mint attacks.',
        location: input.path,
        recommendation: 'Implement maximum supply checks, rate limiting, and supply tracking for all mint operations.',
      });
    }
  }
  
  return findings;
}

// ============================================================================
// MANGO MARKETS EXPLOIT PATTERNS ($116M - Oct 2022)
// Root cause: Oracle manipulation through leveraged perpetual trades
// ============================================================================

// SOL297: Oracle Price Manipulation (Mango-Style)
export function checkOraclePriceManipulation(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  if (!input.rust) return findings;
  const content = input.rust.content;
  
  if (/oracle|price.*feed|get.*price|fetch.*price/gi.test(content)) {
    // Check for manipulation protections
    if (!/twap|time.*weighted|confidence|deviation.*check|staleness|multiple.*oracle/gi.test(content)) {
      findings.push({
        id: 'SOL297',
        severity: 'critical',
        title: 'Mango-Style Oracle Manipulation Vulnerability',
        description: 'The $116M Mango Markets hack exploited spot price oracles without TWAP or manipulation protections. Attacker pumped token price 24x to borrow against inflated collateral.',
        location: input.path,
        recommendation: 'Use TWAP for price feeds, check price confidence intervals, implement deviation limits, use multiple oracle sources.',
      });
    }
  }
  
  return findings;
}

// SOL298: Collateral Value Manipulation
export function checkCollateralValueManipulation(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  if (!input.rust) return findings;
  const content = input.rust.content;
  
  if (/collateral.*value|borrow.*against|leverage|margin/gi.test(content)) {
    if (!/max.*leverage|collateral.*cap|position.*limit|exposure.*limit/gi.test(content)) {
      findings.push({
        id: 'SOL298',
        severity: 'critical',
        title: 'Unbounded Collateral Leverage',
        description: 'Borrowing against collateral without leverage limits allows attackers to manipulate collateral value and drain liquidity.',
        location: input.path,
        recommendation: 'Implement leverage caps, position limits, and per-asset exposure limits.',
      });
    }
  }
  
  return findings;
}

// SOL299: Self-Trading Detection
export function checkSelfTradingDetection(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  if (!input.rust) return findings;
  const content = input.rust.content;
  
  if (/trade|swap|exchange|order.*match/gi.test(content)) {
    if (!/self.*trade|wash.*trade|same.*owner|prevent.*self/gi.test(content)) {
      findings.push({
        id: 'SOL299',
        severity: 'high',
        title: 'Missing Self-Trading Prevention',
        description: 'Mango exploit used self-trading between two accounts to manipulate prices. Self-trading can artificially inflate volumes and prices.',
        location: input.path,
        recommendation: 'Detect and prevent trades between accounts controlled by the same entity. Add wash trading detection.',
      });
    }
  }
  
  return findings;
}

// SOL300: Perpetual Futures Position Limits
export function checkPerpPositionLimits(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  if (!input.rust) return findings;
  const content = input.rust.content;
  
  if (/perpetual|perp|futures|leverage.*position/gi.test(content)) {
    if (!/position.*limit|max.*position|open.*interest.*cap|notional.*limit/gi.test(content)) {
      findings.push({
        id: 'SOL300',
        severity: 'critical',
        title: 'Missing Perpetual Position Limits',
        description: 'Perpetual/futures positions without size limits allow market manipulation through concentrated positions.',
        location: input.path,
        recommendation: 'Implement per-user position limits, maximum open interest caps, and notional value limits.',
      });
    }
  }
  
  return findings;
}

// ============================================================================
// CREMA FINANCE EXPLOIT PATTERNS ($8.8M - Jul 2022)
// Root cause: Fake tick account bypassed owner verification in CLMM
// ============================================================================

// SOL301: CLMM Tick Account Validation
export function checkCLMMTickValidation(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  if (!input.rust) return findings;
  const content = input.rust.content;
  
  if (/tick|clmm|concentrated.*liquidity|price.*range/gi.test(content)) {
    if (!/verify.*tick.*owner|tick.*account.*check|pda.*tick|tick.*seeds/gi.test(content)) {
      findings.push({
        id: 'SOL301',
        severity: 'critical',
        title: 'Crema-Style CLMM Tick Account Bypass',
        description: 'The $8.8M Crema Finance hack used fake tick accounts that bypassed owner verification. Attacker manipulated fee data to drain liquidity pools.',
        location: input.path,
        recommendation: 'Validate tick accounts are PDAs derived from expected seeds. Verify tick account ownership matches the pool.',
      });
    }
  }
  
  return findings;
}

// SOL302: Flash Loan Fee Manipulation
export function checkFlashLoanFeeManipulation(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  if (!input.rust) return findings;
  const content = input.rust.content;
  
  if (/flash.*loan|instant.*borrow|same.*block.*repay/gi.test(content)) {
    if (!/fee.*snapshot|pre.*flash.*state|invariant.*check.*after/gi.test(content)) {
      findings.push({
        id: 'SOL302',
        severity: 'critical',
        title: 'Flash Loan Fee Manipulation',
        description: 'Flash loans without state snapshots allow manipulation of fee calculations. Crema was exploited by manipulating fee data during flash loan.',
        location: input.path,
        recommendation: 'Snapshot all relevant state before flash loan. Verify state invariants after repayment.',
      });
    }
  }
  
  return findings;
}

// SOL303: Liquidity Pool Fee Drain
export function checkLiquidityPoolFeeDrain(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  if (!input.rust) return findings;
  const content = input.rust.content;
  
  if (/claim.*fee|collect.*fee|withdraw.*fee|fee.*reward/gi.test(content)) {
    if (!/fee.*earned.*check|position.*fee.*track|pro.*rata.*fee/gi.test(content)) {
      findings.push({
        id: 'SOL303',
        severity: 'high',
        title: 'Fee Claim Without Earned Verification',
        description: 'Fee claims without verifying earned amount allow attackers to claim fees they did not earn.',
        location: input.path,
        recommendation: 'Track fee accrual per position. Verify claimed amount matches earned amount based on liquidity provided.',
      });
    }
  }
  
  return findings;
}

// ============================================================================
// NIRVANA FINANCE EXPLOIT PATTERNS ($3.5M - Jul 2022)
// Root cause: Bonding curve manipulation via flash loan
// ============================================================================

// SOL304: Bonding Curve Flash Loan Attack
export function checkBondingCurveFlashLoan(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  if (!input.rust) return findings;
  const content = input.rust.content;
  
  if (/bonding.*curve|price.*curve|mint.*price|token.*curve/gi.test(content)) {
    if (!/flash.*loan.*protect|same.*block.*check|cooldown|rate.*limit/gi.test(content)) {
      findings.push({
        id: 'SOL304',
        severity: 'critical',
        title: 'Nirvana-Style Bonding Curve Flash Loan Attack',
        description: 'The $3.5M Nirvana hack exploited bonding curve via flash loan to mint tokens at manipulated prices. Attacker drained stablecoins from the protocol.',
        location: input.path,
        recommendation: 'Add flash loan protection to bonding operations: same-block purchase limits, price impact caps, cooldowns.',
      });
    }
  }
  
  return findings;
}

// SOL305: Price Impact Without Limits
export function checkPriceImpactLimits(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  if (!input.rust) return findings;
  const content = input.rust.content;
  
  if (/swap|exchange|trade|buy|sell/gi.test(content)) {
    if (!/price.*impact|slippage.*limit|max.*impact|min.*output/gi.test(content)) {
      findings.push({
        id: 'SOL305',
        severity: 'high',
        title: 'Missing Price Impact Limits',
        description: 'Swaps without price impact limits allow manipulation of token prices within a single transaction.',
        location: input.path,
        recommendation: 'Implement maximum price impact per transaction. Add slippage protection and minimum output checks.',
      });
    }
  }
  
  return findings;
}

// ============================================================================
// SLOPE WALLET EXPLOIT PATTERNS ($8M - Aug 2022)
// Root cause: Private key leaked through centralized logging
// ============================================================================

// SOL306: Private Key Logging (Slope-Style)
export function checkPrivateKeyLogging(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  if (!input.rust) return findings;
  const content = input.rust.content;
  
  // Check for potential key exposure
  if (/log|print|debug|trace|send.*server|transmit/gi.test(content)) {
    if (/private.*key|secret.*key|seed.*phrase|mnemonic|keypair/gi.test(content)) {
      findings.push({
        id: 'SOL306',
        severity: 'critical',
        title: 'Slope-Style Private Key Exposure',
        description: 'The $8M Slope wallet hack leaked private keys through centralized logging. Never log or transmit private keys.',
        location: input.path,
        recommendation: 'Never log, print, or transmit private keys or seed phrases. Use secure enclaves for key operations.',
      });
    }
  }
  
  return findings;
}

// SOL307: Centralized Key Storage
export function checkCentralizedKeyStorage(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  if (!input.rust) return findings;
  const content = input.rust.content;
  
  if (/store.*key|save.*key|persist.*key|key.*storage/gi.test(content)) {
    if (!/encrypt|hardware.*wallet|secure.*enclave|local.*only/gi.test(content)) {
      findings.push({
        id: 'SOL307',
        severity: 'critical',
        title: 'Insecure Key Storage',
        description: 'Private keys stored without encryption or on centralized servers are vulnerable to theft.',
        location: input.path,
        recommendation: 'Encrypt private keys locally. Never store keys on centralized servers. Use hardware wallets when possible.',
      });
    }
  }
  
  return findings;
}

// ============================================================================
// AUDIUS GOVERNANCE EXPLOIT PATTERNS ($6.1M - Jul 2022)
// Root cause: Governance proposal validation bypass
// ============================================================================

// SOL308: Governance Proposal Validation Bypass
export function checkGovernanceProposalValidation(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  if (!input.rust) return findings;
  const content = input.rust.content;
  
  if (/governance|proposal|vote|dao|ballot/gi.test(content)) {
    if (!/proposal.*validate|check.*proposer|quorum.*verify|vote.*threshold/gi.test(content)) {
      findings.push({
        id: 'SOL308',
        severity: 'critical',
        title: 'Audius-Style Governance Bypass',
        description: 'The $6.1M Audius hack bypassed governance validation to execute malicious proposals and drain treasury.',
        location: input.path,
        recommendation: 'Validate proposer eligibility, vote counting, quorum requirements. Add timelocks for proposal execution.',
      });
    }
  }
  
  return findings;
}

// SOL309: Treasury Permission Manipulation
export function checkTreasuryPermissionManipulation(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  if (!input.rust) return findings;
  const content = input.rust.content;
  
  if (/treasury|vault.*admin|fund.*permission|withdraw.*auth/gi.test(content)) {
    if (!/timelock|multisig|delay.*period|guardian.*approval/gi.test(content)) {
      findings.push({
        id: 'SOL309',
        severity: 'critical',
        title: 'Treasury Permission Without Timelock',
        description: 'Treasury permission changes without timelock allow instant fund drainage if governance is compromised.',
        location: input.path,
        recommendation: 'Add mandatory timelock for treasury permission changes. Require multisig for large withdrawals.',
      });
    }
  }
  
  return findings;
}

// SOL310: Proposal Execution Without Delay
export function checkProposalExecutionDelay(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  if (!input.rust) return findings;
  const content = input.rust.content;
  
  if (/execute.*proposal|proposal.*execute|enact.*vote/gi.test(content)) {
    if (!/execution.*delay|timelock|cool.*off|waiting.*period/gi.test(content)) {
      findings.push({
        id: 'SOL310',
        severity: 'high',
        title: 'Instant Proposal Execution',
        description: 'Proposals that execute immediately after passing prevent community from reacting to malicious proposals.',
        location: input.path,
        recommendation: 'Add execution delay (timelock) between proposal passing and execution. Allow emergency cancellation.',
      });
    }
  }
  
  return findings;
}

// ============================================================================
// RAYDIUM EXPLOIT PATTERNS ($4.4M - Dec 2022)
// Root cause: Admin key compromise
// ============================================================================

// SOL311: Admin Key Compromise Protection
export function checkAdminKeyCompromiseProtection(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  if (!input.rust) return findings;
  const content = input.rust.content;
  
  if (/admin|owner|authority|super.*user/gi.test(content)) {
    if (!/multisig|multi.*sig|threshold.*sig|m.*of.*n/gi.test(content)) {
      findings.push({
        id: 'SOL311',
        severity: 'critical',
        title: 'Single Admin Key Vulnerability',
        description: 'The $4.4M Raydium hack exploited a compromised single admin key. Single admin keys are single points of failure.',
        location: input.path,
        recommendation: 'Use multisig (e.g., 3-of-5) for admin operations. Never use single keys for critical functions.',
      });
    }
  }
  
  return findings;
}

// SOL312: Pool Admin Operations Without Multisig
export function checkPoolAdminMultisig(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  if (!input.rust) return findings;
  const content = input.rust.content;
  
  if (/pool.*admin|pool.*authority|withdraw.*pool|drain.*pool/gi.test(content)) {
    if (!/multisig|timelock|delay|guardian/gi.test(content)) {
      findings.push({
        id: 'SOL312',
        severity: 'critical',
        title: 'Pool Admin Without Protection',
        description: 'Pool admin operations without multisig or timelock allow instant drainage if admin key is compromised.',
        location: input.path,
        recommendation: 'Require multisig for pool admin operations. Add timelock for large withdrawals.',
      });
    }
  }
  
  return findings;
}

// ============================================================================
// PUMP.FUN EXPLOIT PATTERNS ($1.9M - May 2024)
// Root cause: Insider/employee exploit
// ============================================================================

// SOL313: Insider Trading Protection
export function checkInsiderTradingProtection(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  if (!input.rust) return findings;
  const content = input.rust.content;
  
  if (/launch|bonding|early.*access|pre.*sale/gi.test(content)) {
    if (!/lock.*period|vesting|trading.*restriction|insider.*blackout/gi.test(content)) {
      findings.push({
        id: 'SOL313',
        severity: 'high',
        title: 'Pump.fun-Style Insider Trading Vulnerability',
        description: 'The $1.9M Pump.fun hack was an insider exploit. Launch mechanisms without trading restrictions enable insider trading.',
        location: input.path,
        recommendation: 'Add lock periods for team/insider tokens. Implement vesting schedules. Restrict early access trading.',
      });
    }
  }
  
  return findings;
}

// SOL314: Employee Access Control
export function checkEmployeeAccessControl(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  if (!input.rust) return findings;
  const content = input.rust.content;
  
  if (/internal|employee|team|operator/gi.test(content)) {
    if (!/role.*based|permission.*level|access.*log|audit.*trail/gi.test(content)) {
      findings.push({
        id: 'SOL314',
        severity: 'high',
        title: 'Insufficient Employee Access Controls',
        description: 'Internal access without role-based permissions and audit trails enables insider exploits.',
        location: input.path,
        recommendation: 'Implement role-based access control. Log all privileged operations. Require multiple approvals for sensitive actions.',
      });
    }
  }
  
  return findings;
}

// ============================================================================
// DEXX EXPLOIT PATTERNS ($30M - Nov 2024)
// Root cause: Private key leak from centralized storage
// ============================================================================

// SOL315: DEXX-Style Private Key Leak
export function checkDEXXStyleKeyLeak(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  if (!input.rust) return findings;
  const content = input.rust.content;
  
  if (/user.*key|custodial|hot.*wallet|centralized.*wallet/gi.test(content)) {
    if (!/hardware.*security|hsm|secure.*module|cold.*storage/gi.test(content)) {
      findings.push({
        id: 'SOL315',
        severity: 'critical',
        title: 'DEXX-Style Centralized Key Risk',
        description: 'The $30M DEXX hack leaked user private keys from centralized storage. Custodial key storage is a major attack vector.',
        location: input.path,
        recommendation: 'Use HSMs or secure enclaves for key storage. Minimize hot wallet exposure. Implement cold storage for large amounts.',
      });
    }
  }
  
  return findings;
}

// ============================================================================
// SEC3 2025 REPORT PATTERNS - Business Logic (38.5% of vulnerabilities)
// ============================================================================

// SOL316: State Machine Violation
export function checkStateMachineViolation(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  if (!input.rust) return findings;
  const content = input.rust.content;
  
  if (/state|status|phase|stage/gi.test(content)) {
    if (!/valid.*transition|allowed.*state|state.*machine|from.*to/gi.test(content)) {
      findings.push({
        id: 'SOL316',
        severity: 'high',
        title: 'Missing State Machine Validation',
        description: 'State transitions without validation allow bypassing required steps or revisiting completed states.',
        location: input.path,
        recommendation: 'Define explicit state machine with allowed transitions. Validate current state before any transition.',
      });
    }
  }
  
  return findings;
}

// SOL317: Incomplete Business Logic
export function checkIncompleteBusinessLogic(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  if (!input.rust) return findings;
  const content = input.rust.content;
  
  if (/todo|fixme|hack|temporary|placeholder/gi.test(content)) {
    findings.push({
      id: 'SOL317',
      severity: 'medium',
      title: 'Incomplete Business Logic Markers',
      description: 'TODO/FIXME markers indicate incomplete implementation that may have security gaps.',
      location: input.path,
      recommendation: 'Complete all TODO/FIXME items before deployment. Review for missing edge case handling.',
    });
  }
  
  return findings;
}

// SOL318: Missing Edge Case Handling
export function checkEdgeCaseHandling(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  if (!input.rust) return findings;
  const content = input.rust.content;
  
  if (/if\s+|match\s+|when/gi.test(content)) {
    if (!/else|default|_\s*=>/gi.test(content)) {
      findings.push({
        id: 'SOL318',
        severity: 'medium',
        title: 'Missing Default Case Handling',
        description: 'Control flow without default/else cases may miss edge cases that attackers can exploit.',
        location: input.path,
        recommendation: 'Always handle default cases. Use exhaustive matching in Rust.',
      });
    }
  }
  
  return findings;
}

// SOL319: Invariant Violation
export function checkInvariantViolation(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  if (!input.rust) return findings;
  const content = input.rust.content;
  
  if (/pool|vault|reserve|balance/gi.test(content)) {
    if (!/invariant|assert.*eq|check.*balance|verify.*sum/gi.test(content)) {
      findings.push({
        id: 'SOL319',
        severity: 'high',
        title: 'Missing Invariant Checks',
        description: 'Financial operations without invariant verification can lead to fund loss or theft.',
        location: input.path,
        recommendation: 'Define and verify invariants (e.g., sum of user balances == pool total) after each operation.',
      });
    }
  }
  
  return findings;
}

// SOL320: Economic Attack Vector
export function checkEconomicAttackVector(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  if (!input.rust) return findings;
  const content = input.rust.content;
  
  if (/reward|yield|interest|profit|return/gi.test(content)) {
    if (!/cap|limit|max.*rate|sustainable|buffer/gi.test(content)) {
      findings.push({
        id: 'SOL320',
        severity: 'high',
        title: 'Unbounded Economic Rewards',
        description: 'Reward mechanisms without caps can be economically exploited to drain protocol funds.',
        location: input.path,
        recommendation: 'Cap reward rates. Implement sustainable tokenomics. Add protocol reserves as buffer.',
      });
    }
  }
  
  return findings;
}

// ============================================================================
// SEC3 2025 REPORT PATTERNS - Input Validation (25% of vulnerabilities)
// ============================================================================

// SOL321: Unchecked Account Data Size
export function checkAccountDataSize(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  if (!input.rust) return findings;
  const content = input.rust.content;
  
  if (/data\.len|data_len|account.*size/gi.test(content)) {
    if (!/expected.*size|min.*size|size.*check|len\s*==|len\s*>=|len\s*<=/gi.test(content)) {
      findings.push({
        id: 'SOL321',
        severity: 'high',
        title: 'Unchecked Account Data Size',
        description: 'Reading account data without size validation can cause buffer overflows or panics.',
        location: input.path,
        recommendation: 'Validate account data size matches expected size before deserialization.',
      });
    }
  }
  
  return findings;
}

// SOL322: Missing Instruction Data Validation
export function checkInstructionDataValidation(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  if (!input.rust) return findings;
  const content = input.rust.content;
  
  if (/instruction.*data|ix.*data|deserialize/gi.test(content)) {
    if (!/validate.*input|check.*range|bounds.*check|sanitize/gi.test(content)) {
      findings.push({
        id: 'SOL322',
        severity: 'high',
        title: 'Missing Instruction Data Validation',
        description: 'Instruction data without validation can contain malicious values that trigger unexpected behavior.',
        location: input.path,
        recommendation: 'Validate all instruction data fields. Check ranges, formats, and relationships between fields.',
      });
    }
  }
  
  return findings;
}

// SOL323: Array Index Out of Bounds
export function checkArrayIndexBounds(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  if (!input.rust) return findings;
  const content = input.rust.content;
  
  if (/\[\s*\w+\s*\]|get\s*\(|index/gi.test(content)) {
    if (!/get\s*\(.*\)\.ok_or|bounds.*check|\.get\s*\(|checked.*index/gi.test(content)) {
      findings.push({
        id: 'SOL323',
        severity: 'high',
        title: 'Potential Array Index Out of Bounds',
        description: 'Direct array indexing without bounds checking can cause panics or undefined behavior.',
        location: input.path,
        recommendation: 'Use .get() with proper error handling instead of direct indexing.',
      });
    }
  }
  
  return findings;
}

// SOL324: Untrusted String Input
export function checkUntrustedStringInput(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  if (!input.rust) return findings;
  const content = input.rust.content;
  
  if (/String|str|&str|name|symbol|metadata/gi.test(content)) {
    if (!/max.*len|truncate|validate.*utf|sanitize.*string/gi.test(content)) {
      findings.push({
        id: 'SOL324',
        severity: 'medium',
        title: 'Untrusted String Input',
        description: 'String inputs without length limits or sanitization can cause DoS or storage exhaustion.',
        location: input.path,
        recommendation: 'Limit string lengths. Validate UTF-8 encoding. Sanitize special characters.',
      });
    }
  }
  
  return findings;
}

// SOL325: Missing Zero Check
export function checkMissingZeroCheck(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  if (!input.rust) return findings;
  const content = input.rust.content;
  
  if (/amount|quantity|count|number/gi.test(content)) {
    if (!/>\s*0|!=\s*0|non.*zero|require.*positive/gi.test(content)) {
      findings.push({
        id: 'SOL325',
        severity: 'medium',
        title: 'Missing Zero Amount Check',
        description: 'Operations with zero amounts may have unexpected effects or enable economic exploits.',
        location: input.path,
        recommendation: 'Validate amounts are greater than zero where appropriate.',
      });
    }
  }
  
  return findings;
}

// ============================================================================
// SEC3 2025 REPORT PATTERNS - Access Control (19% of vulnerabilities)
// ============================================================================

// SOL326: Missing Permission Check
export function checkMissingPermissionCheck(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  if (!input.rust) return findings;
  const content = input.rust.content;
  
  if (/update|modify|change|set|delete|remove/gi.test(content)) {
    if (!/has_authority|is_admin|check_permission|require_auth|signer/gi.test(content)) {
      findings.push({
        id: 'SOL326',
        severity: 'critical',
        title: 'Missing Permission Check on State Change',
        description: 'State-changing operations without permission checks allow unauthorized modifications.',
        location: input.path,
        recommendation: 'Verify caller has appropriate permissions before any state-changing operation.',
      });
    }
  }
  
  return findings;
}

// SOL327: Privilege Escalation
export function checkPrivilegeEscalation(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  if (!input.rust) return findings;
  const content = input.rust.content;
  
  if (/set.*admin|grant.*role|add.*authority|promote/gi.test(content)) {
    if (!/only.*admin|super.*admin|root.*check|highest.*privilege/gi.test(content)) {
      findings.push({
        id: 'SOL327',
        severity: 'critical',
        title: 'Potential Privilege Escalation',
        description: 'Role/permission granting without proper authorization allows privilege escalation attacks.',
        location: input.path,
        recommendation: 'Only highest privilege level should grant roles. Implement role hierarchy checks.',
      });
    }
  }
  
  return findings;
}

// SOL328: Missing Account Close Authorization
export function checkAccountCloseAuthorization(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  if (!input.rust) return findings;
  const content = input.rust.content;
  
  if (/close.*account|delete.*account|remove.*account/gi.test(content)) {
    if (!/owner.*check|authority.*check|has_one|constraint/gi.test(content)) {
      findings.push({
        id: 'SOL328',
        severity: 'high',
        title: 'Unauthorized Account Closure',
        description: 'Account closure without ownership verification allows attackers to close other users accounts.',
        location: input.path,
        recommendation: 'Verify account owner or authority before closing. Send lamports to rightful owner.',
      });
    }
  }
  
  return findings;
}

// ============================================================================
// SEC3 2025 REPORT PATTERNS - Data Integrity & Arithmetic (8.9%)
// ============================================================================

// SOL329: Precision Loss in Division
export function checkPrecisionLoss(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  if (!input.rust) return findings;
  const content = input.rust.content;
  
  if (/\/\s*\d+|checked_div|divide/gi.test(content)) {
    if (!/scale|precision|decimal|multiply.*before.*divide/gi.test(content)) {
      findings.push({
        id: 'SOL329',
        severity: 'high',
        title: 'Precision Loss in Division',
        description: 'Integer division without scaling causes precision loss that compounds over time.',
        location: input.path,
        recommendation: 'Use fixed-point arithmetic. Multiply before dividing. Use appropriate decimal scaling.',
      });
    }
  }
  
  return findings;
}

// SOL330: Rounding Direction Exploitation
export function checkRoundingDirectionExploitation(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  if (!input.rust) return findings;
  const content = input.rust.content;
  
  if (/round|floor|ceil|truncate/gi.test(content)) {
    if (!/favor.*protocol|round.*down.*user|consistent.*rounding/gi.test(content)) {
      findings.push({
        id: 'SOL330',
        severity: 'medium',
        title: 'Inconsistent Rounding Direction',
        description: 'Inconsistent rounding can be exploited to extract value through many small transactions.',
        location: input.path,
        recommendation: 'Always round in favor of the protocol for withdrawals, in favor of users for deposits.',
      });
    }
  }
  
  return findings;
}

// ============================================================================
// SEC3 2025 REPORT PATTERNS - DoS & Liveness (8.5%)
// ============================================================================

// SOL331: Unbounded Loop DoS
export function checkUnboundedLoopDoS(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  if (!input.rust) return findings;
  const content = input.rust.content;
  
  if (/for\s+\w+\s+in|while|loop|iter/gi.test(content)) {
    if (!/max.*iter|limit|take\s*\(|bounded|pagination/gi.test(content)) {
      findings.push({
        id: 'SOL331',
        severity: 'high',
        title: 'Unbounded Loop DoS Risk',
        description: 'Loops without bounds can exceed compute limits, causing transaction failures.',
        location: input.path,
        recommendation: 'Limit loop iterations. Use pagination for large datasets. Add early termination conditions.',
      });
    }
  }
  
  return findings;
}

// SOL332: Compute Unit Exhaustion
export function checkComputeUnitExhaustion(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  if (!input.rust) return findings;
  const content = input.rust.content;
  
  if (/recursive|deeply.*nested|complex.*calc/gi.test(content)) {
    if (!/compute.*budget|cu.*limit|gas.*estimate/gi.test(content)) {
      findings.push({
        id: 'SOL332',
        severity: 'medium',
        title: 'Compute Unit Exhaustion Risk',
        description: 'Complex operations without compute budget awareness can fail unexpectedly.',
        location: input.path,
        recommendation: 'Estimate compute usage. Split complex operations across multiple transactions.',
      });
    }
  }
  
  return findings;
}

// SOL333: Account Bloat DoS
export function checkAccountBloatDoS(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  if (!input.rust) return findings;
  const content = input.rust.content;
  
  if (/vec.*push|append|extend|grow/gi.test(content)) {
    if (!/max.*capacity|limit.*size|bounded.*vec|pruning/gi.test(content)) {
      findings.push({
        id: 'SOL333',
        severity: 'medium',
        title: 'Account Data Bloat Risk',
        description: 'Unbounded data growth in accounts can exceed size limits or make operations too expensive.',
        location: input.path,
        recommendation: 'Limit collection sizes. Implement pruning. Consider using separate accounts for scalability.',
      });
    }
  }
  
  return findings;
}

// ============================================================================
// ADDITIONAL CRITICAL PATTERNS
// ============================================================================

// SOL334: Time-Based Attack Window
export function checkTimeBasedAttackWindow(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  if (!input.rust) return findings;
  const content = input.rust.content;
  
  if (/clock|timestamp|time|block.*slot|slot/gi.test(content)) {
    if (!/window|tolerance|deviation|safety.*margin/gi.test(content)) {
      findings.push({
        id: 'SOL334',
        severity: 'high',
        title: 'Time-Based Attack Window',
        description: 'Time-dependent logic without safety margins can be exploited through timing attacks.',
        location: input.path,
        recommendation: 'Add time tolerances. Use slot-based timing with margins. Consider validator manipulation.',
      });
    }
  }
  
  return findings;
}

// SOL335: Missing Reentrancy Guard
export function checkReentrancyGuard(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  if (!input.rust) return findings;
  const content = input.rust.content;
  
  if (/invoke|cpi|call.*program|cross.*program/gi.test(content)) {
    if (!/reentrancy.*guard|lock|mutex|in_progress|executing/gi.test(content)) {
      findings.push({
        id: 'SOL335',
        severity: 'high',
        title: 'Missing Reentrancy Guard',
        description: 'CPI calls without reentrancy protection allow callback attacks.',
        location: input.path,
        recommendation: 'Implement reentrancy guard pattern. Update state before CPI. Check for recursive calls.',
      });
    }
  }
  
  return findings;
}

// SOL336: Token Account Authority Confusion
export function checkTokenAccountAuthorityConfusion(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  if (!input.rust) return findings;
  const content = input.rust.content;
  
  if (/token.*account|associated.*token|ata/gi.test(content)) {
    if (!/verify.*owner|check.*authority|validate.*owner/gi.test(content)) {
      findings.push({
        id: 'SOL336',
        severity: 'high',
        title: 'Token Account Authority Confusion',
        description: 'Token operations without verifying account authority can allow unauthorized transfers.',
        location: input.path,
        recommendation: 'Verify token account owner matches expected authority before transfers.',
      });
    }
  }
  
  return findings;
}

// SOL337: Missing Slippage Protection
export function checkSlippageProtection(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  if (!input.rust) return findings;
  const content = input.rust.content;
  
  if (/swap|exchange|trade|convert/gi.test(content)) {
    if (!/min.*amount|slippage|expected.*output|price.*limit/gi.test(content)) {
      findings.push({
        id: 'SOL337',
        severity: 'high',
        title: 'Missing Slippage Protection',
        description: 'Swaps without slippage protection expose users to sandwich attacks.',
        location: input.path,
        recommendation: 'Add minimum output amount parameter. Implement deadline checks.',
      });
    }
  }
  
  return findings;
}

// SOL338: Deadline Expiry Check
export function checkDeadlineExpiryCheck(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  if (!input.rust) return findings;
  const content = input.rust.content;
  
  if (/swap|trade|order|transaction/gi.test(content)) {
    if (!/deadline|expiry|valid.*until|timeout/gi.test(content)) {
      findings.push({
        id: 'SOL338',
        severity: 'medium',
        title: 'Missing Transaction Deadline',
        description: 'Transactions without deadlines can be held by validators and executed at unfavorable times.',
        location: input.path,
        recommendation: 'Add transaction deadline parameter. Reject expired transactions.',
      });
    }
  }
  
  return findings;
}

// SOL339: Missing Event Emission
export function checkMissingEventEmission(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  if (!input.rust) return findings;
  const content = input.rust.content;
  
  if (/transfer|mint|burn|stake|unstake|withdraw|deposit/gi.test(content)) {
    if (!/emit!|event|log|msg!/gi.test(content)) {
      findings.push({
        id: 'SOL339',
        severity: 'low',
        title: 'Missing Event Emission',
        description: 'Important state changes without events make monitoring and auditing difficult.',
        location: input.path,
        recommendation: 'Emit events for all significant state changes.',
      });
    }
  }
  
  return findings;
}

// SOL340: PDA Derivation Collision
export function checkPDADerivationCollision(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  if (!input.rust) return findings;
  const content = input.rust.content;
  
  if (/find_program_address|create_program_address|pda/gi.test(content)) {
    if (!/unique.*seed|collision.*check|distinct.*seeds/gi.test(content)) {
      findings.push({
        id: 'SOL340',
        severity: 'high',
        title: 'PDA Derivation Collision Risk',
        description: 'PDA seeds without sufficient uniqueness can collide, causing account conflicts.',
        location: input.path,
        recommendation: 'Use unique seed combinations (e.g., include user pubkey, type identifier, nonce).',
      });
    }
  }
  
  return findings;
}

// ============================================================================
// Export all pattern checkers
// ============================================================================

export const batch10Patterns = [
  checkGuardianSignatureBypass,
  checkCrossChainMessageValidation,
  checkWrappedTokenMintCollateral,
  checkCollateralMintValidation,
  checkRootOfTrust,
  checkInfiniteMintProtection,
  checkOraclePriceManipulation,
  checkCollateralValueManipulation,
  checkSelfTradingDetection,
  checkPerpPositionLimits,
  checkCLMMTickValidation,
  checkFlashLoanFeeManipulation,
  checkLiquidityPoolFeeDrain,
  checkBondingCurveFlashLoan,
  checkPriceImpactLimits,
  checkPrivateKeyLogging,
  checkCentralizedKeyStorage,
  checkGovernanceProposalValidation,
  checkTreasuryPermissionManipulation,
  checkProposalExecutionDelay,
  checkAdminKeyCompromiseProtection,
  checkPoolAdminMultisig,
  checkInsiderTradingProtection,
  checkEmployeeAccessControl,
  checkDEXXStyleKeyLeak,
  checkStateMachineViolation,
  checkIncompleteBusinessLogic,
  checkEdgeCaseHandling,
  checkInvariantViolation,
  checkEconomicAttackVector,
  checkAccountDataSize,
  checkInstructionDataValidation,
  checkArrayIndexBounds,
  checkUntrustedStringInput,
  checkMissingZeroCheck,
  checkMissingPermissionCheck,
  checkPrivilegeEscalation,
  checkAccountCloseAuthorization,
  checkPrecisionLoss,
  checkRoundingDirectionExploitation,
  checkUnboundedLoopDoS,
  checkComputeUnitExhaustion,
  checkAccountBloatDoS,
  checkTimeBasedAttackWindow,
  checkReentrancyGuard,
  checkTokenAccountAuthorityConfusion,
  checkSlippageProtection,
  checkDeadlineExpiryCheck,
  checkMissingEventEmission,
  checkPDADerivationCollision,
];

// Export pattern metadata
export const batch10PatternInfo = {
  startId: 291,
  endId: 340,
  count: 50,
  categories: [
    'Wormhole Exploit Patterns',
    'Cashio Exploit Patterns', 
    'Mango Markets Exploit Patterns',
    'Crema Finance Exploit Patterns',
    'Nirvana Finance Exploit Patterns',
    'Slope Wallet Exploit Patterns',
    'Audius Governance Exploit Patterns',
    'Raydium Exploit Patterns',
    'Pump.fun Exploit Patterns',
    'DEXX Exploit Patterns',
    'Sec3 2025 Business Logic Patterns',
    'Sec3 2025 Input Validation Patterns',
    'Sec3 2025 Access Control Patterns',
    'Sec3 2025 Data Integrity Patterns',
    'Sec3 2025 DoS Patterns',
  ],
};
