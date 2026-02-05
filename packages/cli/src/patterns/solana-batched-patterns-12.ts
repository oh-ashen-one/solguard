import type { Finding } from '../commands/audit.js';
import type { PatternInput } from './index.js';

// SOL331-SOL350: Additional vulnerability patterns from real exploits and security research

/**
 * SOL331: Hedge Protocol Stability Check
 * Patterns from Hedge Protocol (stablecoin) audits
 */
export function checkHedgeProtocolStability(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  const rustCode = input.rust?.content || '';
  
  // Check for stablecoin/CDP patterns
  if (/cdp|collateral_debt|vault|stability/.test(rustCode)) {
    if (!/health_factor|collateral_ratio|liquidation_threshold/.test(rustCode)) {
      findings.push({
        id: 'SOL331',
        title: 'CDP Health Factor Missing',
        severity: 'critical',
        description: 'CDP/vault without health factor calculation. Hedge Protocol emphasized proper collateralization checks.',
        location: input.path,
        recommendation: 'Calculate health_factor = collateral_value / debt_value. Enforce minimum ratio before withdrawals.'
      });
    }
  }
  
  return findings;
}

/**
 * SOL332: Mean Finance DCA Security
 * Patterns from Mean Finance (DCA protocol) audit
 */
export function checkMeanFinanceDCA(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  const rustCode = input.rust?.content || '';
  
  // Check for DCA/recurring swap patterns
  if (/dca|dollar_cost|recurring|periodic_swap/.test(rustCode)) {
    if (!/min_output|slippage_tolerance/.test(rustCode)) {
      findings.push({
        id: 'SOL332',
        title: 'DCA Slippage Protection Missing',
        severity: 'high',
        description: 'DCA execution without minimum output protection. Mean Finance requires slippage checks on each swap.',
        location: input.path,
        recommendation: 'Set min_output_amount for each DCA execution. Allow users to configure slippage tolerance.'
      });
    }
  }
  
  return findings;
}

/**
 * SOL333: Hubble Lending Pool Isolation
 * Patterns from Hubble Protocol audits
 */
export function checkHubbleLendingIsolation(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  const rustCode = input.rust?.content || '';
  
  // Check for lending pool patterns
  if (/lending.*pool|isolated.*pool|borrow.*market/.test(rustCode)) {
    if (!/pool_type|isolation_mode|collateral_factor/.test(rustCode)) {
      findings.push({
        id: 'SOL333',
        title: 'Lending Pool Isolation Missing',
        severity: 'high',
        description: 'Lending pools without proper isolation. Hubble uses isolated pools to contain risk from volatile assets.',
        location: input.path,
        recommendation: 'Implement pool isolation modes. Risky assets should have separate risk parameters and debt ceilings.'
      });
    }
  }
  
  return findings;
}

/**
 * SOL334: Invariant Protocol Concentrated Liquidity
 * Patterns from Invariant CLMM audit
 */
export function checkInvariantCLMM(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  const rustCode = input.rust?.content || '';
  
  // Check for concentrated liquidity patterns
  if (/concentrated.*liquidity|position.*range|tick_lower.*tick_upper/.test(rustCode)) {
    if (!/liquidity_delta|fee_growth_inside/.test(rustCode)) {
      findings.push({
        id: 'SOL334',
        title: 'CLMM Fee Growth Calculation',
        severity: 'high',
        description: 'Concentrated liquidity without proper fee growth tracking. Invariant audit emphasized fee_growth_inside calculations.',
        location: input.path,
        recommendation: 'Track fee_growth_inside for each position. Calculate fees based on liquidity and tick crossings.'
      });
    }
  }
  
  return findings;
}

/**
 * SOL335: Larix Protocol Liquidation
 * Patterns from Larix lending protocol audit
 */
export function checkLarixLiquidation(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  const rustCode = input.rust?.content || '';
  
  // Check for liquidation patterns
  if (/liquidat|close_factor|seize/.test(rustCode)) {
    if (!/liquidation_bonus|incentive|penalty/.test(rustCode)) {
      findings.push({
        id: 'SOL335',
        title: 'Liquidation Incentive Missing',
        severity: 'high',
        description: 'Liquidation without proper incentive structure. Larix audit emphasized balanced liquidation bonuses.',
        location: input.path,
        recommendation: 'Set appropriate liquidation_bonus (typically 5-15%). Balance between incentivizing liquidators and protecting borrowers.'
      });
    }
  }
  
  return findings;
}

/**
 * SOL336: Light Protocol ZK Proof Verification
 * Patterns from Light Protocol (ZK) audit
 */
export function checkLightProtocolZK(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  const rustCode = input.rust?.content || '';
  
  // Check for ZK proof patterns
  if (/zk|zero_knowledge|proof|groth16|plonk/.test(rustCode)) {
    if (!/verify_proof|pairing|public_input/.test(rustCode)) {
      findings.push({
        id: 'SOL336',
        title: 'ZK Proof Verification Missing',
        severity: 'critical',
        description: 'ZK operations without proper proof verification. Light Protocol audit emphasized on-chain verification.',
        location: input.path,
        recommendation: 'Always verify ZK proofs on-chain. Validate public inputs match expected values. Use audited verification libraries.'
      });
    }
  }
  
  return findings;
}

/**
 * SOL337: Francium Leverage Vault Security
 * Patterns from Francium yield vault audit
 */
export function checkFranciumLeverageVault(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  const rustCode = input.rust?.content || '';
  
  // Check for leveraged vault patterns
  if (/leverage.*vault|yield.*strategy|compound/.test(rustCode)) {
    if (!/debt_ratio|max_leverage|deleverage/.test(rustCode)) {
      findings.push({
        id: 'SOL337',
        title: 'Leverage Vault Risk Controls',
        severity: 'high',
        description: 'Leveraged vault without debt ratio limits. Francium implements max_leverage and emergency deleverage.',
        location: input.path,
        recommendation: 'Set maximum leverage ratios. Implement emergency deleverage when approaching liquidation. Track debt ratios continuously.'
      });
    }
  }
  
  return findings;
}

/**
 * SOL338: Friktion Options Vault Security
 * Patterns from Friktion (DOV) audit
 */
export function checkFriktionOptionsVault(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  const rustCode = input.rust?.content || '';
  
  // Check for options vault patterns
  if (/options|volt|covered_call|put_selling|dov/.test(rustCode)) {
    if (!/epoch|round|pending_deposit/.test(rustCode)) {
      findings.push({
        id: 'SOL338',
        title: 'Options Vault Epoch Management',
        severity: 'high',
        description: 'Options vault without proper epoch/round management. Friktion uses epochs to manage option lifecycles.',
        location: input.path,
        recommendation: 'Implement epoch-based vault management. Handle pending deposits/withdrawals between epochs. Lock funds during active options.'
      });
    }
  }
  
  return findings;
}

/**
 * SOL339: Genopets Staking Duration
 * Patterns from Genopets NFT staking audit
 */
export function checkGenopetsStakingDuration(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  const rustCode = input.rust?.content || '';
  
  // Check for NFT staking duration patterns
  if (/nft.*stake|stake.*nft|staking_duration/.test(rustCode)) {
    if (!/min_stake_time|lock_period|early_unstake_penalty/.test(rustCode)) {
      findings.push({
        id: 'SOL339',
        title: 'NFT Staking Duration Controls',
        severity: 'medium',
        description: 'NFT staking without minimum lock period or early unstake penalty. Genopets implements stake duration requirements.',
        location: input.path,
        recommendation: 'Set minimum staking periods. Apply penalties for early unstaking. Calculate rewards based on actual stake duration.'
      });
    }
  }
  
  return findings;
}

/**
 * SOL340: GooseFX Swap Invariant
 * Patterns from GooseFX swap audit
 */
export function checkGooseFXSwapInvariant(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  const rustCode = input.rust?.content || '';
  
  // Check for swap invariant patterns
  if (/swap|exchange|trade/.test(rustCode) && /reserve|pool/.test(rustCode)) {
    if (!/k\s*=|x\s*\*\s*y|product/.test(rustCode)) {
      findings.push({
        id: 'SOL340',
        title: 'Swap Pool Invariant Check',
        severity: 'high',
        description: 'Swap pool without explicit invariant validation. GooseFX enforces k = x * y invariant on every swap.',
        location: input.path,
        recommendation: 'Validate pool invariant before and after swaps. For constant product: k_after >= k_before (accounting for fees).'
      });
    }
  }
  
  return findings;
}

/**
 * SOL341: Cropper Finance AMM Security
 * Patterns from Cropper AMM audit
 */
export function checkCropperAMMSecurity(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  const rustCode = input.rust?.content || '';
  
  // Check for AMM fee patterns
  if (/amm|swap.*fee|trading_fee/.test(rustCode)) {
    if (!/fee_numerator.*fee_denominator|basis_points/.test(rustCode)) {
      findings.push({
        id: 'SOL341',
        title: 'AMM Fee Precision Issue',
        severity: 'medium',
        description: 'AMM fee calculation may have precision issues. Cropper uses numerator/denominator for precise fee calculation.',
        location: input.path,
        recommendation: 'Use numerator/denominator for fees to avoid precision loss. Calculate: fee = amount * fee_numerator / fee_denominator.'
      });
    }
  }
  
  return findings;
}

/**
 * SOL342: Parrot Protocol Collateral Types
 * Patterns from Parrot stablecoin audit
 */
export function checkParrotCollateralTypes(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  const rustCode = input.rust?.content || '';
  
  // Check for multi-collateral patterns
  if (/collateral.*type|accepted_collateral|mint.*stable/.test(rustCode)) {
    if (!/collateral_factor|debt_ceiling|oracle_source/.test(rustCode)) {
      findings.push({
        id: 'SOL342',
        title: 'Multi-Collateral Risk Parameters',
        severity: 'high',
        description: 'Multi-collateral system without per-asset risk parameters. Parrot uses different collateral factors and debt ceilings.',
        location: input.path,
        recommendation: 'Set per-collateral: collateral_factor, debt_ceiling, oracle_source, liquidation_bonus. Adjust for asset volatility.'
      });
    }
  }
  
  return findings;
}

/**
 * SOL343: Aldrin DEX Order Matching
 * Patterns from Aldrin DEX audit
 */
export function checkAldrinOrderMatching(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  const rustCode = input.rust?.content || '';
  
  // Check for order matching patterns
  if (/order.*match|match.*engine|fill_or_kill|ioc/.test(rustCode)) {
    if (!/partial_fill|remaining_quantity/.test(rustCode)) {
      findings.push({
        id: 'SOL343',
        title: 'Order Partial Fill Handling',
        severity: 'medium',
        description: 'Order matching without proper partial fill handling. Aldrin handles remaining quantities after partial fills.',
        location: input.path,
        recommendation: 'Track filled_quantity and remaining_quantity. Handle FOK (fill-or-kill) and IOC (immediate-or-cancel) order types.'
      });
    }
  }
  
  return findings;
}

/**
 * SOL344: Audius Storage Slot Security
 * Patterns from Audius storage/delegation audit
 */
export function checkAudiusStorageSlot(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  const rustCode = input.rust?.content || '';
  
  // Check for storage delegation patterns
  if (/storage.*slot|delegat.*storage|content_node/.test(rustCode)) {
    if (!/slot_ownership|authorized_node/.test(rustCode)) {
      findings.push({
        id: 'SOL344',
        title: 'Storage Slot Authorization',
        severity: 'high',
        description: 'Storage delegation without proper slot ownership checks. Audius requires authorized node validation.',
        location: input.path,
        recommendation: 'Verify storage slot ownership. Check node authorization before accepting delegated storage operations.'
      });
    }
  }
  
  return findings;
}

/**
 * SOL345: Swim Protocol Cross-Chain Message
 * Patterns from Swim cross-chain bridge audit
 */
export function checkSwimCrossChainMessage(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  const rustCode = input.rust?.content || '';
  
  // Check for cross-chain message patterns
  if (/cross_chain|bridge.*message|wormhole.*message/.test(rustCode)) {
    if (!/payload_hash|sequence_number|emitter_chain/.test(rustCode)) {
      findings.push({
        id: 'SOL345',
        title: 'Cross-Chain Message Validation',
        severity: 'critical',
        description: 'Cross-chain messaging without proper payload validation. Swim implements payload_hash and sequence validation.',
        location: input.path,
        recommendation: 'Validate message payload_hash, sequence_number, emitter_chain, and emitter_address. Prevent message replay.'
      });
    }
  }
  
  return findings;
}

/**
 * SOL346: Synthetify Synthetic Asset Minting
 * Patterns from Synthetify synthetic asset audit
 */
export function checkSynthetifySyntheticMinting(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  const rustCode = input.rust?.content || '';
  
  // Check for synthetic asset patterns
  if (/synthetic|synth|mint.*asset|debt_pool/.test(rustCode)) {
    if (!/global_debt|debt_share|c_ratio/.test(rustCode)) {
      findings.push({
        id: 'SOL346',
        title: 'Synthetic Asset Debt Pool',
        severity: 'high',
        description: 'Synthetic asset minting without global debt tracking. Synthetify uses debt shares and global debt pool.',
        location: input.path,
        recommendation: 'Track global debt pool. Calculate user debt_share proportionally. Enforce minimum c_ratio (collateralization ratio).'
      });
    }
  }
  
  return findings;
}

/**
 * SOL347: UXD Redeemable Asset Peg
 * Patterns from UXD stablecoin audit
 */
export function checkUXDRedeemablePeg(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  const rustCode = input.rust?.content || '';
  
  // Check for redeemable stablecoin patterns
  if (/redeem|burn.*stable|peg|backing/.test(rustCode)) {
    if (!/insurance_fund|backing_ratio|depeg_threshold/.test(rustCode)) {
      findings.push({
        id: 'SOL347',
        title: 'Redeemable Stablecoin Peg Mechanism',
        severity: 'high',
        description: 'Redeemable stablecoin without insurance fund or depeg protection. UXD uses insurance fund for backing.',
        location: input.path,
        recommendation: 'Maintain insurance fund for undercollateralization. Set depeg_threshold for emergency measures. Track backing_ratio continuously.'
      });
    }
  }
  
  return findings;
}

/**
 * SOL348: Wormhole VAA Parsing
 * Detailed VAA (Verified Action Approval) parsing security
 */
export function checkWormholeVAAParsing(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  const rustCode = input.rust?.content || '';
  
  // Check for VAA parsing patterns
  if (/vaa|verified_action|guardian.*signature/.test(rustCode)) {
    if (!/guardian_set_index|signatures\[|quorum/.test(rustCode)) {
      findings.push({
        id: 'SOL348',
        title: 'Wormhole VAA Guardian Quorum',
        severity: 'critical',
        description: 'VAA processing without proper guardian quorum verification. Must verify sufficient guardian signatures.',
        location: input.path,
        recommendation: 'Verify guardian_set_index is current. Check quorum (2/3 + 1 guardians). Validate each guardian signature.'
      });
    }
  }
  
  return findings;
}

/**
 * SOL349: Debridge Message Verification
 * Patterns from Debridge cross-chain audit
 */
export function checkDebridgeMessageVerification(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  const rustCode = input.rust?.content || '';
  
  // Check for cross-chain submission patterns
  if (/submission|claim|bridge.*transfer/.test(rustCode)) {
    if (!/submission_id|is_used|prevent_double/.test(rustCode)) {
      findings.push({
        id: 'SOL349',
        title: 'Bridge Submission Double-Claim Prevention',
        severity: 'critical',
        description: 'Bridge claim without double-claim prevention. Debridge uses submission_id to prevent replays.',
        location: input.path,
        recommendation: 'Mark submission_id as used after claim. Check is_used before processing. Use PDA derived from submission_id.'
      });
    }
  }
  
  return findings;
}

/**
 * SOL350: Cashmere Multisig Threshold
 * Patterns from Cashmere multisig audit
 */
export function checkCashmereMultisigThreshold(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  const rustCode = input.rust?.content || '';
  
  // Check for multisig threshold patterns
  if (/multisig|threshold|m_of_n/.test(rustCode)) {
    if (!/threshold\s*<=\s*owners|threshold.*len/.test(rustCode)) {
      findings.push({
        id: 'SOL350',
        title: 'Multisig Threshold Bounds',
        severity: 'critical',
        description: 'Multisig without threshold bounds validation. Cashmere enforces threshold <= owner_count and threshold > 0.',
        location: input.path,
        recommendation: 'Validate: 0 < threshold <= owners.len(). Prevent threshold changes that would lock funds.'
      });
    }
  }
  
  return findings;
}
