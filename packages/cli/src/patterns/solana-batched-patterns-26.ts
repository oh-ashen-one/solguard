import type { Finding } from '../commands/audit.js';
import type { PatternInput } from './index.js';

// SOL745-SOL764: Advanced DeFi Protocol Security Patterns (Feb 5 2026 5:30AM)
// Source: sannykim/solsec + Trail of Bits DeFi Security

function createFinding(id: string, name: string, severity: Finding['severity'], file: string, line: number, details: string): Finding {
  return { id, name, severity, file, line, details };
}

// SOL745: AMM Invariant Check Missing
export function checkAmmInvariantMissing(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  const content = input.sourceCode;
  const lines = content.split('\n');

  // AMM swap functions without invariant checks (k = x * y should be preserved)
  const ammPatterns = [
    /fn\s+swap\s*\(/i,
    /fn\s+exchange\s*\(/i,
    /fn\s+trade\s*\(/i,
  ];

  const invariantPatterns = [
    /constant_product/i,
    /invariant/i,
    /k\s*=\s*x\s*\*\s*y/,
    /product_before/i,
    /product_after/i,
  ];

  lines.forEach((line, idx) => {
    for (const pattern of ammPatterns) {
      if (pattern.test(line)) {
        // Check surrounding context for invariant validation
        const contextStart = Math.max(0, idx - 5);
        const contextEnd = Math.min(lines.length, idx + 30);
        const context = lines.slice(contextStart, contextEnd).join('\n');
        
        const hasInvariantCheck = invariantPatterns.some(p => p.test(context));
        if (!hasInvariantCheck) {
          findings.push(createFinding(
            'SOL745',
            'AMM Invariant Check Missing',
            'high',
            input.filePath,
            idx + 1,
            'AMM swap function found without constant product invariant validation. This could allow value extraction attacks.'
          ));
        }
        break;
      }
    }
  });

  return findings;
}

// SOL746: Flash Loan Callback Validation Missing
export function checkFlashLoanCallbackValidation(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  const content = input.sourceCode;
  const lines = content.split('\n');

  const flashLoanPatterns = [
    /flash_loan/i,
    /flash_borrow/i,
    /FlashLoan/,
  ];

  lines.forEach((line, idx) => {
    for (const pattern of flashLoanPatterns) {
      if (pattern.test(line)) {
        const contextEnd = Math.min(lines.length, idx + 20);
        const context = lines.slice(idx, contextEnd).join('\n');
        
        // Check for callback validation
        if (!/callback_program/.test(context) && !/verify_callback/.test(context)) {
          findings.push(createFinding(
            'SOL746',
            'Flash Loan Callback Validation Missing',
            'critical',
            input.filePath,
            idx + 1,
            'Flash loan implementation without callback program validation. Attackers could use malicious callbacks.'
          ));
        }
        break;
      }
    }
  });

  return findings;
}

// SOL747: Liquidity Pool Share Calculation Precision Loss
export function checkLpSharePrecisionLoss(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  const content = input.sourceCode;
  const lines = content.split('\n');

  // Pattern: division before multiplication in LP share calculations
  const divBeforeMulPattern = /(\w+)\s*\/\s*(\w+)\s*\*\s*(\w+)/;
  const lpContextPatterns = [
    /lp_token/i,
    /share/i,
    /mint_amount/i,
    /pool_token/i,
  ];

  lines.forEach((line, idx) => {
    if (divBeforeMulPattern.test(line)) {
      const contextStart = Math.max(0, idx - 10);
      const contextEnd = Math.min(lines.length, idx + 10);
      const context = lines.slice(contextStart, contextEnd).join('\n');
      
      const isLpContext = lpContextPatterns.some(p => p.test(context));
      if (isLpContext) {
        findings.push(createFinding(
          'SOL747',
          'LP Share Calculation Precision Loss',
          'high',
          input.filePath,
          idx + 1,
          'Division before multiplication in LP share calculation can cause precision loss. Multiply first, then divide.'
        ));
      }
    }
  });

  return findings;
}

// SOL748: Lending Protocol Interest Rate Model Manipulation
export function checkInterestRateManipulation(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  const content = input.sourceCode;
  const lines = content.split('\n');

  const interestPatterns = [
    /interest_rate/i,
    /borrow_rate/i,
    /utilization_rate/i,
  ];

  lines.forEach((line, idx) => {
    for (const pattern of interestPatterns) {
      if (pattern.test(line)) {
        const contextEnd = Math.min(lines.length, idx + 15);
        const context = lines.slice(idx, contextEnd).join('\n');
        
        // Check for rate capping
        if (!/max_rate/.test(context) && !/rate_cap/.test(context) && !/\.min\(/.test(context)) {
          findings.push(createFinding(
            'SOL748',
            'Interest Rate Model Missing Cap',
            'medium',
            input.filePath,
            idx + 1,
            'Interest rate calculation without maximum cap. Extreme utilization could cause unfair rates.'
          ));
        }
        break;
      }
    }
  });

  return findings;
}

// SOL749: Collateral Factor Manipulation Risk
export function checkCollateralFactorManipulation(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  const content = input.sourceCode;
  const lines = content.split('\n');

  const collateralPatterns = [
    /collateral_factor/i,
    /ltv/i,
    /loan_to_value/i,
  ];

  lines.forEach((line, idx) => {
    for (const pattern of collateralPatterns) {
      if (pattern.test(line)) {
        const contextEnd = Math.min(lines.length, idx + 20);
        const context = lines.slice(idx, contextEnd).join('\n');
        
        // Check for timelock on collateral factor changes
        if (!/timelock/.test(context) && !/delay/.test(context)) {
          findings.push(createFinding(
            'SOL749',
            'Collateral Factor Change Without Timelock',
            'high',
            input.filePath,
            idx + 1,
            'Collateral factor can be changed without timelock. Governance attacks could instantly liquidate users.'
          ));
        }
        break;
      }
    }
  });

  return findings;
}

// SOL750: Liquidation Bonus Exploitation
export function checkLiquidationBonusExploit(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  const content = input.sourceCode;
  const lines = content.split('\n');

  if (/liquidation_bonus/i.test(content) || /liquidator_reward/i.test(content)) {
    // Check for self-liquidation prevention
    if (!/liquidator\s*!=\s*borrower/i.test(content) && !/self_liquidation/i.test(content)) {
      findings.push(createFinding(
        'SOL750',
        'Self-Liquidation Not Prevented',
        'medium',
        input.filePath,
        1,
        'Liquidation function may allow self-liquidation to exploit liquidation bonus.'
      ));
    }
  }

  return findings;
}

// SOL751: Oracle Price Staleness Not Checked
export function checkOraclePriceStaleness(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  const content = input.sourceCode;
  const lines = content.split('\n');

  const oraclePatterns = [
    /get_price/i,
    /oracle\.price/i,
    /price_feed/i,
    /pyth/i,
    /switchboard/i,
  ];

  lines.forEach((line, idx) => {
    for (const pattern of oraclePatterns) {
      if (pattern.test(line)) {
        const contextEnd = Math.min(lines.length, idx + 10);
        const context = lines.slice(idx, contextEnd).join('\n');
        
        // Check for staleness validation
        if (!/stale/.test(context) && !/last_update/.test(context) && !/timestamp/.test(context)) {
          findings.push(createFinding(
            'SOL751',
            'Oracle Price Staleness Not Checked',
            'high',
            input.filePath,
            idx + 1,
            'Oracle price used without staleness check. Stale prices can be exploited for arbitrage.'
          ));
        }
        break;
      }
    }
  });

  return findings;
}

// SOL752: Yield Aggregator Harvest Timing Attack
export function checkHarvestTimingAttack(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  const content = input.sourceCode;
  const lines = content.split('\n');

  const harvestPatterns = [
    /fn\s+harvest/i,
    /fn\s+compound/i,
    /fn\s+claim_rewards/i,
  ];

  lines.forEach((line, idx) => {
    for (const pattern of harvestPatterns) {
      if (pattern.test(line)) {
        const contextEnd = Math.min(lines.length, idx + 25);
        const context = lines.slice(idx, contextEnd).join('\n');
        
        // Check for harvest delay or access control
        if (!/last_harvest/.test(context) && !/harvest_delay/.test(context)) {
          findings.push(createFinding(
            'SOL752',
            'Harvest Function Missing Timing Protection',
            'medium',
            input.filePath,
            idx + 1,
            'Harvest function without timing protection. MEV bots could front-run harvests.'
          ));
        }
        break;
      }
    }
  });

  return findings;
}

// SOL753: Vault Share Inflation Attack
export function checkVaultShareInflation(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  const content = input.sourceCode;
  const lines = content.split('\n');

  // ERC4626-style vault share inflation attack
  if (/vault/i.test(content) && /share/i.test(content)) {
    const hasMinDeposit = /min_deposit/i.test(content) || /minimum_deposit/i.test(content);
    const hasInitialShares = /initial_share/i.test(content) || /dead_shares/i.test(content);
    
    if (!hasMinDeposit && !hasInitialShares) {
      findings.push(createFinding(
        'SOL753',
        'Vault Share Inflation Attack Possible',
        'high',
        input.filePath,
        1,
        'Vault implementation may be vulnerable to share inflation attack. Consider minimum deposit or dead shares.'
      ));
    }
  }

  return findings;
}

// SOL754: Bonding Curve Manipulation
export function checkBondingCurveManipulation(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  const content = input.sourceCode;
  const lines = content.split('\n');

  if (/bonding_curve/i.test(content) || /BondingCurve/.test(content)) {
    // Check for slippage protection
    if (!/slippage/.test(content) && !/min_out/.test(content) && !/max_in/.test(content)) {
      findings.push(createFinding(
        'SOL754',
        'Bonding Curve Missing Slippage Protection',
        'high',
        input.filePath,
        1,
        'Bonding curve without slippage protection is vulnerable to sandwich attacks.'
      ));
    }
    
    // Check for flash loan protection (like Nirvana exploit)
    if (!/flash_loan_guard/.test(content) && !/same_slot/.test(content)) {
      findings.push(createFinding(
        'SOL754',
        'Bonding Curve Flash Loan Vulnerable',
        'critical',
        input.filePath,
        1,
        'Bonding curve may be vulnerable to flash loan manipulation (Nirvana-style attack).'
      ));
    }
  }

  return findings;
}

// SOL755: Perpetual Protocol Funding Rate Manipulation
export function checkFundingRateManipulation(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  const content = input.sourceCode;
  const lines = content.split('\n');

  if (/funding_rate/i.test(content) || /perpetual/i.test(content)) {
    // Check for funding rate caps
    if (!/max_funding/.test(content) && !/funding_cap/.test(content)) {
      findings.push(createFinding(
        'SOL755',
        'Perpetual Funding Rate Missing Cap',
        'high',
        input.filePath,
        1,
        'Funding rate calculation without cap. Extreme rates could liquidate positions unfairly.'
      ));
    }
  }

  return findings;
}

// SOL756: Options Protocol Greeks Manipulation
export function checkOptionsGreeksManipulation(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  const content = input.sourceCode;
  const lines = content.split('\n');

  const optionsPatterns = [
    /option/i,
    /strike_price/i,
    /expiry/i,
    /call|put/i,
  ];

  const hasOptionsContext = optionsPatterns.filter(p => p.test(content)).length >= 2;
  
  if (hasOptionsContext) {
    // Check for IV manipulation protection
    if (!/implied_volatility/.test(content) && !/iv_oracle/.test(content)) {
      findings.push(createFinding(
        'SOL756',
        'Options Protocol Missing IV Oracle',
        'medium',
        input.filePath,
        1,
        'Options protocol without external IV oracle may be vulnerable to volatility manipulation.'
      ));
    }
  }

  return findings;
}

// SOL757: Prediction Market Resolution Manipulation
export function checkPredictionMarketResolution(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  const content = input.sourceCode;
  const lines = content.split('\n');

  if (/prediction_market/i.test(content) || /outcome/i.test(content)) {
    // Check for oracle-based resolution
    if (/resolve/i.test(content)) {
      if (!/oracle/.test(content) && !/uma/.test(content) && !/dispute/.test(content)) {
        findings.push(createFinding(
          'SOL757',
          'Prediction Market Centralized Resolution',
          'high',
          input.filePath,
          1,
          'Prediction market resolution without oracle or dispute mechanism is vulnerable to manipulation.'
        ));
      }
    }
  }

  return findings;
}

// SOL758: Staking Reward Dilution Attack
export function checkStakingRewardDilution(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  const content = input.sourceCode;
  const lines = content.split('\n');

  if (/staking/i.test(content) && /reward/i.test(content)) {
    // Check for deposit/withdraw same block protection
    if (!/cooldown/.test(content) && !/lockup/.test(content) && !/unbonding/.test(content)) {
      findings.push(createFinding(
        'SOL758',
        'Staking Reward Dilution Possible',
        'medium',
        input.filePath,
        1,
        'Staking without cooldown allows flash-staking to dilute rewards for long-term stakers.'
      ));
    }
  }

  return findings;
}

// SOL759: Cross-Margin Liquidation Cascade
export function checkCrossMarginCascade(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  const content = input.sourceCode;
  const lines = content.split('\n');

  if (/cross_margin/i.test(content) || /portfolio_margin/i.test(content)) {
    // Check for cascade protection
    if (!/circuit_breaker/.test(content) && !/max_liquidation/.test(content)) {
      findings.push(createFinding(
        'SOL759',
        'Cross-Margin Liquidation Cascade Risk',
        'high',
        input.filePath,
        1,
        'Cross-margin system without circuit breaker could cause liquidation cascades.'
      ));
    }
  }

  return findings;
}

// SOL760: Governance Token Flash Loan Voting
export function checkGovernanceFlashLoanVoting(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  const content = input.sourceCode;
  const lines = content.split('\n');

  if (/governance/i.test(content) && /vote/i.test(content)) {
    // Check for snapshot or checkpoint
    if (!/snapshot/.test(content) && !/checkpoint/.test(content) && !/voting_escrow/.test(content)) {
      findings.push(createFinding(
        'SOL760',
        'Governance Vulnerable to Flash Loan Voting',
        'critical',
        input.filePath,
        1,
        'Governance without snapshots is vulnerable to flash loan voting attacks (DAO proposal attack).'
      ));
    }
  }

  return findings;
}

// SOL761: NFT Royalty Bypass
export function checkNftRoyaltyBypass(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  const content = input.sourceCode;
  const lines = content.split('\n');

  if (/nft/i.test(content) && /transfer/i.test(content)) {
    // Check for royalty enforcement
    if (!/royalty/.test(content) && !/creator_fee/.test(content)) {
      findings.push(createFinding(
        'SOL761',
        'NFT Royalty Enforcement Missing',
        'info',
        input.filePath,
        1,
        'NFT transfer without royalty enforcement. Consider implementing programmable royalties.'
      ));
    }
  }

  return findings;
}

// SOL762: Token-2022 Transfer Hook Reentrancy
export function checkToken2022TransferHookReentrancy(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  const content = input.sourceCode;
  const lines = content.split('\n');

  if (/transfer_hook/i.test(content) || /TransferHook/.test(content)) {
    // Check for reentrancy guard
    if (!/reentrancy_guard/.test(content) && !/is_processing/.test(content)) {
      findings.push(createFinding(
        'SOL762',
        'Token-2022 Transfer Hook Reentrancy Risk',
        'high',
        input.filePath,
        1,
        'Transfer hook without reentrancy protection could be exploited via recursive calls.'
      ));
    }
  }

  return findings;
}

// SOL763: cNFT Merkle Tree Overflow
export function checkCnftMerkleTreeOverflow(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  const content = input.sourceCode;
  const lines = content.split('\n');

  if (/compressed_nft/i.test(content) || /merkle_tree/i.test(content)) {
    // Check for tree capacity validation
    if (!/max_depth/.test(content) && !/tree_capacity/.test(content)) {
      findings.push(createFinding(
        'SOL763',
        'cNFT Merkle Tree Capacity Not Validated',
        'medium',
        input.filePath,
        1,
        'Compressed NFT merkle tree without capacity check could overflow.'
      ));
    }
  }

  return findings;
}

// SOL764: Restaking Protocol Slashing Cascade
export function checkRestakingSlashingCascade(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  const content = input.sourceCode;
  const lines = content.split('\n');

  if (/restaking/i.test(content) || /liquid_staking/i.test(content)) {
    // Check for slashing protection
    if (/slash/i.test(content)) {
      if (!/max_slash/.test(content) && !/slash_cap/.test(content)) {
        findings.push(createFinding(
          'SOL764',
          'Restaking Slashing Cascade Risk',
          'high',
          input.filePath,
          1,
          'Restaking protocol without slashing cap could cause cascade failures across protocols.'
        ));
      }
    }
  }

  return findings;
}

export const batchedPatterns26 = [
  { id: 'SOL745', name: 'AMM Invariant Check Missing', severity: 'high' as const, run: checkAmmInvariantMissing },
  { id: 'SOL746', name: 'Flash Loan Callback Validation Missing', severity: 'critical' as const, run: checkFlashLoanCallbackValidation },
  { id: 'SOL747', name: 'LP Share Calculation Precision Loss', severity: 'high' as const, run: checkLpSharePrecisionLoss },
  { id: 'SOL748', name: 'Interest Rate Model Missing Cap', severity: 'medium' as const, run: checkInterestRateManipulation },
  { id: 'SOL749', name: 'Collateral Factor Change Without Timelock', severity: 'high' as const, run: checkCollateralFactorManipulation },
  { id: 'SOL750', name: 'Self-Liquidation Not Prevented', severity: 'medium' as const, run: checkLiquidationBonusExploit },
  { id: 'SOL751', name: 'Oracle Price Staleness Not Checked', severity: 'high' as const, run: checkOraclePriceStaleness },
  { id: 'SOL752', name: 'Harvest Function Missing Timing Protection', severity: 'medium' as const, run: checkHarvestTimingAttack },
  { id: 'SOL753', name: 'Vault Share Inflation Attack Possible', severity: 'high' as const, run: checkVaultShareInflation },
  { id: 'SOL754', name: 'Bonding Curve Manipulation', severity: 'critical' as const, run: checkBondingCurveManipulation },
  { id: 'SOL755', name: 'Perpetual Funding Rate Missing Cap', severity: 'high' as const, run: checkFundingRateManipulation },
  { id: 'SOL756', name: 'Options Protocol Missing IV Oracle', severity: 'medium' as const, run: checkOptionsGreeksManipulation },
  { id: 'SOL757', name: 'Prediction Market Centralized Resolution', severity: 'high' as const, run: checkPredictionMarketResolution },
  { id: 'SOL758', name: 'Staking Reward Dilution Possible', severity: 'medium' as const, run: checkStakingRewardDilution },
  { id: 'SOL759', name: 'Cross-Margin Liquidation Cascade Risk', severity: 'high' as const, run: checkCrossMarginCascade },
  { id: 'SOL760', name: 'Governance Flash Loan Voting', severity: 'critical' as const, run: checkGovernanceFlashLoanVoting },
  { id: 'SOL761', name: 'NFT Royalty Enforcement Missing', severity: 'info' as const, run: checkNftRoyaltyBypass },
  { id: 'SOL762', name: 'Token-2022 Transfer Hook Reentrancy Risk', severity: 'high' as const, run: checkToken2022TransferHookReentrancy },
  { id: 'SOL763', name: 'cNFT Merkle Tree Capacity Not Validated', severity: 'medium' as const, run: checkCnftMerkleTreeOverflow },
  { id: 'SOL764', name: 'Restaking Slashing Cascade Risk', severity: 'high' as const, run: checkRestakingSlashingCascade },
];
