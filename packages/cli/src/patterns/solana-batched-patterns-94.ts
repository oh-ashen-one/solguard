/**
 * SolGuard Batch 94 Patterns
 * 
 * Source: Helius Complete Exploit History + Solsec PoC Research + Feb 2026 Deep Dive
 * Patterns: SOL5601-SOL5700
 * Added: Feb 6, 2026 7:30 AM
 */

import type { ParsedRust } from '../parsers/rust.js';

export const batch94Patterns = [
  // ===== SIGNATURE VERIFICATION PATTERNS (Wormhole-style) =====
  {
    id: 'SOL5601',
    name: 'signature-set-spoofing-deep',
    severity: 'critical' as const,
    category: 'cross-chain',
    description: 'Deep detection of signature set spoofing attacks where attackers create fake SignatureSet accounts to bypass guardian validation (Wormhole $326M)',
    pattern: /verify_signatures|guardian.*signature|signature_set|validate_guardian|check_guardian_set/gi,
    detector: (content: string) => {
      const issues: string[] = [];
      
      // Check for signature verification without proper account validation
      if (/verify_signatures/i.test(content) && !/owner\s*==|key\s*==|constraint\s*=.*owner/i.test(content)) {
        issues.push('Signature verification without account owner check - vulnerable to spoofed SignatureSet accounts');
      }
      
      // Check for guardian validation without source verification
      if (/guardian.*set|guardian.*signature/i.test(content) && !/(secp256k1|ed25519).*verify/i.test(content)) {
        issues.push('Guardian validation without cryptographic signature verification');
      }
      
      // Check for cross-chain message processing
      if (/process_vaa|parse_vaa|verify_vaa/i.test(content)) {
        issues.push('VAA processing detected - ensure guardian signatures are cryptographically verified, not just account-checked');
      }
      
      // Deprecated function usage
      if (/invoke_signed.*verify_signatures_deprecated/i.test(content)) {
        issues.push('Using deprecated verify_signatures - may contain known vulnerabilities');
      }
      
      return issues;
    },
  },
  {
    id: 'SOL5602',
    name: 'guardian-threshold-bypass',
    severity: 'critical' as const,
    category: 'cross-chain',
    description: 'Detection of guardian threshold bypass where attacker can validate with fewer signatures than required',
    pattern: /guardian.*threshold|required_signatures|min_signatures|quorum/gi,
    detector: (content: string) => {
      const issues: string[] = [];
      
      if (/guardian.*threshold/i.test(content) && !/>=\s*\d+.*\/.*3|2.*\/.*3/i.test(content)) {
        issues.push('Guardian threshold may not enforce 2/3 majority requirement');
      }
      
      if (/signature.*count|num_signatures/i.test(content) && !/require!|assert!/i.test(content)) {
        issues.push('Signature count not enforced with require!/assert! macro');
      }
      
      return issues;
    },
  },

  // ===== CLMM TICK ACCOUNT ATTACKS (Crema-style) =====
  {
    id: 'SOL5603',
    name: 'tick-account-owner-bypass',
    severity: 'critical' as const,
    category: 'defi',
    description: 'Detection of tick account owner bypass where attackers create fake tick accounts to manipulate fees (Crema $8.8M)',
    pattern: /tick_account|tick_array|tick_state|position_tick|lower_tick|upper_tick/gi,
    detector: (content: string) => {
      const issues: string[] = [];
      
      // Check for tick accounts without owner verification
      if (/tick_account|tick_array/i.test(content)) {
        if (!/owner\s*==.*program_id|has_one\s*=.*pool|seeds\s*=/i.test(content)) {
          issues.push('Tick account missing owner or pool verification - vulnerable to fake tick data injection');
        }
      }
      
      // Check for fee claims using tick data
      if (/claim.*fee|collect.*fee|withdraw.*fee/i.test(content) && /tick/i.test(content)) {
        if (!/verify.*tick|validate.*tick|check.*tick.*owner/i.test(content)) {
          issues.push('Fee claim uses tick data without verification - attacker can inflate claimed fees');
        }
      }
      
      return issues;
    },
  },
  {
    id: 'SOL5604',
    name: 'clmm-flash-loan-fee-manipulation',
    severity: 'critical' as const,
    category: 'defi',
    description: 'Detection of CLMM flash loan attacks that manipulate fee accumulation through fake tick data',
    pattern: /flash_loan|swap.*large|fee_growth|accumulated_fee|position_fee/gi,
    detector: (content: string) => {
      const issues: string[] = [];
      
      if (/fee_growth|accumulated_fee/i.test(content)) {
        if (!/snapshot|checkpoint|before_swap/i.test(content)) {
          issues.push('Fee growth tracking without snapshots - vulnerable to single-tx fee manipulation');
        }
      }
      
      if (/flash.*loan|flash.*swap/i.test(content) && /fee.*claim|collect.*fee/i.test(content)) {
        issues.push('Flash loan combined with fee claim in same flow - potential for fee inflation attack');
      }
      
      return issues;
    },
  },

  // ===== GOVERNANCE PROPOSAL ATTACKS (Audius-style) =====
  {
    id: 'SOL5605',
    name: 'governance-proposal-injection',
    severity: 'critical' as const,
    category: 'governance',
    description: 'Detection of governance proposal injection where malicious proposals can reconfigure treasury permissions (Audius $6.1M)',
    pattern: /execute_proposal|proposal.*execute|governance.*action|treasury.*transfer/gi,
    detector: (content: string) => {
      const issues: string[] = [];
      
      // Check for proposal execution without proper validation
      if (/execute.*proposal/i.test(content)) {
        if (!/timelock|delay|voting_period/i.test(content)) {
          issues.push('Proposal execution without timelock - vulnerable to immediate malicious execution');
        }
        if (!/quorum|min_votes|threshold/i.test(content)) {
          issues.push('Proposal execution without quorum check - attacker can self-approve proposals');
        }
      }
      
      // Check for treasury reconfiguration
      if (/treasury.*permission|treasury.*owner|treasury.*authority/i.test(content)) {
        if (!/multi_sig|require.*signatures|2.*of.*3/i.test(content)) {
          issues.push('Treasury permission changes without multi-sig requirement');
        }
      }
      
      return issues;
    },
  },
  {
    id: 'SOL5606',
    name: 'governance-initialization-hijack',
    severity: 'critical' as const,
    category: 'governance',
    description: 'Detection of governance initialization that can be hijacked by attackers',
    pattern: /initialize_governance|setup_governor|create_governance/gi,
    detector: (content: string) => {
      const issues: string[] = [];
      
      if (/initialize.*governance|create.*governor/i.test(content)) {
        if (!/is_initialized|initialized.*check|already_initialized/i.test(content)) {
          issues.push('Governance initialization without initialization check - can be re-initialized');
        }
      }
      
      return issues;
    },
  },

  // ===== BONDING CURVE EXPLOITS (Nirvana-style) =====
  {
    id: 'SOL5607',
    name: 'bonding-curve-flash-loan-manipulation',
    severity: 'critical' as const,
    category: 'defi',
    description: 'Detection of bonding curve manipulation via flash loans where attackers inflate token minting (Nirvana $3.5M)',
    pattern: /bonding_curve|mint_rate|price_curve|token_price|curve_multiplier/gi,
    detector: (content: string) => {
      const issues: string[] = [];
      
      // Check for bonding curve without flash loan protection
      if (/bonding_curve|price_curve/i.test(content)) {
        if (!/flash.*protection|same_block.*check|loan.*guard/i.test(content)) {
          issues.push('Bonding curve without flash loan protection - vulnerable to price manipulation attacks');
        }
      }
      
      // Check for price calculation vulnerabilities
      if (/mint_rate|token_price/i.test(content)) {
        if (!/twap|time_weighted|oracle/i.test(content)) {
          issues.push('Token price calculated without TWAP - vulnerable to single-block manipulation');
        }
      }
      
      // Check for missing reserve validation
      if (/curve.*mint|bonding.*mint/i.test(content)) {
        if (!/reserve.*check|collateral.*ratio|backing/i.test(content)) {
          issues.push('Bonding curve minting without reserve validation');
        }
      }
      
      return issues;
    },
  },
  {
    id: 'SOL5608',
    name: 'rising-floor-mechanism-bypass',
    severity: 'high' as const,
    category: 'defi',
    description: 'Detection of "rising floor" price mechanism vulnerabilities in stablecoin protocols',
    pattern: /floor_price|minimum_price|price_floor|backing_ratio/gi,
    detector: (content: string) => {
      const issues: string[] = [];
      
      if (/floor_price|price_floor/i.test(content)) {
        if (!/oracle.*validate|external.*price|chainlink|pyth/i.test(content)) {
          issues.push('Floor price mechanism without external oracle validation');
        }
      }
      
      return issues;
    },
  },

  // ===== INFINITE MINT EXPLOITS (Cashio-style) =====
  {
    id: 'SOL5609',
    name: 'collateral-validation-chain-bypass',
    severity: 'critical' as const,
    category: 'defi',
    description: 'Detection of collateral validation chain bypass where attackers use fake nested accounts (Cashio $52.8M)',
    pattern: /collateral.*validate|arrow.*account|saber_swap|nested.*account|nested.*mint/gi,
    detector: (content: string) => {
      const issues: string[] = [];
      
      // Check for nested account validation
      if (/arrow|nested|wrapped/i.test(content) && /collateral|mint/i.test(content)) {
        if (!/validate.*mint|check.*mint.*address|verify.*underlying/i.test(content)) {
          issues.push('Nested collateral account without mint field validation - vulnerable to fake collateral');
        }
      }
      
      // Check for LP token collateral
      if (/lp.*token.*collateral|lp.*as.*backing/i.test(content)) {
        if (!/verify.*lp.*pool|check.*pool.*address/i.test(content)) {
          issues.push('LP token collateral without pool address verification');
        }
      }
      
      // Root of trust pattern
      if (/mint.*token|create.*token/i.test(content)) {
        if (!/root_of_trust|trusted_mint|hardcoded.*mint/i.test(content)) {
          issues.push('Token minting without establishing root of trust for collateral chain');
        }
      }
      
      return issues;
    },
  },
  {
    id: 'SOL5610',
    name: 'infinite-mint-glitch-detection',
    severity: 'critical' as const,
    category: 'defi',
    description: 'Detection of infinite mint vulnerabilities in stablecoin protocols',
    pattern: /mint_to|token_mint|create_token|stablecoin.*mint/gi,
    detector: (content: string) => {
      const issues: string[] = [];
      
      if (/mint_to|stablecoin.*mint/i.test(content)) {
        if (!/max_supply|supply_cap|mint_limit/i.test(content)) {
          issues.push('Stablecoin minting without supply cap');
        }
        if (!/collateral.*>=|backing.*>=|ratio.*check/i.test(content)) {
          issues.push('Minting without collateral ratio enforcement');
        }
      }
      
      return issues;
    },
  },

  // ===== AUTH BYPASS PATTERNS (Solend-style) =====
  {
    id: 'SOL5611',
    name: 'lending-market-authority-bypass',
    severity: 'critical' as const,
    category: 'defi',
    description: 'Detection of lending market authority bypass where attackers create fake markets to bypass admin checks (Solend Aug 2021)',
    pattern: /update.*reserve|update.*config|lending_market|market.*authority/gi,
    detector: (content: string) => {
      const issues: string[] = [];
      
      // Check for UpdateReserveConfig pattern
      if (/update.*reserve.*config/i.test(content)) {
        if (!/market.*owner|lending_market.*authority|admin.*check/i.test(content)) {
          issues.push('UpdateReserveConfig without market owner verification - attacker can pass own market');
        }
        if (!/has_one\s*=.*lending_market|constraint.*market.*key/i.test(content)) {
          issues.push('Reserve config update without lending market constraint');
        }
      }
      
      // Check for liquidation parameter manipulation
      if (/liquidation_threshold|liquidation_bonus/i.test(content)) {
        if (!/admin|owner|authority/i.test(content)) {
          issues.push('Liquidation parameters modifiable without admin check');
        }
      }
      
      return issues;
    },
  },
  {
    id: 'SOL5612',
    name: 'reserve-config-manipulation',
    severity: 'high' as const,
    category: 'defi',
    description: 'Detection of reserve configuration manipulation vulnerabilities',
    pattern: /reserve_config|asset_config|collateral_factor|borrow_rate/gi,
    detector: (content: string) => {
      const issues: string[] = [];
      
      if (/reserve_config|asset_config/i.test(content)) {
        if (!/timelock|delay|circuit_breaker/i.test(content)) {
          issues.push('Reserve config changes without timelock or circuit breaker');
        }
      }
      
      return issues;
    },
  },

  // ===== WALLET KEY EXPOSURE (Slope-style) =====
  {
    id: 'SOL5613',
    name: 'private-key-logging-detection',
    severity: 'critical' as const,
    category: 'wallet',
    description: 'Detection of private key logging vulnerabilities where keys are sent to remote servers (Slope $8M)',
    pattern: /log.*key|send.*private|transmit.*seed|analytics.*wallet|sentry.*key/gi,
    detector: (content: string) => {
      const issues: string[] = [];
      
      // Check for key logging
      if (/private_key|secret_key|seed_phrase|mnemonic/i.test(content)) {
        if (/log|console|print|debug|sentry|analytics|http|fetch|post/i.test(content)) {
          issues.push('CRITICAL: Private key or seed phrase may be logged or transmitted');
        }
      }
      
      // Check for plaintext storage
      if (/store.*key|save.*key|persist.*key/i.test(content)) {
        if (!/encrypt|cipher|aes|chacha/i.test(content)) {
          issues.push('Private key storage without encryption');
        }
      }
      
      return issues;
    },
  },
  {
    id: 'SOL5614',
    name: 'wallet-sentry-integration-risk',
    severity: 'high' as const,
    category: 'wallet',
    description: 'Detection of risky Sentry/analytics integration that might capture sensitive data',
    pattern: /sentry|analytics|crashlytics|bugsnag|raygun/gi,
    detector: (content: string) => {
      const issues: string[] = [];
      
      if (/sentry|crashlytics|bugsnag/i.test(content)) {
        if (!/redact|scrub|filter|exclude.*key|exclude.*seed/i.test(content)) {
          issues.push('Error reporting integration without key/seed redaction');
        }
      }
      
      return issues;
    },
  },

  // ===== ORACLE MANIPULATION (Mango-style) =====
  {
    id: 'SOL5615',
    name: 'spot-oracle-manipulation-deep',
    severity: 'critical' as const,
    category: 'oracle',
    description: 'Detection of spot oracle manipulation for self-liquidation attacks (Mango $116M)',
    pattern: /spot_price|mark_price|index_price|perp.*price|oracle.*price/gi,
    detector: (content: string) => {
      const issues: string[] = [];
      
      // Check for price manipulation protections
      if (/spot_price|mark_price/i.test(content)) {
        if (!/deviation.*check|price.*band|circuit_breaker/i.test(content)) {
          issues.push('Spot/mark price without deviation checks - vulnerable to manipulation');
        }
        if (!/twap|ema|time_weighted/i.test(content)) {
          issues.push('Price oracle without time-weighted averaging');
        }
      }
      
      // Check for borrow against manipulated price
      if (/borrow|margin|leverage/i.test(content) && /oracle|price/i.test(content)) {
        if (!/max_borrow|borrow_limit|position_limit/i.test(content)) {
          issues.push('Borrowing/margin without position limits - vulnerable to price pump and borrow attack');
        }
      }
      
      return issues;
    },
  },
  {
    id: 'SOL5616',
    name: 'perpetual-funding-manipulation',
    severity: 'high' as const,
    category: 'defi',
    description: 'Detection of perpetual funding rate manipulation vulnerabilities',
    pattern: /funding_rate|perp.*funding|funding.*payment/gi,
    detector: (content: string) => {
      const issues: string[] = [];
      
      if (/funding_rate/i.test(content)) {
        if (!/cap|limit|max_funding/i.test(content)) {
          issues.push('Funding rate without caps - vulnerable to extreme funding extraction');
        }
      }
      
      return issues;
    },
  },

  // ===== LP TOKEN ORACLE ATTACKS =====
  {
    id: 'SOL5617',
    name: 'lp-token-oracle-manipulation',
    severity: 'critical' as const,
    category: 'oracle',
    description: 'Detection of LP token oracle manipulation where attackers move AMM prices to inflate collateral value',
    pattern: /lp.*price|lp.*oracle|lp.*value|pool.*token.*price/gi,
    detector: (content: string) => {
      const issues: string[] = [];
      
      // Check for LP token pricing
      if (/lp.*price|lp.*value/i.test(content)) {
        if (!/fair.*pricing|alpha.*homora|geometric_mean/i.test(content)) {
          issues.push('LP token pricing without fair value calculation - use Alpha Homora style pricing');
        }
      }
      
      // Check for pool reserve manipulation
      if (/pool.*reserve|amm.*reserve/i.test(content)) {
        if (!/k.*invariant|constant_product/i.test(content)) {
          issues.push('Pool reserve without constant product invariant verification');
        }
      }
      
      return issues;
    },
  },

  // ===== FLASH LOAN PROTECTION =====
  {
    id: 'SOL5618',
    name: 'comprehensive-flash-loan-protection',
    severity: 'high' as const,
    category: 'defi',
    description: 'Comprehensive flash loan protection detection',
    pattern: /flash_loan|flash_borrow|atomic_swap|same_block/gi,
    detector: (content: string) => {
      const issues: string[] = [];
      
      // Check for flash loan entry points
      if (/flash_loan|flash_borrow/i.test(content)) {
        if (!/callback|receiver.*check|whitelist/i.test(content)) {
          issues.push('Flash loan without receiver validation');
        }
        if (!/fee.*>=|min_fee/i.test(content)) {
          issues.push('Flash loan without minimum fee enforcement');
        }
      }
      
      // Check for same-block manipulation
      if (/price|oracle|value/i.test(content)) {
        if (!/slot.*check|block.*check|last_update/i.test(content)) {
          issues.push('Price-sensitive operation without same-block check');
        }
      }
      
      return issues;
    },
  },

  // ===== ROUNDING DIRECTION ATTACKS (Neodyme-style) =====
  {
    id: 'SOL5619',
    name: 'rounding-direction-exploit',
    severity: 'high' as const,
    category: 'arithmetic',
    description: 'Detection of rounding direction exploits where attackers accumulate dust through repeated small transactions (Neodyme $2.6B at risk)',
    pattern: /round|floor|ceil|div|division|truncate/gi,
    detector: (content: string) => {
      const issues: string[] = [];
      
      // Check for division rounding
      if (/\/.*\d|div\(|checked_div/i.test(content)) {
        if (!/floor|ceil|round_up|round_down/i.test(content)) {
          issues.push('Division without explicit rounding direction - may allow dust accumulation attacks');
        }
      }
      
      // Check for interest calculation
      if (/interest|yield|apy|apr/i.test(content) && /calculate|compute/i.test(content)) {
        if (!/floor.*borrow|ceil.*deposit/i.test(content)) {
          issues.push('Interest calculation without proper rounding (floor for borrower, ceil for protocol)');
        }
      }
      
      // Check for small transaction thresholds
      if (/deposit|withdraw|transfer/i.test(content)) {
        if (!/min_amount|minimum|threshold/i.test(content)) {
          issues.push('Missing minimum amount threshold - vulnerable to dust attacks');
        }
      }
      
      return issues;
    },
  },

  // ===== EXPLOIT CHAINING DETECTION =====
  {
    id: 'SOL5620',
    name: 'exploit-chain-vulnerability',
    severity: 'high' as const,
    category: 'attack-surface',
    description: 'Detection of vulnerabilities that can be chained together for larger exploits (samczsun methodology)',
    pattern: /multiple.*instruction|batch|chain.*call|sequential/gi,
    detector: (content: string) => {
      const issues: string[] = [];
      
      // Check for multi-instruction transactions
      if (/remaining_accounts|additional_accounts|extra_accounts/i.test(content)) {
        if (!/validate.*each|check.*all|verify.*remaining/i.test(content)) {
          issues.push('Remaining accounts not validated - potential for instruction chaining attacks');
        }
      }
      
      // Check for state changes across instructions
      if (/state.*change|update.*state/i.test(content)) {
        if (!/atomic|transaction.*boundary/i.test(content)) {
          issues.push('State changes without atomicity guarantees');
        }
      }
      
      return issues;
    },
  },

  // ===== COPE ROULETTE PATTERN (Revert Exploitation) =====
  {
    id: 'SOL5621',
    name: 'revert-transaction-exploitation',
    severity: 'medium' as const,
    category: 'attack-surface',
    description: 'Detection of revert transaction exploitation where attackers exploit reverting transactions for information (Cope Roulette)',
    pattern: /revert|rollback|undo|simulate|preflight/gi,
    detector: (content: string) => {
      const issues: string[] = [];
      
      // Check for information leakage through reverts
      if (/error.*message|revert.*reason/i.test(content)) {
        if (/price|balance|amount|secret/i.test(content)) {
          issues.push('Revert message may leak sensitive information (price/balance)');
        }
      }
      
      // Check for timing-based attacks
      if (/simulate|preflight/i.test(content)) {
        if (!/rate.*limit|throttle/i.test(content)) {
          issues.push('Transaction simulation without rate limiting - vulnerable to oracle probing');
        }
      }
      
      return issues;
    },
  },

  // ===== SIMULATION DETECTION BYPASS =====
  {
    id: 'SOL5622',
    name: 'simulation-detection-bypass',
    severity: 'medium' as const,
    category: 'attack-surface',
    description: 'Detection of simulation detection that can be bypassed by attackers (Opcodes research)',
    pattern: /is_simulation|simulation.*check|bank.*check|preflight/gi,
    detector: (content: string) => {
      const issues: string[] = [];
      
      // Check for simulation-only behavior
      if (/is_simulation|simulation_mode/i.test(content)) {
        issues.push('Simulation detection can be bypassed - do not rely on it for security');
      }
      
      // Check for different behavior in simulation
      if (/if.*simulation|when.*simulated/i.test(content)) {
        issues.push('Different behavior in simulation vs execution - potential for attack');
      }
      
      return issues;
    },
  },

  // ===== INCINERATOR ATTACK PATTERN =====
  {
    id: 'SOL5623',
    name: 'incinerator-nft-attack-deep',
    severity: 'high' as const,
    category: 'nft',
    description: 'Detection of incinerator/burn-based NFT attacks combining multiple small exploits (Solens research)',
    pattern: /burn.*nft|incinerator|close_account.*nft|destroy.*token/gi,
    detector: (content: string) => {
      const issues: string[] = [];
      
      // Check for NFT burning
      if (/burn.*nft|close.*nft.*account/i.test(content)) {
        if (!/owner.*check|authority.*verify/i.test(content)) {
          issues.push('NFT burn without proper owner verification');
        }
      }
      
      // Check for token account closure
      if (/close_account|close.*token/i.test(content)) {
        if (!/balance.*==.*0|empty.*check/i.test(content)) {
          issues.push('Token account closure without zero balance check');
        }
      }
      
      return issues;
    },
  },

  // ===== TOKEN APPROVAL EXPLOITATION =====
  {
    id: 'SOL5624',
    name: 'spl-token-approval-exploitation',
    severity: 'high' as const,
    category: 'token',
    description: 'Detection of SPL token approval exploitation where delegated amounts can be stolen (Hana research)',
    pattern: /approve|delegate|delegated_amount|authorized_amount/gi,
    detector: (content: string) => {
      const issues: string[] = [];
      
      // Check for approve without revoke
      if (/approve|delegate/i.test(content)) {
        if (!/revoke|reset.*approval|clear.*delegate/i.test(content)) {
          issues.push('Token approval without corresponding revoke mechanism');
        }
      }
      
      // Check for unlimited approvals
      if (/u64::MAX|max_amount|unlimited/i.test(content) && /approve|delegate/i.test(content)) {
        issues.push('Unlimited token approval - prefer exact amounts');
      }
      
      return issues;
    },
  },

  // ===== THIRD-PARTY DEPENDENCY RISKS =====
  {
    id: 'SOL5625',
    name: 'mongodb-injection-exploit',
    severity: 'critical' as const,
    category: 'infrastructure',
    description: 'Detection of MongoDB injection vulnerabilities in off-chain infrastructure (Thunder Terminal $240K)',
    pattern: /mongodb|mongo|nosql|database.*query/gi,
    detector: (content: string) => {
      const issues: string[] = [];
      
      // Check for raw query construction
      if (/mongo|nosql/i.test(content)) {
        if (/\$where|\$regex|\.find\(|\.aggregate\(/i.test(content)) {
          if (!/sanitize|escape|parameterize/i.test(content)) {
            issues.push('MongoDB query without input sanitization - vulnerable to NoSQL injection');
          }
        }
      }
      
      return issues;
    },
  },
  {
    id: 'SOL5626',
    name: 'session-token-theft-protection',
    severity: 'high' as const,
    category: 'infrastructure',
    description: 'Detection of session token theft vulnerabilities in trading infrastructure',
    pattern: /session.*token|auth.*token|bearer.*token|jwt/gi,
    detector: (content: string) => {
      const issues: string[] = [];
      
      if (/session.*token|auth.*token/i.test(content)) {
        if (!/secure|httponly|samesite/i.test(content)) {
          issues.push('Session token without secure cookie flags');
        }
        if (!/expire|ttl|timeout/i.test(content)) {
          issues.push('Session token without expiration');
        }
      }
      
      return issues;
    },
  },

  // ===== INSIDER THREAT PATTERNS =====
  {
    id: 'SOL5627',
    name: 'insider-employee-exploit',
    severity: 'critical' as const,
    category: 'access-control',
    description: 'Detection of insider threat vulnerabilities where employees can exploit privileged access (Pump.fun, Cypher)',
    pattern: /employee|admin|operator|privileged|internal/gi,
    detector: (content: string) => {
      const issues: string[] = [];
      
      // Check for single-key admin access
      if (/admin|operator/i.test(content)) {
        if (!/multi_sig|multisig|2.*of.*3|threshold.*signature/i.test(content)) {
          issues.push('Admin access without multi-sig requirement - vulnerable to insider exploit');
        }
      }
      
      // Check for privileged operations
      if (/withdraw_all|drain|emergency.*withdraw/i.test(content)) {
        if (!/timelock|delay|require.*approval/i.test(content)) {
          issues.push('Privileged withdrawal without timelock or multi-party approval');
        }
      }
      
      return issues;
    },
  },
  {
    id: 'SOL5628',
    name: 'migration-key-custody-risk',
    severity: 'high' as const,
    category: 'access-control',
    description: 'Detection of migration key custody risks during protocol upgrades',
    pattern: /migration|upgrade|transfer_authority|new_owner/gi,
    detector: (content: string) => {
      const issues: string[] = [];
      
      if (/migration.*key|upgrade.*authority/i.test(content)) {
        if (!/cold.*storage|hardware.*wallet|mpc/i.test(content)) {
          issues.push('Migration/upgrade key without cold storage requirement');
        }
      }
      
      return issues;
    },
  },

  // ===== DAO GOVERNANCE ATTACKS =====
  {
    id: 'SOL5629',
    name: 'dao-proposal-stealth-attack',
    severity: 'critical' as const,
    category: 'governance',
    description: 'Detection of DAO proposal attacks where malicious proposals go unnoticed (Saga DAO $230K)',
    pattern: /proposal|vote|governance.*action|dao.*execute/gi,
    detector: (content: string) => {
      const issues: string[] = [];
      
      // Check for proposal visibility
      if (/create.*proposal|submit.*proposal/i.test(content)) {
        if (!/emit.*event|log.*proposal|notify/i.test(content)) {
          issues.push('Proposal creation without event emission - may go unnoticed');
        }
      }
      
      // Check for voting period
      if (/voting.*period|vote.*deadline/i.test(content)) {
        if (!/>=.*\d+.*day|>=.*\d+.*hour/i.test(content)) {
          issues.push('Voting period may be too short for community review');
        }
      }
      
      // Check for proposal execution delay
      if (/execute.*proposal/i.test(content)) {
        if (!/execution.*delay|grace.*period/i.test(content)) {
          issues.push('No execution delay after proposal passes');
        }
      }
      
      return issues;
    },
  },

  // ===== LOOPSCALE RECOVERY PATTERNS =====
  {
    id: 'SOL5630',
    name: 'admin-redemption-exploit',
    severity: 'critical' as const,
    category: 'defi',
    description: 'Detection of admin redemption function exploits in lending protocols (Loopscale $5.8M)',
    pattern: /admin.*redeem|force.*redeem|privileged.*withdraw|redemption.*override/gi,
    detector: (content: string) => {
      const issues: string[] = [];
      
      if (/admin.*redeem|force.*redeem/i.test(content)) {
        if (!/emergency|pause.*state|circuit.*break/i.test(content)) {
          issues.push('Admin redemption function without emergency state requirement');
        }
        if (!/emit.*event|audit.*log/i.test(content)) {
          issues.push('Admin redemption without audit logging');
        }
      }
      
      return issues;
    },
  },

  // ===== DEXX PRIVATE KEY PATTERNS =====
  {
    id: 'SOL5631',
    name: 'custodial-key-exposure',
    severity: 'critical' as const,
    category: 'wallet',
    description: 'Detection of custodial key exposure vulnerabilities in DEX aggregators (DEXX $30M)',
    pattern: /custodial|store.*key|server.*wallet|hot.*wallet/gi,
    detector: (content: string) => {
      const issues: string[] = [];
      
      if (/custodial|server.*wallet|hot.*wallet/i.test(content)) {
        if (!/hsm|enclave|secure.*element/i.test(content)) {
          issues.push('Custodial keys without HSM/secure enclave protection');
        }
        if (!/split.*key|mpc|shamir/i.test(content)) {
          issues.push('Custodial keys without key splitting/MPC');
        }
      }
      
      return issues;
    },
  },

  // ===== SUPPLY CHAIN ATTACKS =====
  {
    id: 'SOL5632',
    name: 'npm-supply-chain-2026',
    severity: 'critical' as const,
    category: 'supply-chain',
    description: 'Detection of npm supply chain attack patterns (Web3.js $160K, solana-web3.js-v2 typosquat)',
    pattern: /solana.*web3|@solana\/web3|require\(|import.*from/gi,
    detector: (content: string) => {
      const issues: string[] = [];
      
      // Check for version pinning
      if (/@solana\/web3|solana-web3/i.test(content)) {
        if (/\^|~|latest/i.test(content)) {
          issues.push('Unpinned @solana/web3.js version - vulnerable to malicious updates');
        }
      }
      
      // Check for typosquat packages
      const typosquats = ['solana-web3.js-v2', 'solana-web3', '@solana-web3', 'solana_web3'];
      for (const pkg of typosquats) {
        if (content.includes(pkg)) {
          issues.push(`Potential typosquat package detected: ${pkg}`);
        }
      }
      
      return issues;
    },
  },

  // ===== NOONES BRIDGE PATTERNS =====
  {
    id: 'SOL5633',
    name: 'bridge-endpoint-exposure',
    severity: 'critical' as const,
    category: 'cross-chain',
    description: 'Detection of bridge endpoint exposure vulnerabilities (NoOnes $7.2M)',
    pattern: /bridge.*endpoint|api.*bridge|withdraw.*api|exposed.*function/gi,
    detector: (content: string) => {
      const issues: string[] = [];
      
      if (/bridge.*api|withdraw.*endpoint/i.test(content)) {
        if (!/auth|signature|verify.*caller/i.test(content)) {
          issues.push('Bridge API endpoint without authentication');
        }
        if (!/rate.*limit|throttle/i.test(content)) {
          issues.push('Bridge endpoint without rate limiting');
        }
      }
      
      return issues;
    },
  },

  // ===== SVT TOKEN PATTERNS =====
  {
    id: 'SOL5634',
    name: 'token-creation-exploit',
    severity: 'high' as const,
    category: 'token',
    description: 'Detection of token creation exploits where attackers manipulate new token launches (SVT Token $300K)',
    pattern: /token.*launch|create.*mint|initialize.*token|ido|ico/gi,
    detector: (content: string) => {
      const issues: string[] = [];
      
      if (/token.*launch|ido|ico/i.test(content)) {
        if (!/vesting|lock|cliff/i.test(content)) {
          issues.push('Token launch without vesting schedule');
        }
        if (!/max.*buy|purchase.*limit/i.test(content)) {
          issues.push('Token sale without purchase limits - vulnerable to whale manipulation');
        }
      }
      
      return issues;
    },
  },

  // ===== BANANA GUN BOT PATTERNS =====
  {
    id: 'SOL5635',
    name: 'trading-bot-key-compromise',
    severity: 'critical' as const,
    category: 'wallet',
    description: 'Detection of trading bot private key compromise patterns (Banana Gun $1.9M)',
    pattern: /trading.*bot|sniper.*bot|auto.*trade|bot.*wallet/gi,
    detector: (content: string) => {
      const issues: string[] = [];
      
      if (/trading.*bot|sniper.*bot/i.test(content)) {
        if (!/separate.*wallet|isolated.*key|burner/i.test(content)) {
          issues.push('Trading bot without isolated wallet - main wallet at risk');
        }
        if (!/limit.*order|max.*trade/i.test(content)) {
          issues.push('Trading bot without trade size limits');
        }
      }
      
      return issues;
    },
  },

  // ===== IO.NET PATTERNS =====
  {
    id: 'SOL5636',
    name: 'fake-gpu-worker-exploit',
    severity: 'high' as const,
    category: 'infrastructure',
    description: 'Detection of fake GPU worker exploits in decentralized compute networks (io.net $6M)',
    pattern: /gpu.*worker|compute.*node|worker.*proof|resource.*verify/gi,
    detector: (content: string) => {
      const issues: string[] = [];
      
      if (/gpu.*worker|compute.*node/i.test(content)) {
        if (!/proof.*of.*work|challenge.*response|attestation/i.test(content)) {
          issues.push('Compute worker without proof of work verification');
        }
        if (!/slash|penalty|stake/i.test(content)) {
          issues.push('Worker system without slashing for fake resources');
        }
      }
      
      return issues;
    },
  },

  // ===== SOLAREUM RUG PULL PATTERNS =====
  {
    id: 'SOL5637',
    name: 'trading-platform-rug-detection',
    severity: 'critical' as const,
    category: 'defi',
    description: 'Detection of trading platform rug pull indicators (Solareum $500K)',
    pattern: /trading.*platform|copy.*trade|social.*trade|managed.*fund/gi,
    detector: (content: string) => {
      const issues: string[] = [];
      
      if (/trading.*platform|managed.*fund/i.test(content)) {
        if (!/withdrawal.*right|instant.*withdraw|no.*lock/i.test(content)) {
          issues.push('Trading platform with potential user fund lockup');
        }
        if (!/transparent.*pnl|public.*trade/i.test(content)) {
          issues.push('Trading platform without transparent P&L tracking');
        }
      }
      
      return issues;
    },
  },

  // ===== OPTIFI LOCKUP PATTERNS =====
  {
    id: 'SOL5638',
    name: 'accidental-program-close',
    severity: 'critical' as const,
    category: 'program',
    description: 'Detection of accidental program closure vulnerabilities (OptiFi $661K locked)',
    pattern: /close.*program|program.*close|solana.*program.*close|terminate.*program/gi,
    detector: (content: string) => {
      const issues: string[] = [];
      
      // Check for program close functions
      if (/close.*program|terminate.*program/i.test(content)) {
        if (!/admin.*only|multi_sig|governance.*vote/i.test(content)) {
          issues.push('Program close function without governance approval');
        }
        if (!/drain.*first|withdraw.*all|empty.*vault/i.test(content)) {
          issues.push('Program close without ensuring funds are drained first');
        }
        if (!/confirm|double.*check|require.*confirmation/i.test(content)) {
          issues.push('Program close without confirmation step');
        }
      }
      
      return issues;
    },
  },

  // ===== TULIP PROTOCOL PATTERNS =====
  {
    id: 'SOL5639',
    name: 'vault-strategy-exploit',
    severity: 'high' as const,
    category: 'defi',
    description: 'Detection of yield vault strategy exploits (Tulip Protocol)',
    pattern: /vault.*strategy|yield.*strategy|harvest|compound/gi,
    detector: (content: string) => {
      const issues: string[] = [];
      
      if (/vault.*strategy|yield.*strategy/i.test(content)) {
        if (!/slippage.*check|min.*output/i.test(content)) {
          issues.push('Vault strategy without slippage protection');
        }
        if (!/deadline|max.*age/i.test(content)) {
          issues.push('Vault strategy without transaction deadline');
        }
      }
      
      return issues;
    },
  },

  // ===== AURORY GAMING PATTERNS =====
  {
    id: 'SOL5640',
    name: 'gaming-nft-exploit',
    severity: 'high' as const,
    category: 'nft',
    description: 'Detection of gaming NFT exploits (Aurory $830K)',
    pattern: /game.*nft|gaming.*token|play.*earn|in_game.*asset/gi,
    detector: (content: string) => {
      const issues: string[] = [];
      
      if (/game.*nft|play.*earn/i.test(content)) {
        if (!/cooldown|rate.*limit|anti.*bot/i.test(content)) {
          issues.push('Gaming NFT system without anti-bot protection');
        }
        if (!/max.*mint.*per.*user|limit.*per.*wallet/i.test(content)) {
          issues.push('Gaming NFT without per-user limits');
        }
      }
      
      return issues;
    },
  },

  // ===== UXD PROTOCOL PATTERNS =====
  {
    id: 'SOL5641',
    name: 'delta-neutral-exploit',
    severity: 'high' as const,
    category: 'defi',
    description: 'Detection of delta-neutral stablecoin exploits (UXD Protocol)',
    pattern: /delta.*neutral|hedge|short.*perp|backing.*perp/gi,
    detector: (content: string) => {
      const issues: string[] = [];
      
      if (/delta.*neutral|hedge.*perp/i.test(content)) {
        if (!/funding.*check|negative.*funding/i.test(content)) {
          issues.push('Delta-neutral strategy without funding rate risk management');
        }
        if (!/liquidation.*buffer|margin.*cushion/i.test(content)) {
          issues.push('Perpetual hedge without liquidation buffer');
        }
      }
      
      return issues;
    },
  },

  // ===== RAYDIUM PATTERNS =====
  {
    id: 'SOL5642',
    name: 'amm-admin-key-compromise',
    severity: 'critical' as const,
    category: 'defi',
    description: 'Detection of AMM admin key compromise patterns (Raydium $4.4M)',
    pattern: /amm.*admin|pool.*owner|liquidity.*admin|fee.*admin/gi,
    detector: (content: string) => {
      const issues: string[] = [];
      
      if (/amm.*admin|pool.*owner/i.test(content)) {
        if (!/multi_sig|hardware.*wallet|cold.*storage/i.test(content)) {
          issues.push('AMM admin key without multi-sig or cold storage');
        }
        if (!/rotation|key.*update/i.test(content)) {
          issues.push('No admin key rotation mechanism');
        }
      }
      
      return issues;
    },
  },

  // ===== SYNTHETIFY DAO PATTERNS =====
  {
    id: 'SOL5643',
    name: 'synthetic-asset-exploit',
    severity: 'high' as const,
    category: 'defi',
    description: 'Detection of synthetic asset protocol exploits (Synthetify DAO)',
    pattern: /synthetic|synth.*asset|debt.*pool|collateral.*ratio/gi,
    detector: (content: string) => {
      const issues: string[] = [];
      
      if (/synthetic|synth.*asset/i.test(content)) {
        if (!/c_ratio|collateral.*ratio.*check/i.test(content)) {
          issues.push('Synthetic asset without collateralization ratio check');
        }
        if (!/global.*debt|debt.*pool.*update/i.test(content)) {
          issues.push('Synthetic asset without global debt tracking');
        }
      }
      
      return issues;
    },
  },

  // ===== PHANTOM DOS PATTERNS =====
  {
    id: 'SOL5644',
    name: 'wallet-dos-protection',
    severity: 'medium' as const,
    category: 'wallet',
    description: 'Detection of wallet DoS attack vulnerabilities (Phantom DoS)',
    pattern: /render.*token|display.*nft|wallet.*ui|token.*list/gi,
    detector: (content: string) => {
      const issues: string[] = [];
      
      if (/render.*token|display.*nft/i.test(content)) {
        if (!/pagination|limit.*display|lazy.*load/i.test(content)) {
          issues.push('Token display without pagination - vulnerable to UI DoS');
        }
        if (!/sanitize.*metadata|validate.*uri/i.test(content)) {
          issues.push('Token metadata rendering without sanitization');
        }
      }
      
      return issues;
    },
  },

  // ===== JITO DOS PATTERNS =====
  {
    id: 'SOL5645',
    name: 'bundle-dos-protection',
    severity: 'medium' as const,
    category: 'infrastructure',
    description: 'Detection of MEV bundle DoS vulnerabilities (Jito DoS)',
    pattern: /bundle|mev|priority.*fee|tip/gi,
    detector: (content: string) => {
      const issues: string[] = [];
      
      if (/bundle|mev/i.test(content)) {
        if (!/rate.*limit|max.*bundle/i.test(content)) {
          issues.push('MEV bundle handling without rate limiting');
        }
        if (!/validate.*bundle|check.*tip/i.test(content)) {
          issues.push('Bundle processing without validation');
        }
      }
      
      return issues;
    },
  },

  // ===== GRAPE PROTOCOL PATTERNS =====
  {
    id: 'SOL5646',
    name: 'nft-spam-protection',
    severity: 'medium' as const,
    category: 'nft',
    description: 'Detection of NFT spam attack vulnerabilities (Grape Protocol outage)',
    pattern: /nft.*spam|mass.*mint|bulk.*transfer|airdrop.*nft/gi,
    detector: (content: string) => {
      const issues: string[] = [];
      
      if (/mass.*mint|bulk.*transfer/i.test(content)) {
        if (!/compute.*limit|batch.*size/i.test(content)) {
          issues.push('Bulk NFT operation without compute/batch limits');
        }
      }
      
      return issues;
    },
  },

  // ===== CANDY MACHINE PATTERNS =====
  {
    id: 'SOL5647',
    name: 'candy-machine-v2-exploit',
    severity: 'high' as const,
    category: 'nft',
    description: 'Detection of Candy Machine exploit patterns (Dec 2021 outage)',
    pattern: /candy.*machine|nft.*mint.*bot|mint.*snipe/gi,
    detector: (content: string) => {
      const issues: string[] = [];
      
      if (/candy.*machine/i.test(content)) {
        if (!/bot.*protection|captcha|proof.*of.*human/i.test(content)) {
          issues.push('Candy Machine without bot protection');
        }
        if (!/guard|whitelist|allow.*list/i.test(content)) {
          issues.push('Candy Machine without access guards');
        }
      }
      
      return issues;
    },
  },

  // ===== CORE PROTOCOL PATTERNS =====
  {
    id: 'SOL5648',
    name: 'turbine-propagation-vulnerability',
    severity: 'high' as const,
    category: 'protocol',
    description: 'Detection of Turbine block propagation vulnerabilities',
    pattern: /turbine|shred|block.*propagation|data.*broadcast/gi,
    detector: (content: string) => {
      const issues: string[] = [];
      
      if (/turbine|shred/i.test(content)) {
        if (!/erasure.*coding|reed.*solomon/i.test(content)) {
          issues.push('Block propagation without erasure coding');
        }
        if (!/verify.*shred|validate.*shred/i.test(content)) {
          issues.push('Shred handling without verification');
        }
      }
      
      return issues;
    },
  },
  {
    id: 'SOL5649',
    name: 'durable-nonce-exploitation',
    severity: 'medium' as const,
    category: 'protocol',
    description: 'Detection of durable nonce exploitation vulnerabilities',
    pattern: /durable.*nonce|nonce.*account|advance.*nonce/gi,
    detector: (content: string) => {
      const issues: string[] = [];
      
      if (/durable.*nonce/i.test(content)) {
        if (!/authority.*check|nonce.*authority/i.test(content)) {
          issues.push('Durable nonce without authority verification');
        }
      }
      
      return issues;
    },
  },
  {
    id: 'SOL5650',
    name: 'duplicate-block-exploitation',
    severity: 'high' as const,
    category: 'protocol',
    description: 'Detection of duplicate block exploitation vulnerabilities',
    pattern: /duplicate.*block|block.*hash.*collision|leader.*schedule/gi,
    detector: (content: string) => {
      const issues: string[] = [];
      
      if (/duplicate.*block|block.*collision/i.test(content)) {
        issues.push('Potential duplicate block handling issue - ensure proper block deduplication');
      }
      
      return issues;
    },
  },

  // ===== ADDITIONAL HELIUS PATTERNS =====
  {
    id: 'SOL5651',
    name: 'pump-fun-employee-exploit',
    severity: 'critical' as const,
    category: 'access-control',
    description: 'Detection of employee exploit patterns where insiders abuse privileged access (Pump.fun $1.9M)',
    pattern: /employee.*access|staff.*key|internal.*wallet|team.*authority/gi,
    detector: (content: string) => {
      const issues: string[] = [];
      
      if (/employee.*access|team.*authority/i.test(content)) {
        if (!/audit.*log|access.*log|monitoring/i.test(content)) {
          issues.push('Employee access without audit logging');
        }
        if (!/separation.*of.*duties|dual.*control/i.test(content)) {
          issues.push('No separation of duties for privileged operations');
        }
      }
      
      return issues;
    },
  },
  {
    id: 'SOL5652',
    name: 'cypher-insider-theft-v2',
    severity: 'critical' as const,
    category: 'access-control',
    description: 'Detection of insider theft patterns (Cypher $317K theft by Hoak)',
    pattern: /former.*employee|ex.*team|past.*contributor|insider.*theft/gi,
    detector: (content: string) => {
      const issues: string[] = [];
      
      if (/former.*employee|ex.*team/i.test(content)) {
        if (!/revoke.*access|key.*rotation|offboarding/i.test(content)) {
          issues.push('No offboarding procedure for revoking former employee access');
        }
      }
      
      return issues;
    },
  },

  // ===== PARCL FRONTEND PATTERNS =====
  {
    id: 'SOL5653',
    name: 'frontend-supply-chain-attack',
    severity: 'high' as const,
    category: 'supply-chain',
    description: 'Detection of frontend supply chain attack patterns (Parcl $500K)',
    pattern: /frontend|web.*app|react|vue|angular|next/gi,
    detector: (content: string) => {
      const issues: string[] = [];
      
      if (/frontend|web.*app/i.test(content)) {
        if (!/sri|subresource.*integrity|hash.*check/i.test(content)) {
          issues.push('Frontend without subresource integrity checks');
        }
        if (!/csp|content.*security.*policy/i.test(content)) {
          issues.push('Frontend without Content Security Policy');
        }
      }
      
      return issues;
    },
  },

  // ===== SOLANA JIT CACHE PATTERNS =====
  {
    id: 'SOL5654',
    name: 'jit-cache-overflow',
    severity: 'high' as const,
    category: 'protocol',
    description: 'Detection of JIT cache overflow vulnerabilities',
    pattern: /jit.*cache|program.*cache|compiled.*cache|bpf.*cache/gi,
    detector: (content: string) => {
      const issues: string[] = [];
      
      if (/jit.*cache|program.*cache/i.test(content)) {
        if (!/cache.*limit|max.*cache|eviction/i.test(content)) {
          issues.push('Program cache without size limits or eviction policy');
        }
      }
      
      return issues;
    },
  },

  // ===== ELF ALIGNMENT PATTERNS =====
  {
    id: 'SOL5655',
    name: 'elf-address-alignment',
    severity: 'medium' as const,
    category: 'protocol',
    description: 'Detection of ELF address alignment vulnerabilities in BPF programs',
    pattern: /elf|bpf.*loader|program.*deploy|alignment/gi,
    detector: (content: string) => {
      const issues: string[] = [];
      
      if (/elf|bpf.*loader/i.test(content)) {
        if (!/alignment.*check|aligned/i.test(content)) {
          issues.push('BPF program without alignment checks');
        }
      }
      
      return issues;
    },
  },

  // ===== WEB3.JS SUPPLY CHAIN =====
  {
    id: 'SOL5656',
    name: 'web3js-malicious-version',
    severity: 'critical' as const,
    category: 'supply-chain',
    description: 'Detection of malicious @solana/web3.js version usage ($160K stolen)',
    pattern: /@solana\/web3\.js|solana-web3|web3\.js.*1\.95\.[6-8]/gi,
    detector: (content: string) => {
      const issues: string[] = [];
      
      // Check for compromised versions
      if (/1\.95\.6|1\.95\.7|1\.95\.8/i.test(content) && /@solana\/web3/i.test(content)) {
        issues.push('CRITICAL: Using compromised @solana/web3.js version (1.95.6-1.95.8) - update immediately');
      }
      
      // Check for lockfile
      if (/@solana\/web3/i.test(content)) {
        if (!/package-lock|yarn\.lock|pnpm-lock/i.test(content)) {
          issues.push('No lockfile detected - vulnerable to malicious package updates');
        }
      }
      
      return issues;
    },
  },

  // ===== ADDITIONAL CRITICAL PATTERNS =====
  {
    id: 'SOL5657',
    name: 'thunder-terminal-9min-response',
    severity: 'high' as const,
    category: 'incident-response',
    description: 'Incident response time benchmark (Thunder Terminal 9-minute halt)',
    pattern: /circuit.*breaker|emergency.*halt|kill.*switch|pause.*all/gi,
    detector: (content: string) => {
      const issues: string[] = [];
      
      if (/trading.*platform|dex|exchange/i.test(content)) {
        if (!/circuit.*breaker|emergency.*halt|pause/i.test(content)) {
          issues.push('Trading platform without emergency circuit breaker');
        }
        if (!/monitoring|alert|anomaly.*detection/i.test(content)) {
          issues.push('No real-time monitoring for rapid incident response');
        }
      }
      
      return issues;
    },
  },

  // ===== CROSS-CHAIN BRIDGE COMPLETE =====
  {
    id: 'SOL5658',
    name: 'bridge-complete-security',
    severity: 'critical' as const,
    category: 'cross-chain',
    description: 'Comprehensive cross-chain bridge security patterns',
    pattern: /bridge|cross.*chain|wormhole|portal|wrapped/gi,
    detector: (content: string) => {
      const issues: string[] = [];
      
      if (/bridge|cross.*chain/i.test(content)) {
        // Guardian validation
        if (!/guardian|validator.*set|relayer.*verify/i.test(content)) {
          issues.push('Bridge without guardian/validator validation');
        }
        // Message finality
        if (!/finality|confirmation|block.*confirm/i.test(content)) {
          issues.push('Bridge without finality checks on source chain');
        }
        // Replay protection
        if (!/nonce|sequence|replay.*protect/i.test(content)) {
          issues.push('Bridge without replay protection');
        }
        // Rate limiting
        if (!/rate.*limit|max.*transfer|daily.*limit/i.test(content)) {
          issues.push('Bridge without transfer rate limits');
        }
      }
      
      return issues;
    },
  },

  // ===== LENDING PROTOCOL COMPLETE =====
  {
    id: 'SOL5659',
    name: 'lending-complete-security',
    severity: 'high' as const,
    category: 'defi',
    description: 'Comprehensive lending protocol security patterns',
    pattern: /lending|borrow|collateral|liquidat|interest.*rate/gi,
    detector: (content: string) => {
      const issues: string[] = [];
      
      if (/lending|borrow/i.test(content)) {
        // Interest rate validation
        if (!/interest.*cap|max.*rate|rate.*limit/i.test(content)) {
          issues.push('Lending without interest rate caps');
        }
        // Utilization checks
        if (!/utilization|reserve.*ratio/i.test(content)) {
          issues.push('Lending without utilization tracking');
        }
        // Bad debt handling
        if (!/bad.*debt|socialized.*loss|insurance/i.test(content)) {
          issues.push('Lending without bad debt handling mechanism');
        }
      }
      
      return issues;
    },
  },

  // ===== DEX/AMM COMPLETE =====
  {
    id: 'SOL5660',
    name: 'dex-complete-security',
    severity: 'high' as const,
    category: 'defi',
    description: 'Comprehensive DEX/AMM security patterns',
    pattern: /dex|amm|swap|pool|liquidity/gi,
    detector: (content: string) => {
      const issues: string[] = [];
      
      if (/dex|amm|swap/i.test(content)) {
        // Slippage protection
        if (!/slippage|min.*out|max.*in/i.test(content)) {
          issues.push('DEX swap without slippage protection');
        }
        // Deadline enforcement
        if (!/deadline|expire|valid.*until/i.test(content)) {
          issues.push('DEX swap without deadline');
        }
        // Sandwich protection
        if (!/private.*mempool|jito|mev.*protect/i.test(content)) {
          issues.push('Consider MEV/sandwich protection for swaps');
        }
      }
      
      return issues;
    },
  },
];

export function checkBatch94Patterns(parsed: ParsedRust): Array<{id: string; name: string; severity: string; message: string; line?: number}> {
  const issues: Array<{id: string; name: string; severity: string; message: string; line?: number}> = [];
  const content = parsed.content;

  for (const pattern of batch94Patterns) {
    if (pattern.pattern.test(content)) {
      const detectedIssues = pattern.detector(content);
      for (const issue of detectedIssues) {
        issues.push({
          id: pattern.id,
          name: pattern.name,
          severity: pattern.severity,
          message: `${pattern.description}: ${issue}`,
        });
      }
    }
    // Reset regex lastIndex for global patterns
    pattern.pattern.lastIndex = 0;
  }

  return issues;
}

export default batch94Patterns;
