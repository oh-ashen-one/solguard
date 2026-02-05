/**
 * SolShield Security Patterns - Batch 9 (SOL276-SOL290)
 * Advanced attack vectors from 2024-2025 security research
 */

import type { Finding } from '../commands/audit.js';
import type { PatternInput } from './index.js';

// SOL276: Phishing Ownership Transfer (Solana Phishing Attack 2025)
export function checkOwnershipPhishing(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  if (!input.rust) return findings;
  const content = input.rust.content;
  
  // Check for owner/authority transfer patterns
  if (/set.*owner|transfer.*authority|change.*owner/gi.test(content)) {
    // Check for confirmation requirements
    if (!/confirm|two.*step|pending.*transfer|accept.*ownership/gi.test(content)) {
      findings.push({
        id: 'SOL276',
        severity: 'critical',
        title: 'Single-Step Ownership Transfer',
        description: 'Ownership transfer happens in single step. Phishing attacks can trick users into signing ownership transfers. 2025 Solana phishing attacks exploited this to steal millions.',
        location: input.path,
        recommendation: 'Implement two-step ownership transfer: propose → accept. New owner must explicitly accept ownership.',
      });
    }
  }
  
  return findings;
}

// SOL277: Program Account Confusion Attack
export function checkProgramAccountConfusion(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  if (!input.rust) return findings;
  const content = input.rust.content;
  
  // Check for account type handling
  if (/AccountInfo|Account<|#\[account\]/gi.test(content)) {
    // Check for explicit type discrimination
    if (!/discriminator|account.*type|type.*check|variant/gi.test(content)) {
      // But has multiple account types
      if (/struct\s+\w+Account|pub\s+struct.*Config|pub\s+struct.*State/gi.test(content)) {
        findings.push({
          id: 'SOL277',
          severity: 'high',
          title: 'Missing Account Type Discrimination',
          description: 'Multiple account types without explicit type discrimination. Attackers can substitute one account type for another.',
          location: input.path,
          recommendation: 'Add unique discriminator bytes to each account type. Validate discriminator before processing any account.',
        });
      }
    }
  }
  
  return findings;
}

// SOL278: Raydium-style AMM Exploit
export function checkAmmPoolDrainExploit(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  if (!input.rust) return findings;
  const content = input.rust.content;
  
  // Check for AMM/pool patterns
  if (/amm|liquidity.*pool|swap.*pool|token.*pair/gi.test(content)) {
    // Check for admin key separation
    if (/admin|authority|owner/gi.test(content)) {
      if (!/separate.*admin|isolated.*key|cold.*wallet/gi.test(content)) {
        findings.push({
          id: 'SOL278',
          severity: 'critical',
          title: 'AMM Admin Key Not Isolated',
          description: 'AMM admin keys may not be properly isolated. The Raydium exploit occurred when admin keys were compromised, allowing $4.4M pool drain.',
          location: input.path,
          recommendation: 'Store admin keys in cold wallets or HSMs. Use multisig for all admin operations. Implement timelocks on sensitive actions.',
        });
      }
    }
    
    // Check for emergency controls
    if (!/pause|emergency.*stop|circuit.*breaker/gi.test(content)) {
      findings.push({
        id: 'SOL278',
        severity: 'high',
        title: 'Missing AMM Emergency Controls',
        description: 'AMM lacks emergency pause functionality. Cannot stop exploits in progress.',
        location: input.path,
        recommendation: 'Implement emergency pause mechanism that can halt all pool operations. Add circuit breakers for unusual activity.',
      });
    }
  }
  
  return findings;
}

// SOL279: Cypher Protocol Insider Exploit
export function checkInsiderExploitVectors(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  if (!input.rust) return findings;
  const content = input.rust.content;
  
  // Check for privileged operations
  if (/withdraw.*all|drain|collect.*fee|admin.*withdraw/gi.test(content)) {
    // Check for withdrawal limits
    if (!/limit|max.*withdraw|daily.*limit|rate.*limit/gi.test(content)) {
      findings.push({
        id: 'SOL279',
        severity: 'critical',
        title: 'Unlimited Privileged Withdrawal',
        description: 'Admin/privileged accounts can withdraw without limits. The Cypher Protocol lost $317K when a contributor drained funds.',
        location: input.path,
        recommendation: 'Implement withdrawal limits even for admin accounts. Use timelocks and multisig for large withdrawals.',
      });
    }
  }
  
  return findings;
}

// SOL280: Solend-style Reserve Config Manipulation
export function checkReserveConfigManipulation(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  if (!input.rust) return findings;
  const content = input.rust.content;
  
  // Check for lending protocol patterns
  if (/reserve|lending.*pool|borrow.*rate|liquidation/gi.test(content)) {
    // Check for config update protections
    if (/update.*config|set.*param|change.*rate/gi.test(content)) {
      if (!/verify.*lending.*market|market.*owner|root.*market/gi.test(content)) {
        findings.push({
          id: 'SOL280',
          severity: 'critical',
          title: 'Reserve Config Update Bypass Risk',
          description: 'Reserve configuration updates may not properly verify lending market ownership. The Solend auth bypass allowed attackers to create fake markets and modify reserve configs.',
          location: input.path,
          recommendation: 'Always verify the lending market account is the canonical one, not attacker-controlled. Validate market ownership before config updates.',
        });
      }
    }
  }
  
  return findings;
}

// SOL281: Solareum-style Rug Pull Detection
export function checkRugPullVectors(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  if (!input.rust) return findings;
  const content = input.rust.content;
  
  // Check for token/pool patterns
  if (/mint.*authority|token.*mint|liquidity.*add/gi.test(content)) {
    // Check for mint authority controls
    if (!/renounce.*mint|disable.*mint|burn.*authority/gi.test(content)) {
      if (/mint/gi.test(content)) {
        findings.push({
          id: 'SOL281',
          severity: 'high',
          title: 'Mint Authority Not Renounced',
          description: 'Token mint authority is not renounced. Project owners can mint unlimited tokens to dump. Solareum users lost $523K when the Telegram bot rugged.',
          location: input.path,
          recommendation: 'Consider renouncing mint authority after initial distribution. If mint authority needed, implement transparent vesting/emission schedules.',
        });
      }
    }
    
    // Check for liquidity locks
    if (/liquidity|lp.*token/gi.test(content)) {
      if (!/lock.*liquidity|time.*lock.*lp|vesting/gi.test(content)) {
        findings.push({
          id: 'SOL281',
          severity: 'high',
          title: 'Liquidity Not Locked',
          description: 'Liquidity pool tokens are not locked. Owners can remove liquidity and rug pull users.',
          location: input.path,
          recommendation: 'Lock liquidity tokens with timelock contracts. Use third-party liquidity lockers for transparency.',
        });
      }
    }
  }
  
  return findings;
}

// SOL282: io.net GPU Network Exploit Pattern
export function checkDistributedNetworkExploit(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  if (!input.rust) return findings;
  const content = input.rust.content;
  
  // Check for distributed network/node patterns
  if (/node.*network|distributed|worker.*node|compute.*provider/gi.test(content)) {
    // Check for Sybil resistance
    if (!/stake.*node|bond|collateral.*node|proof.*of/gi.test(content)) {
      findings.push({
        id: 'SOL282',
        severity: 'high',
        title: 'Missing Sybil Resistance',
        description: 'Distributed network without Sybil resistance. Attackers can create fake nodes to exploit reward systems or disrupt network.',
        location: input.path,
        recommendation: 'Require staking/bonding for node participation. Implement proof of work/stake/resource. Verify node authenticity.',
      });
    }
    
    // Check for metadata validation
    if (/metadata|user.*info|profile/gi.test(content)) {
      if (!/verify.*metadata|validate.*info|check.*authentic/gi.test(content)) {
        findings.push({
          id: 'SOL282',
          severity: 'medium',
          title: 'Unverified Node Metadata',
          description: 'Node metadata not verified. io.net suffered inflated worker counts from fake metadata, causing a 96% token price drop.',
          location: input.path,
          recommendation: 'Verify all node metadata through cryptographic proofs or trusted attestation.',
        });
      }
    }
  }
  
  return findings;
}

// SOL283: Aurory Game Exploit Pattern
export function checkGamingExploitVectors(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  if (!input.rust) return findings;
  const content = input.rust.content;
  
  // Check for gaming/reward patterns
  if (/game|reward|nft.*claim|play.*to.*earn|achievement/gi.test(content)) {
    // Check for off-chain verification
    if (/off.*chain|backend|server.*verify/gi.test(content)) {
      if (!/signature.*verify|merkle.*proof|zero.*knowledge/gi.test(content)) {
        findings.push({
          id: 'SOL283',
          severity: 'high',
          title: 'Weak Off-Chain Verification',
          description: 'Off-chain game state not cryptographically verified on-chain. Aurory lost $830K when hackers exploited off-chain inventory system.',
          location: input.path,
          recommendation: 'Use cryptographic proofs (signatures, Merkle proofs) for all off-chain state claims. Never trust client-submitted data.',
        });
      }
    }
    
    // Check for claim rate limiting
    if (/claim|reward|withdraw/gi.test(content)) {
      if (!/rate.*limit|cooldown|daily.*cap/gi.test(content)) {
        findings.push({
          id: 'SOL283',
          severity: 'medium',
          title: 'Missing Reward Claim Limits',
          description: 'No rate limiting on reward claims. Exploiters can drain rewards faster than detection.',
          location: input.path,
          recommendation: 'Implement claim cooldowns and daily/weekly caps. Add anomaly detection for unusual claim patterns.',
        });
      }
    }
  }
  
  return findings;
}

// SOL284: SVT Token CertiK Alert Pattern
export function checkCertiKAlertPatterns(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  if (!input.rust) return findings;
  const content = input.rust.content;
  
  // Check for token patterns
  if (/token|mint|supply/gi.test(content)) {
    // Check for blacklist/freeze capability
    if (/blacklist|freeze|block.*address/gi.test(content)) {
      findings.push({
        id: 'SOL284',
        severity: 'medium',
        title: 'Token Blacklist/Freeze Capability',
        description: 'Token has blacklist or freeze capability. While legitimate for compliance, this can be used maliciously to trap user funds.',
        location: input.path,
        recommendation: 'If blacklist/freeze needed, implement transparent governance. Document when and why accounts may be frozen.',
      });
    }
    
    // Check for unlimited minting
    if (/mint/gi.test(content)) {
      if (!/max.*supply|cap|limit.*mint/gi.test(content)) {
        findings.push({
          id: 'SOL284',
          severity: 'high',
          title: 'Uncapped Token Supply',
          description: 'Token has no maximum supply cap. Unlimited minting can dilute holders. CertiK flagged SVT token for hidden unlimited mint.',
          location: input.path,
          recommendation: 'Implement maximum supply cap. Make supply schedule transparent and immutable.',
        });
      }
    }
  }
  
  return findings;
}

// SOL285: Synthetify DAO Hidden Minting
export function checkHiddenMintingPatterns(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  if (!input.rust) return findings;
  const content = input.rust.content;
  
  // Check for mint patterns
  if (/mint/gi.test(content)) {
    // Check for obfuscated mint calls
    const obfuscationPatterns = [
      /internal.*mint|_mint|private.*mint/gi,
      /mint.*internal|create.*token.*internal/gi,
      /hidden|secret|backdoor/gi,
    ];
    
    for (const pattern of obfuscationPatterns) {
      if (pattern.test(content)) {
        findings.push({
          id: 'SOL285',
          severity: 'critical',
          title: 'Potentially Hidden Minting Function',
          description: 'Mint function may be hidden or obfuscated. Synthetify DAO had hidden minting that allowed unauthorized token creation.',
          location: input.path,
          recommendation: 'All minting functions should be clearly documented and publicly visible. Remove any hidden or internal-only minting.',
        });
        break;
      }
    }
    
    // Check for governance minting
    if (/dao|governance/gi.test(content) && /mint/gi.test(content)) {
      if (!/vote.*mint|proposal.*mint|timelock.*mint/gi.test(content)) {
        findings.push({
          id: 'SOL285',
          severity: 'high',
          title: 'DAO Minting Without Governance Vote',
          description: 'DAO can mint tokens without proper governance voting process.',
          location: input.path,
          recommendation: 'All DAO minting should require full governance vote with timelock. Make emission schedule transparent.',
        });
      }
    }
  }
  
  return findings;
}

// SOL286: Saga DAO Governance Attack
export function checkDaoGovernanceAttack(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  if (!input.rust) return findings;
  const content = input.rust.content;
  
  // Check for DAO/voting patterns
  if (/dao|governance|voting|proposal/gi.test(content)) {
    // Check for vote buying protection
    if (!/commit.*reveal|secret.*vote|encrypted.*vote/gi.test(content)) {
      findings.push({
        id: 'SOL286',
        severity: 'high',
        title: 'Vulnerable to Vote Buying',
        description: 'Votes are publicly visible before close. Enables vote buying and last-minute manipulation. Saga DAO suffered governance attack.',
        location: input.path,
        recommendation: 'Implement commit-reveal voting scheme. Votes should be encrypted until voting period ends.',
      });
    }
    
    // Check for flash loan governance attack
    if (!/snapshot|block.*based.*voting|checkpoint/gi.test(content)) {
      findings.push({
        id: 'SOL286',
        severity: 'critical',
        title: 'Flash Loan Governance Attack Vector',
        description: 'Voting power not snapshotted. Attackers can use flash loans to temporarily gain voting power.',
        location: input.path,
        recommendation: 'Snapshot voting power at proposal creation. Use time-weighted voting power.',
      });
    }
  }
  
  return findings;
}

// SOL287: NoOnes Platform P2P Exploit
export function checkP2pPlatformExploit(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  if (!input.rust) return findings;
  const content = input.rust.content;
  
  // Check for P2P/escrow patterns
  if (/p2p|escrow|trade.*peer|dispute/gi.test(content)) {
    // Check for dispute resolution
    if (!/arbiter|dispute.*resolution|mediator/gi.test(content)) {
      findings.push({
        id: 'SOL287',
        severity: 'high',
        title: 'Missing Dispute Resolution',
        description: 'P2P trading without dispute resolution mechanism. NoOnes lost $4M to targeted account theft. Disputes can freeze user funds indefinitely.',
        location: input.path,
        recommendation: 'Implement robust dispute resolution with neutral arbiters. Add time limits for dispute escalation.',
      });
    }
    
    // Check for identity verification
    if (!/kyc|identity|verify.*user/gi.test(content)) {
      findings.push({
        id: 'SOL287',
        severity: 'medium',
        title: 'No Identity Verification for P2P',
        description: 'P2P trading without identity verification enables fraud and account theft.',
        location: input.path,
        recommendation: 'Implement identity verification for high-value trades. Use reputation systems for trust.',
      });
    }
  }
  
  return findings;
}

// SOL288: Loopscale Exploit Pattern (Flash Loan + Undercollateralized Position)
export function checkLoopscaleExploitPattern(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  if (!input.rust) return findings;
  const content = input.rust.content;
  
  // Check for lending/borrowing patterns
  if (/lend|borrow|collateral|loan/gi.test(content)) {
    // Check for collateralization ratio validation
    if (!/collateral.*ratio|ltv|loan.*to.*value|health.*factor/gi.test(content)) {
      findings.push({
        id: 'SOL288',
        severity: 'critical',
        title: 'Missing Collateralization Ratio Check',
        description: 'No collateralization ratio validation. Loopscale lost $5.8M to undercollateralized positions via flash loan manipulation.',
        location: input.path,
        recommendation: 'Always validate collateralization ratio. Implement minimum collateral requirements that cannot be bypassed.',
      });
    }
    
    // Check for same-transaction manipulation
    if (!/same.*transaction.*check|atomic.*borrow|flash.*loan.*guard/gi.test(content)) {
      findings.push({
        id: 'SOL288',
        severity: 'high',
        title: 'Same-Transaction Manipulation Possible',
        description: 'Position can be opened and manipulated in same transaction. Flash loans enable complex attacks.',
        location: input.path,
        recommendation: 'Add delays between position opening and borrowing. Prevent same-transaction collateral manipulation.',
      });
    }
  }
  
  return findings;
}

// SOL289: Candy Machine NFT Minting DoS
export function checkNftMintingDosPattern(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  if (!input.rust) return findings;
  const content = input.rust.content;
  
  // Check for NFT minting patterns
  if (/nft|mint.*collection|candy.*machine|token.*metadata/gi.test(content)) {
    // Check for bot protection
    if (!/captcha|bot.*protection|rate.*limit|proof.*of.*human/gi.test(content)) {
      findings.push({
        id: 'SOL289',
        severity: 'medium',
        title: 'NFT Mint Bot Vulnerability',
        description: 'NFT minting without bot protection. Bots can snipe all mints or DoS the network. The 2022 Candy Machine minting caused network-wide outages.',
        location: input.path,
        recommendation: 'Implement bot mitigation: rate limiting, proof-of-personhood, or randomized mint queues.',
      });
    }
    
    // Check for compute optimization
    if (/mint/gi.test(content)) {
      if (!/compute.*budget|optimize|batch/gi.test(content)) {
        findings.push({
          id: 'SOL289',
          severity: 'low',
          title: 'NFT Mint Compute Optimization',
          description: 'NFT minting may not be compute-optimized. High-demand mints can fail or congest network.',
          location: input.path,
          recommendation: 'Optimize minting for minimal compute units. Implement proper compute budget requests.',
        });
      }
    }
  }
  
  return findings;
}

// SOL290: Phantom Wallet DDoS Pattern
export function checkWalletDdosPattern(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  if (!input.rust) return findings;
  const content = input.rust.content;
  
  // Check for RPC/endpoint patterns
  if (/rpc|endpoint|api.*call|fetch.*data/gi.test(content)) {
    // Check for rate limiting
    if (!/rate.*limit|throttle|backoff|retry.*limit/gi.test(content)) {
      findings.push({
        id: 'SOL290',
        severity: 'medium',
        title: 'Missing API Rate Limiting',
        description: 'No rate limiting on API/RPC calls. Can be DDoSed or cause service degradation. Phantom wallet suffered DDoS in 2023.',
        location: input.path,
        recommendation: 'Implement rate limiting and exponential backoff. Use multiple RPC endpoints with failover.',
      });
    }
    
    // Check for RPC failover
    if (!/failover|fallback.*rpc|multiple.*endpoint/gi.test(content)) {
      findings.push({
        id: 'SOL290',
        severity: 'low',
        title: 'Single RPC Endpoint',
        description: 'Application may use single RPC endpoint without failover. Single point of failure for availability.',
        location: input.path,
        recommendation: 'Use multiple RPC endpoints with automatic failover. Monitor RPC health.',
      });
    }
  }
  
  return findings;
}
