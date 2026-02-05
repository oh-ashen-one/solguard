/**
 * SolGuard Batched Patterns 33 - Network & Infrastructure Security
 * Based on Helius research: Network-Level Attacks + Core Protocol Vulnerabilities
 * Feb 5, 2026 - 6:30 AM CST
 */

import type { Finding } from '../commands/audit.js';
import type { ParsedIdl } from '../parsers/idl.js';
import type { ParsedRust } from '../parsers/rust.js';

interface PatternInput {
  idl?: ParsedIdl;
  rust?: ParsedRust;
  content?: string;
  contractAddress?: string;
  network?: string;
}

// SOL869: Grape Protocol-Style Network Congestion Attack
export function checkNetworkCongestionAttack(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  const content = input.rust?.content || input.content || '';
  
  // Check for patterns vulnerable to network congestion
  const hasTimeSensitiveOps = /deadline|expiry|timeout|timestamp.*check/i.test(content);
  const hasNoRetry = !/(retry|backoff|fallback|queue)/i.test(content);
  const hasNoGracePeriod = !/(grace.*period|extension|buffer.*time)/i.test(content);
  
  if (hasTimeSensitiveOps && hasNoRetry && hasNoGracePeriod) {
    findings.push({
      id: 'SOL869',
      title: 'Network Congestion Attack Vulnerability',
      severity: 'medium',
      description: 'Time-sensitive operations without retry logic or grace periods are vulnerable during network congestion. Grape Protocol incident caused 17-hour outage affecting dApps.',
      location: 'time_sensitive_operations',
      recommendation: 'Add retry logic with exponential backoff. Implement grace periods for deadlines. Use transaction queuing. Add fallback mechanisms for critical operations.'
    });
  }
  
  return findings;
}

// SOL870: Candy Machine-Style Minting DoS
export function checkMintingDoSVulnerability(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  const content = input.rust?.content || input.content || '';
  
  // Check for high-volume minting patterns
  const hasMinting = /mint|create_nft|candy.*machine|launch/i.test(content);
  const hasNoRateLimit = !/(rate.*limit|throttle|cooldown|max_per)/i.test(content);
  const hasNoBotProtection = !/(captcha|whitelist|merkle.*proof|signature)/i.test(content);
  
  if (hasMinting && hasNoRateLimit && hasNoBotProtection) {
    findings.push({
      id: 'SOL870',
      title: 'Candy Machine-Style Minting DoS Risk',
      severity: 'high',
      description: 'High-volume minting without rate limiting or bot protection can cause network congestion. Candy Machine V2 launch caused widespread outages.',
      location: 'minting_handler',
      recommendation: 'Implement rate limiting per wallet. Use whitelist/merkle proof for launches. Add bot protection mechanisms. Consider batch minting to reduce transaction count.'
    });
  }
  
  return findings;
}

// SOL871: Jito-Style DDoS via Bundle Spam
export function checkBundleSpamDoS(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  const content = input.rust?.content || input.content || '';
  
  // Check for bundle/MEV-related patterns
  const hasBundleIntegration = /jito|bundle|mev|priority.*fee|tip/i.test(content);
  const hasNoValidation = !/(validate.*bundle|bundle.*check|max.*bundle)/i.test(content);
  
  if (hasBundleIntegration && hasNoValidation) {
    findings.push({
      id: 'SOL871',
      title: 'Jito-Style Bundle Spam DoS Risk',
      severity: 'medium',
      description: 'MEV bundle integration without validation may be exploited for DoS attacks. Jito experienced DDoS via spam bundles affecting validator performance.',
      location: 'bundle_handler',
      recommendation: 'Validate bundle submissions. Implement spam filtering. Add rate limiting for bundle APIs. Monitor for unusual bundle patterns.'
    });
  }
  
  return findings;
}

// SOL872: Phantom-Style Wallet DoS
export function checkWalletDoSVulnerability(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  const content = input.rust?.content || input.content || '';
  
  // Check for patterns that could trigger wallet DoS
  const hasLargeAccountData = /account.*data|serialize|deserialize|buffer/i.test(content);
  const hasUnboundedSize = !/(max.*size|size.*limit|bounded)/i.test(content);
  const hasNFTHandling = /nft|token.*metadata|collection/i.test(content);
  
  if (hasLargeAccountData && hasUnboundedSize && hasNFTHandling) {
    findings.push({
      id: 'SOL872',
      title: 'Phantom-Style Wallet DoS via Malformed Data',
      severity: 'medium',
      description: 'Unbounded account data or malformed NFTs can cause wallet DoS. Phantom wallet experienced crashes from malicious NFT spam.',
      location: 'data_serialization',
      recommendation: 'Implement data size limits. Validate all deserialized data. Add error handling for malformed accounts. Use lazy loading for large collections.'
    });
  }
  
  return findings;
}

// SOL873: Turbine-Style Propagation Failure
export function checkTurbinePropagationRisk(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  const content = input.rust?.content || input.content || '';
  
  // Check for patterns dependent on consistent data propagation
  const hasDistributedState = /shred|propagate|replicate|consensus/i.test(content);
  const hasNoValidation = !/(validate.*shred|verify.*propagation|consistency.*check)/i.test(content);
  
  if (hasDistributedState && hasNoValidation) {
    findings.push({
      id: 'SOL873',
      title: 'Turbine-Style Propagation Failure Risk',
      severity: 'high',
      description: 'Distributed state without propagation validation may fail during network issues. Solana Turbine failures caused multi-hour outages.',
      location: 'distributed_state',
      recommendation: 'Implement propagation validation. Add redundancy for critical data. Monitor for inconsistencies. Use fallback mechanisms for data retrieval.'
    });
  }
  
  return findings;
}

// SOL874: Durable Nonce Expiry Attack
export function checkDurableNonceExpiry(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  const content = input.rust?.content || input.content || '';
  
  // Check for durable nonce usage patterns
  const hasDurableNonce = /durable.*nonce|nonce.*account|advance.*nonce/i.test(content);
  const hasNoExpiryCheck = !/(nonce.*valid|check.*nonce.*age|nonce.*expir)/i.test(content);
  
  if (hasDurableNonce && hasNoExpiryCheck) {
    findings.push({
      id: 'SOL874',
      title: 'Durable Nonce Expiry Vulnerability',
      severity: 'medium',
      description: 'Durable nonce usage without expiry validation may cause transaction failures. Solana had bugs with nonce account handling that caused outages.',
      location: 'nonce_handler',
      recommendation: 'Validate nonce account age before use. Implement nonce refresh logic. Add fallback for expired nonces. Monitor nonce account state.'
    });
  }
  
  return findings;
}

// SOL875: Duplicate Block Handling
export function checkDuplicateBlockHandling(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  const content = input.rust?.content || input.content || '';
  
  // Check for block/slot handling patterns
  const hasBlockHandling = /block|slot|leader.*schedule|fork/i.test(content);
  const hasNoDuplicateCheck = !/(duplicate.*check|seen.*before|dedup)/i.test(content);
  
  if (hasBlockHandling && hasNoDuplicateCheck) {
    findings.push({
      id: 'SOL875',
      title: 'Duplicate Block Handling Vulnerability',
      severity: 'high',
      description: 'Block handling without duplicate detection may cause consensus issues. Solana duplicate block bug caused validator crashes.',
      location: 'block_handler',
      recommendation: 'Implement duplicate block detection. Add block hash verification. Monitor for fork conditions. Use idempotent processing for blocks.'
    });
  }
  
  return findings;
}

// SOL876: JIT Cache Corruption
export function checkJITCacheCorruption(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  const content = input.rust?.content || input.content || '';
  
  // Check for caching patterns
  const hasCaching = /cache|jit|compiled|precompile/i.test(content);
  const hasNoValidation = !/(validate.*cache|cache.*integrity|checksum)/i.test(content);
  
  if (hasCaching && hasNoValidation) {
    findings.push({
      id: 'SOL876',
      title: 'JIT Cache Corruption Risk',
      severity: 'high',
      description: 'JIT compilation caching without validation may cause execution errors. Solana JIT cache bug caused 5-hour network outage.',
      location: 'cache_handler',
      recommendation: 'Validate cached data integrity. Implement cache invalidation. Add fallback for cache misses. Monitor for cache-related errors.'
    });
  }
  
  return findings;
}

// SOL877: ELF Address Alignment Exploit
export function checkELFAlignmentExploit(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  const content = input.rust?.content || input.content || '';
  
  // Check for binary/ELF handling patterns
  const hasBinaryHandling = /elf|binary|loader|program.*data|executable/i.test(content);
  const hasNoAlignmentCheck = !/(alignment|aligned|padding|boundary)/i.test(content);
  
  if (hasBinaryHandling && hasNoAlignmentCheck) {
    findings.push({
      id: 'SOL877',
      title: 'ELF Address Alignment Vulnerability',
      severity: 'medium',
      description: 'Binary/ELF handling without alignment validation may cause execution issues. Solana had ELF address alignment vulnerability affecting program execution.',
      location: 'binary_loader',
      recommendation: 'Validate address alignment for all binary data. Add boundary checks. Implement proper padding. Test with various alignment scenarios.'
    });
  }
  
  return findings;
}

// SOL878: Front-End Phishing Attack
export function checkFrontEndPhishingRisk(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  const content = input.rust?.content || input.content || '';
  
  // Check for frontend integration patterns
  const hasFrontendIntegration = /frontend|dapp|web.*app|ui/i.test(content);
  const hasTransactionSigning = /sign|approve|confirm|connect.*wallet/i.test(content);
  const hasNoVerification = !/(verify.*origin|check.*domain|content.*security)/i.test(content);
  
  if (hasFrontendIntegration && hasTransactionSigning && hasNoVerification) {
    findings.push({
      id: 'SOL878',
      title: 'Front-End Phishing Attack Risk (Parcl-style)',
      severity: 'high',
      description: 'Frontend integration without origin verification enables phishing. Parcl frontend was compromised, redirecting users to malicious sites.',
      location: 'frontend_integration',
      recommendation: 'Implement Subresource Integrity (SRI). Use Content Security Policy (CSP). Add domain verification. Educate users about phishing risks.'
    });
  }
  
  return findings;
}

// SOL879: Tulip Protocol Flash Loan Vulnerability
export function checkTulipStyleFlashLoan(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  const content = input.rust?.content || input.content || '';
  
  // Check for flash loan integration patterns
  const hasFlashLoan = /flash.*loan|borrow.*instant|same.*tx.*repay/i.test(content);
  const hasVaultStrategy = /vault|strategy|deposit.*withdraw|yield/i.test(content);
  const hasNoReentrancyGuard = !/(reentrancy|mutex|lock|guard)/i.test(content);
  
  if (hasFlashLoan && hasVaultStrategy && hasNoReentrancyGuard) {
    findings.push({
      id: 'SOL879',
      title: 'Tulip-Style Flash Loan Vault Vulnerability',
      severity: 'critical',
      description: 'Vault strategies with flash loan exposure without reentrancy guards are vulnerable. Tulip Protocol lost funds through flash loan manipulation.',
      location: 'vault_strategy',
      recommendation: 'Add reentrancy guards to all vault functions. Validate flash loan repayment atomically. Limit vault exposure per transaction. Add circuit breakers for unusual activity.'
    });
  }
  
  return findings;
}

// SOL880: UXD Protocol Depeg Risk
export function checkUXDStyleDepegRisk(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  const content = input.rust?.content || input.content || '';
  
  // Check for stablecoin/depeg patterns
  const hasStablecoin = /stablecoin|stable|peg|mint.*redeem/i.test(content);
  const hasCollateralDep = /collateral|backing|reserve|mango|perp/i.test(content);
  const hasNoDepegProtection = !/(depeg|circuit.*breaker|emergency.*redeem|backup.*collateral)/i.test(content);
  
  if (hasStablecoin && hasCollateralDep && hasNoDepegProtection) {
    findings.push({
      id: 'SOL880',
      title: 'UXD-Style Stablecoin Depeg Risk',
      severity: 'high',
      description: 'Stablecoin backed by DeFi positions may depeg if underlying protocol fails. UXD Protocol had depeg risk when Mango Markets was exploited.',
      location: 'stablecoin_backing',
      recommendation: 'Diversify collateral sources. Add circuit breakers for depeg scenarios. Implement emergency redemption. Monitor backing ratio continuously.'
    });
  }
  
  return findings;
}

// SOL881: SVT Token Unclaimed Vulnerability
export function checkSVTStyleUnclaimedVuln(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  const content = input.rust?.content || input.content || '';
  
  // Check for airdrop/claim patterns
  const hasAirdrop = /airdrop|claim|unclaimed|distribution/i.test(content);
  const hasTimedExpiry = /expiry|deadline|window|period/i.test(content);
  const hasNoAccessControl = !/(merkle|whitelist|signature.*verify|eligible)/i.test(content);
  
  if (hasAirdrop && hasTimedExpiry && hasNoAccessControl) {
    findings.push({
      id: 'SOL881',
      title: 'SVT-Style Unclaimed Token Vulnerability',
      severity: 'medium',
      description: 'Token distribution without proper access control may be exploited. SVT Token had vulnerability in unclaimed token handling.',
      location: 'token_distribution',
      recommendation: 'Use merkle proofs for airdrops. Implement proper eligibility checks. Add claim verification. Monitor for unusual claim patterns.'
    });
  }
  
  return findings;
}

// SOL882: io.net API Key Exposure
export function checkAPIKeyExposureRisk(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  const content = input.rust?.content || input.content || '';
  
  // Check for API key handling patterns
  const hasAPIKeys = /api.*key|secret|token|credential/i.test(content);
  const hasHardcoded = /(const|let|static).*=.*["'][a-zA-Z0-9]{20,}/i.test(content);
  const hasNoEnvVar = !/(env|dotenv|secret.*manager|vault)/i.test(content);
  
  if (hasAPIKeys && (hasHardcoded || hasNoEnvVar)) {
    findings.push({
      id: 'SOL882',
      title: 'io.net-Style API Key Exposure Risk',
      severity: 'high',
      description: 'API keys may be exposed through hardcoding or improper storage. io.net had API key exposure affecting user accounts.',
      location: 'api_key_handling',
      recommendation: 'Use environment variables for secrets. Implement secret rotation. Add key scoping and permissions. Monitor for leaked credentials.'
    });
  }
  
  return findings;
}

// SOL883: Aurory Smart Contract Exploit
export function checkAuroryStyleExploit(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  const content = input.rust?.content || input.content || '';
  
  // Check for gaming/NFT marketplace patterns
  const hasGameMarketplace = /game|marketplace|nft.*trade|in.*game/i.test(content);
  const hasRewardSystem = /reward|earn|mint.*reward|claim/i.test(content);
  const hasNoValidation = !/(validate.*action|verify.*ownership|anti.*cheat)/i.test(content);
  
  if (hasGameMarketplace && hasRewardSystem && hasNoValidation) {
    findings.push({
      id: 'SOL883',
      title: 'Aurory-Style Game Marketplace Exploit',
      severity: 'high',
      description: 'Gaming marketplace without action validation may be exploited. Aurory had smart contract exploit affecting marketplace.',
      location: 'game_marketplace',
      recommendation: 'Validate all game actions server-side. Implement anti-cheat mechanisms. Add rate limiting for rewards. Monitor for unusual patterns.'
    });
  }
  
  return findings;
}

// SOL884: Cross-Chain Message Verification
export function checkCrossChainMessageVerification(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  const content = input.rust?.content || input.content || '';
  
  // Check for cross-chain messaging patterns
  const hasCrossChain = /bridge|cross.*chain|wormhole|layerzero|message.*pass/i.test(content);
  const hasMessageHandling = /receive.*message|process.*message|verify.*message/i.test(content);
  const hasWeakVerification = !/(guardian|signature.*set|multi.*sig.*verify)/i.test(content);
  
  if (hasCrossChain && hasMessageHandling && hasWeakVerification) {
    findings.push({
      id: 'SOL884',
      title: 'Cross-Chain Message Verification Weakness',
      severity: 'critical',
      description: 'Cross-chain message handling without robust verification is vulnerable to spoofing. Wormhole lost $326M through signature verification flaw.',
      location: 'cross_chain_handler',
      recommendation: 'Require multi-sig guardian verification. Implement message replay protection. Add source chain validation. Use multiple independent oracles.'
    });
  }
  
  return findings;
}

// Export all pattern checkers
export const batchedPatterns33 = {
  checkNetworkCongestionAttack,
  checkMintingDoSVulnerability,
  checkBundleSpamDoS,
  checkWalletDoSVulnerability,
  checkTurbinePropagationRisk,
  checkDurableNonceExpiry,
  checkDuplicateBlockHandling,
  checkJITCacheCorruption,
  checkELFAlignmentExploit,
  checkFrontEndPhishingRisk,
  checkTulipStyleFlashLoan,
  checkUXDStyleDepegRisk,
  checkSVTStyleUnclaimedVuln,
  checkAPIKeyExposureRisk,
  checkAuroryStyleExploit,
  checkCrossChainMessageVerification
};

export default batchedPatterns33;
