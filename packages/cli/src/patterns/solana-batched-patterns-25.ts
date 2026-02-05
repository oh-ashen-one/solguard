// SOL744: Additional Security Patterns Based on Helius Exploit Research
// Comprehensive patterns from Solana security history analysis (38 sub-patterns)

import type { ParsedRust } from '../parsers/rust.js';
import type { Finding } from '../commands/audit.js';
import type { PatternInput } from './index.js';

/**
 * Additional patterns from comprehensive Helius research covering:
 * - Application exploits (26 incidents)
 * - Supply chain attacks (2 incidents)
 * - Network-level attacks (4 incidents)
 * - Core protocol vulnerabilities (6 incidents)
 */

export function checkBatchedPatterns25(parsed: ParsedRust): Finding[] {
  const findings: Finding[] = [];

  // SOL683: SVT Token CertiK Alert Pattern
  const tokenEmissionPatterns = [
    /mint_to|create_token|emit_token/i,
    /total_supply.*increase|increase.*supply/i,
  ];

  for (const func of parsed.functions) {
    const content = func.content.toLowerCase();
    
    if (tokenEmissionPatterns.some(p => p.test(content))) {
      if (!/max_supply|supply_cap|hard_cap/i.test(content)) {
        findings.push({
          id: 'SOL683',
          severity: 'high',
          title: 'SVT-style Uncapped Token Emission',
          description: `Function '${func.name}' mints tokens without supply cap`,
          location: func.location,
          recommendation: 'Implement hard supply cap and validate against max supply on every mint.',
        });
      }
    }
  }

  // SOL684: io.net GPU Node Compromise Pattern
  const nodeValidationPatterns = [
    /node_registration|register_node|add_worker/i,
    /compute_provider|gpu_node|worker_join/i,
  ];

  for (const func of parsed.functions) {
    const content = func.content.toLowerCase();
    
    if (nodeValidationPatterns.some(p => p.test(content))) {
      if (!/proof_of_work|hardware_attestation|challenge_response/i.test(content)) {
        findings.push({
          id: 'SOL684',
          severity: 'high',
          title: 'Node Registration Without Hardware Attestation',
          description: `Function '${func.name}' registers nodes without hardware verification`,
          location: func.location,
          recommendation: 'Implement hardware attestation or proof-of-work challenges for node registration.',
        });
      }
    }
  }

  // SOL685: Parcl Frontend Compromise Pattern
  const frontendSecurityPatterns = [
    /user_input|form_data|request_body/i,
    /api_call|fetch_data|http_request/i,
  ];

  for (const func of parsed.functions) {
    const content = func.content.toLowerCase();
    
    if (frontendSecurityPatterns.some(p => p.test(content))) {
      if (!/csp_header|content_security|integrity_check/i.test(content)) {
        findings.push({
          id: 'SOL685',
          severity: 'medium',
          title: 'Frontend Security Policy Missing',
          description: `Function '${func.name}' handles user input without content security`,
          location: func.location,
          recommendation: 'Implement Content Security Policy (CSP), subresource integrity, and input validation.',
        });
      }
    }
  }

  // SOL686: Web3.js Supply Chain Attack Pattern
  const dependencyPatterns = [
    /require|import|use\s+crate/i,
    /dependency|external_lib/i,
  ];

  for (const func of parsed.functions) {
    const content = func.content.toLowerCase();
    
    if (dependencyPatterns.some(p => p.test(content))) {
      if (/solana_sdk|anchor_lang|spl_token/i.test(content)) {
        findings.push({
          id: 'SOL686',
          severity: 'info',
          title: 'External Dependency Usage',
          description: `Function '${func.name}' uses external Solana dependencies`,
          location: func.location,
          recommendation: 'Pin dependency versions, verify package integrity, and monitor for security advisories.',
        });
      }
    }
  }

  // SOL687: Grape Protocol Network Attack Pattern
  const networkLoadPatterns = [
    /rate_limit|throttle|backpressure/i,
    /max_connections|connection_pool/i,
  ];

  for (const func of parsed.functions) {
    const content = func.content.toLowerCase();
    
    if (/network|rpc|websocket/i.test(content)) {
      if (!networkLoadPatterns.some(p => p.test(content))) {
        findings.push({
          id: 'SOL687',
          severity: 'medium',
          title: 'Network Endpoint Without Rate Limiting',
          description: `Function '${func.name}' handles network traffic without rate limiting`,
          location: func.location,
          recommendation: 'Implement rate limiting and backpressure mechanisms for network endpoints.',
        });
      }
    }
  }

  // SOL688: Candy Machine Minting Attack Pattern
  const mintingDosPatterns = [
    /candy_machine|nft_mint|collection_mint/i,
    /mint_nft|create_nft/i,
  ];

  for (const func of parsed.functions) {
    const content = func.content.toLowerCase();
    
    if (mintingDosPatterns.some(p => p.test(content))) {
      if (!/queue|fair_launch|whitelist/i.test(content)) {
        findings.push({
          id: 'SOL688',
          severity: 'medium',
          title: 'NFT Minting Without Fair Launch Protection',
          description: `Function '${func.name}' handles minting without queue or whitelist`,
          location: func.location,
          recommendation: 'Implement queuing, whitelists, or hidden reveal mechanisms for fair NFT launches.',
        });
      }
    }
  }

  // SOL689: Jito DDoS Pattern
  const mevPatterns = [
    /bundle|jito|mev/i,
    /tip|priority_fee|bribe/i,
  ];

  for (const func of parsed.functions) {
    const content = func.content.toLowerCase();
    
    if (mevPatterns.some(p => p.test(content))) {
      if (!/rate_limit|max_bundles|bundle_cap/i.test(content)) {
        findings.push({
          id: 'SOL689',
          severity: 'medium',
          title: 'MEV Bundle Processing Without Limits',
          description: `Function '${func.name}' processes MEV bundles without rate limiting`,
          location: func.location,
          recommendation: 'Implement bundle rate limits and priority fee caps to prevent DoS attacks.',
        });
      }
    }
  }

  // SOL690: Phantom Wallet DDoS Pattern
  const walletRpcPatterns = [
    /get_account_info|get_balance|fetch_tokens/i,
    /rpc_call|rpc_request/i,
  ];

  for (const func of parsed.functions) {
    const content = func.content.toLowerCase();
    
    if (walletRpcPatterns.some(p => p.test(content))) {
      if (!/cache|memoize|debounce/i.test(content)) {
        findings.push({
          id: 'SOL690',
          severity: 'low',
          title: 'RPC Calls Without Caching',
          description: `Function '${func.name}' makes RPC calls without visible caching`,
          location: func.location,
          recommendation: 'Cache RPC responses and implement request debouncing to reduce load.',
        });
      }
    }
  }

  // SOL691-695: Core Protocol Vulnerability Patterns
  const protocolPatterns = [
    { id: 'SOL691', name: 'Turbine Propagation', pattern: /turbine|shred|block_propagation/i },
    { id: 'SOL692', name: 'Durable Nonce', pattern: /durable_nonce|advance_nonce/i },
    { id: 'SOL693', name: 'Duplicate Block', pattern: /block_hash|recent_blockhash/i },
    { id: 'SOL694', name: 'JIT Cache', pattern: /jit|just_in_time|cache_compile/i },
    { id: 'SOL695', name: 'ELF Alignment', pattern: /elf|bpf_loader|program_data/i },
  ];

  for (const func of parsed.functions) {
    const content = func.content.toLowerCase();
    
    for (const proto of protocolPatterns) {
      if (proto.pattern.test(content)) {
        findings.push({
          id: proto.id,
          severity: 'info',
          title: `${proto.name} Handling Detected`,
          description: `Function '${func.name}' handles ${proto.name.toLowerCase()} operations`,
          location: func.location,
          recommendation: `Follow Solana best practices for ${proto.name.toLowerCase()} handling. Check for recent security advisories.`,
        });
      }
    }
  }

  // SOL696-700: Stablecoin Specific Patterns
  const stablecoinPatterns = [
    /stablecoin|pegged|dollar_value/i,
    /collateral_ratio|backing_ratio/i,
    /depeg|peg_break|price_deviation/i,
  ];

  for (const func of parsed.functions) {
    const content = func.content.toLowerCase();
    
    if (stablecoinPatterns.some(p => p.test(content))) {
      // Check for collateral ratio enforcement
      if (!/min_collateral|collateral_check|undercollateralized/i.test(content)) {
        findings.push({
          id: 'SOL696',
          severity: 'critical',
          title: 'Stablecoin Without Collateral Check',
          description: `Function '${func.name}' handles stablecoin without collateral verification`,
          location: func.location,
          recommendation: 'Always verify collateral ratio before minting. Implement circuit breakers for depeg events.',
        });
      }

      // Check for depeg circuit breaker
      if (!/circuit_breaker|pause_mint|depeg_halt/i.test(content)) {
        findings.push({
          id: 'SOL697',
          severity: 'high',
          title: 'Missing Depeg Circuit Breaker',
          description: `Function '${func.name}' lacks depeg protection mechanism`,
          location: func.location,
          recommendation: 'Implement automatic minting halt when price deviates more than 5% from peg.',
        });
      }
    }
  }

  // SOL698-700: Bot/Trading Security Patterns
  const botPatterns = [
    /trading_bot|auto_trade|bot_strategy/i,
    /sniper|frontrun|backrun/i,
  ];

  for (const func of parsed.functions) {
    const content = func.content.toLowerCase();
    
    if (botPatterns.some(p => p.test(content))) {
      if (!/signature_verify|owner_check/i.test(content)) {
        findings.push({
          id: 'SOL698',
          severity: 'high',
          title: 'Trading Bot Without Auth Verification',
          description: `Function '${func.name}' executes trades without proper authorization`,
          location: func.location,
          recommendation: 'Require signature verification for all trade executions. Never store private keys on servers.',
        });
      }

      if (!/slippage|max_loss|stop_loss/i.test(content)) {
        findings.push({
          id: 'SOL699',
          severity: 'medium',
          title: 'Trading Without Loss Limits',
          description: `Function '${func.name}' executes trades without loss protection`,
          location: func.location,
          recommendation: 'Implement slippage limits, stop-losses, and maximum loss per epoch.',
        });
      }

      if (!/withdrawal_limit|daily_cap/i.test(content)) {
        findings.push({
          id: 'SOL700',
          severity: 'medium',
          title: 'Bot Without Withdrawal Limits',
          description: `Function '${func.name}' allows unlimited bot withdrawals`,
          location: func.location,
          recommendation: 'Set daily/hourly withdrawal limits and require manual approval for large amounts.',
        });
      }
    }
  }

  // SOL701-710: Protocol Recovery Patterns
  const recoveryPatterns = [
    /emergency|recovery|rescue/i,
    /pause|halt|freeze_protocol/i,
  ];

  for (const func of parsed.functions) {
    const content = func.content.toLowerCase();
    
    if (recoveryPatterns.some(p => p.test(content))) {
      // SOL701: Emergency pause without timelock bypass
      if (/pause|halt/i.test(content) && !/immediate|bypass_timelock/i.test(content)) {
        findings.push({
          id: 'SOL701',
          severity: 'info',
          title: 'Emergency Pause May Have Timelock',
          description: `Function '${func.name}' implements pause but may be subject to timelock`,
          location: func.location,
          recommendation: 'Ensure emergency pause can bypass normal timelocks for rapid response.',
        });
      }

      // SOL702: Recovery fund allocation
      if (!/insurance_fund|recovery_fund|reserve/i.test(content)) {
        findings.push({
          id: 'SOL702',
          severity: 'medium',
          title: 'Missing Insurance/Recovery Fund',
          description: `Function '${func.name}' handles emergencies without visible insurance fund`,
          location: func.location,
          recommendation: 'Maintain insurance fund (suggested: 5-10% of TVL) for user reimbursements.',
        });
      }
    }
  }

  // SOL703-710: Response Time Optimization
  const monitoringPatterns = [
    /alert|notify|webhook/i,
    /monitor|watch|observe/i,
  ];

  for (const func of parsed.functions) {
    const content = func.content.toLowerCase();
    
    if (/exploit|attack|suspicious/i.test(content)) {
      if (!monitoringPatterns.some(p => p.test(content))) {
        findings.push({
          id: 'SOL703',
          severity: 'medium',
          title: 'Exploit Detection Without Alerting',
          description: `Function '${func.name}' detects exploits without visible alerting mechanism`,
          location: func.location,
          recommendation: 'Implement real-time alerting (PagerDuty, Discord webhooks) for suspicious activity.',
        });
      }
    }
  }

  // SOL704-710: Historical Exploit Learning Patterns
  const historicalPatterns = [
    { id: 'SOL704', name: 'Wormhole-style Bridge', pattern: /bridge|cross_chain|wrapped/i, risk: 'signature validation' },
    { id: 'SOL705', name: 'Cashio-style Collateral', pattern: /collateral|backing|reserve/i, risk: 'root of trust' },
    { id: 'SOL706', name: 'Mango-style Oracle', pattern: /oracle|price_feed|twap/i, risk: 'manipulation' },
    { id: 'SOL707', name: 'Slope-style Key', pattern: /private_key|seed_phrase|mnemonic/i, risk: 'exposure' },
    { id: 'SOL708', name: 'DEXX-style Leak', pattern: /api_key|secret|credential/i, risk: 'server leak' },
    { id: 'SOL709', name: 'Pump.fun-style Insider', pattern: /admin|authority|privileged/i, risk: 'insider access' },
    { id: 'SOL710', name: 'Banana Gun-style Bot', pattern: /trading_bot|auto_execute|bot_wallet/i, risk: 'private key theft' },
  ];

  for (const func of parsed.functions) {
    const content = func.content.toLowerCase();
    
    for (const hist of historicalPatterns) {
      if (hist.pattern.test(content)) {
        findings.push({
          id: hist.id,
          severity: 'info',
          title: `${hist.name} Pattern Detected`,
          description: `Function '${func.name}' uses patterns similar to ${hist.name.split('-')[0]} exploit vector`,
          location: func.location,
          recommendation: `Review for ${hist.risk} vulnerabilities. See Helius blog for detailed exploit analysis.`,
        });
      }
    }
  }

  // SOL711-720: Future-Proofing Patterns
  const emergingThreats = [
    { id: 'SOL711', name: 'AI-Assisted Attack', pattern: /ai_|machine_learning|automated_exploit/i },
    { id: 'SOL712', name: 'Quantum Risk', pattern: /quantum|post_quantum|lattice/i },
    { id: 'SOL713', name: 'ZK Proof Vulnerability', pattern: /zk_proof|zero_knowledge|snark/i },
    { id: 'SOL714', name: 'FHE Risk', pattern: /fhe|fully_homomorphic|encrypted_compute/i },
    { id: 'SOL715', name: 'MPC Coordination', pattern: /mpc|multi_party|threshold_sig/i },
    { id: 'SOL716', name: 'TEE Bypass', pattern: /tee|secure_enclave|sgx/i },
    { id: 'SOL717', name: 'Side Channel', pattern: /timing_attack|cache_attack|power_analysis/i },
    { id: 'SOL718', name: 'Sandwich V2', pattern: /sandwich|frontrun|backrun/i },
    { id: 'SOL719', name: 'JIT Liquidity', pattern: /jit_liquidity|just_in_time_lp/i },
    { id: 'SOL720', name: 'Intent-Based Attack', pattern: /intent|order_flow|rfi/i },
  ];

  for (const func of parsed.functions) {
    const content = func.content.toLowerCase();
    
    for (const threat of emergingThreats) {
      if (threat.pattern.test(content)) {
        findings.push({
          id: threat.id,
          severity: 'info',
          title: `${threat.name} Technology Detected`,
          description: `Function '${func.name}' uses ${threat.name.toLowerCase()} patterns`,
          location: func.location,
          recommendation: `Stay updated on emerging ${threat.name.toLowerCase()} security research.`,
        });
      }
    }
  }

  return findings;
}

// Export all batched patterns
export function checkAllBatch25Patterns(input: PatternInput): Finding[] {
  if (!input.rust) return [];
  return checkBatchedPatterns25(input.rust);
}
