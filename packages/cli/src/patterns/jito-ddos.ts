import type { Finding } from '../commands/audit.js';
import type { ParsedIdl } from '../parsers/idl.js';
import type { ParsedRust } from '../parsers/rust.js';

/**
 * SOL236: Jito/MEV DDoS Protection
 * Detects patterns vulnerable to MEV extraction and Jito bundle attacks
 * Reference: Jito DDoS incident, MEV sandwich attacks on Solana
 */
export function checkJitoDdos(idl: ParsedIdl | null, rust: ParsedRust | null): Finding[] {
  const findings: Finding[] = [];

  if (rust) {
    for (const fn of rust.functions) {
      const content = fn.body.toLowerCase();

      // Check for swap operations without slippage protection
      if (content.includes('swap') || content.includes('exchange') || content.includes('trade')) {
        if (!content.includes('slippage') && !content.includes('min_amount') && !content.includes('minimum_out')) {
          findings.push({
            id: 'SOL236',
            severity: 'high',
            title: 'Swap Without Slippage Protection',
            description: 'Swap operation detected without slippage check. MEV bots using Jito bundles can sandwich this transaction.',
            location: `Function: ${fn.name}`,
            recommendation: 'Add minimum output amount parameter and validate: require!(amount_out >= min_amount_out).',
          });
        }
      }

      // Check for price-sensitive operations
      if (content.includes('price') || content.includes('oracle')) {
        if (content.includes('transfer') || content.includes('mint') || content.includes('burn')) {
          if (!content.includes('twap') && !content.includes('time_weighted') && !content.includes('median')) {
            findings.push({
              id: 'SOL236',
              severity: 'medium',
              title: 'Price-Sensitive Operation Without TWAP',
              description: 'Critical operation uses spot price. MEV bundles can manipulate price within a single block.',
              location: `Function: ${fn.name}`,
              recommendation: 'Use TWAP (time-weighted average price) or median price across multiple slots for MEV resistance.',
            });
          }
        }
      }

      // Check for liquidation vulnerabilities
      if (content.includes('liquidat')) {
        if (!content.includes('grace_period') && !content.includes('delay') && !content.includes('cooldown')) {
          findings.push({
            id: 'SOL236',
            severity: 'medium',
            title: 'Liquidation Without Protection Period',
            description: 'Liquidation has no grace period. MEV bots can force-liquidate positions by manipulating price and instantly liquidating.',
            location: `Function: ${fn.name}`,
            recommendation: 'Add grace period between becoming liquidatable and actual liquidation. Consider partial liquidations.',
          });
        }
      }

      // Check for bundle-ordering vulnerabilities
      if (content.includes('invoke') && content.includes('signer_seeds')) {
        if (content.includes('amount') && !content.includes('deadline') && !content.includes('valid_until')) {
          findings.push({
            id: 'SOL236',
            severity: 'low',
            title: 'CPI Without Deadline',
            description: 'Cross-program invocation transfers value without deadline. Jito bundles can delay execution for profit.',
            location: `Function: ${fn.name}`,
            recommendation: 'Add transaction deadline: require!(Clock::get()?.slot <= deadline_slot).',
          });
        }
      }

      // Check for atomic arbitrage vectors
      if ((content.includes('flash_loan') || content.includes('flashloan')) && 
          (content.includes('repay') || content.includes('return'))) {
        if (!content.includes('same_transaction') && !content.includes('atomic')) {
          findings.push({
            id: 'SOL236',
            severity: 'medium',
            title: 'Flash Loan Without Atomicity Check',
            description: 'Flash loan may not enforce same-transaction repayment. MEV bots could exploit timing gaps.',
            location: `Function: ${fn.name}`,
            recommendation: 'Enforce flash loan repayment within the same transaction using instruction introspection.',
          });
        }
      }

      // Check for tip/priority fee handling
      if (content.includes('priority_fee') || content.includes('compute_budget') || content.includes('tip')) {
        if (content.includes('set_compute_unit_price') && !content.includes('max_fee')) {
          findings.push({
            id: 'SOL236',
            severity: 'low',
            title: 'Unbounded Priority Fee',
            description: 'Priority fee can be set without upper bound. Users could accidentally overpay during MEV competition.',
            location: `Function: ${fn.name}`,
            recommendation: 'Set reasonable maximum priority fee to protect users from fee wars.',
          });
        }
      }

      // Check for order book front-running
      if (content.includes('order') && (content.includes('place') || content.includes('submit'))) {
        if (!content.includes('hidden') && !content.includes('iceberg') && !content.includes('post_only')) {
          findings.push({
            id: 'SOL236',
            severity: 'low',
            title: 'Order Visible to MEV',
            description: 'Order placement is visible in mempool. Consider adding hidden order types or post-only mode.',
            location: `Function: ${fn.name}`,
            recommendation: 'Consider implementing hidden orders or using private mempool services like Jito for sensitive trades.',
          });
        }
      }
    }
  }

  if (idl) {
    // Check for missing slippage in IDL
    for (const instruction of idl.instructions) {
      const hasSwapLike = instruction.name.toLowerCase().includes('swap') || 
                          instruction.name.toLowerCase().includes('exchange');
      
      if (hasSwapLike) {
        const hasMinAmount = instruction.args.some(arg => 
          arg.name.toLowerCase().includes('min') || 
          arg.name.toLowerCase().includes('slippage')
        );
        
        if (!hasMinAmount) {
          findings.push({
            id: 'SOL236',
            severity: 'high',
            title: 'Swap Instruction Missing Slippage Parameter',
            description: `Instruction ${instruction.name} appears to be a swap but lacks minimum amount parameter.`,
            location: `Instruction: ${instruction.name}`,
            recommendation: 'Add min_amount_out: u64 parameter to protect users from MEV extraction.',
          });
        }
      }
    }
  }

  return findings;
}
