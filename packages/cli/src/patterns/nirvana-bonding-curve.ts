import type { Finding } from '../commands/audit.js';
import type { ParsedIdl } from '../parsers/idl.js';
import type { ParsedRust } from '../parsers/rust.js';

/**
 * SOL245: Nirvana Finance-style Bonding Curve Exploit
 * Detects bonding curve and AMM pricing vulnerabilities
 * Reference: Nirvana Finance exploit (July 2022) - $3.5M stolen via flash loan + bonding curve manipulation
 */
export function checkNirvanaBondingCurve(idl: ParsedIdl | null, rust: ParsedRust | null): Finding[] {
  const findings: Finding[] = [];

  if (rust) {
    for (const fn of rust.functions) {
      const content = fn.body.toLowerCase();

      // Check for bonding curve pricing
      if (content.includes('bonding_curve') || content.includes('pricing_curve') ||
          content.includes('mint_price') || content.includes('burn_price')) {
        
        // Check for flash loan vulnerability
        if (!content.includes('flash_loan_check') && !content.includes('same_block') &&
            !content.includes('time_delay')) {
          findings.push({
            id: 'SOL245',
            severity: 'critical',
            title: 'Bonding Curve Without Flash Loan Protection',
            description: 'Bonding curve can be manipulated within single transaction. Nirvana lost $3.5M to this attack.',
            location: `Function: ${fn.name}`,
            recommendation: 'Add flash loan protection: require time delay between large price-affecting operations.',
          });
        }

        // Check for slippage in curve operations
        if (!content.includes('slippage') && !content.includes('min_return') && 
            !content.includes('max_price')) {
          findings.push({
            id: 'SOL245',
            severity: 'high',
            title: 'Bonding Curve Without Slippage Control',
            description: 'Bonding curve operations lack slippage protection. Users can receive far less than expected.',
            location: `Function: ${fn.name}`,
            recommendation: 'Add slippage parameters and validate: actual_price within acceptable range of expected_price.',
          });
        }

        // Check for reserve validation
        if (!content.includes('reserve') || !content.includes('validate')) {
          findings.push({
            id: 'SOL245',
            severity: 'high',
            title: 'Bonding Curve Reserve Not Validated',
            description: 'Bonding curve may not validate reserve backing. Undercollateralized curves can be exploited.',
            location: `Function: ${fn.name}`,
            recommendation: 'Validate total token supply is backed by curve reserves before each mint/burn.',
          });
        }
      }

      // Check for flash loan + mint combination
      if (content.includes('flash_loan') || content.includes('flash_borrow')) {
        if (content.includes('mint') || content.includes('buy')) {
          findings.push({
            id: 'SOL245',
            severity: 'critical',
            title: 'Flash Loan Near Minting',
            description: 'Flash loan used near token minting. This is the exact pattern used in Nirvana attack.',
            location: `Function: ${fn.name}`,
            recommendation: 'Prevent flash-loaned funds from being used for minting in same transaction.',
          });
        }
      }

      // Check for price impact calculations
      if (content.includes('price_impact') || content.includes('market_impact')) {
        if (!content.includes('max_impact') && !content.includes('limit')) {
          findings.push({
            id: 'SOL245',
            severity: 'medium',
            title: 'Unbounded Price Impact',
            description: 'No maximum price impact limit. Large trades could move price excessively.',
            location: `Function: ${fn.name}`,
            recommendation: 'Limit maximum price impact per transaction. Split large trades automatically.',
          });
        }
      }

      // Check for virtual reserves pattern
      if (content.includes('virtual_reserve') || content.includes('virtual_liquidity')) {
        if (!content.includes('real_reserve') && !content.includes('actual_balance')) {
          findings.push({
            id: 'SOL245',
            severity: 'high',
            title: 'Virtual Reserves Without Real Backing',
            description: 'Virtual reserves detected without real balance validation. Could lead to insolvency.',
            location: `Function: ${fn.name}`,
            recommendation: 'Always validate virtual reserves against actual token balances in vault.',
          });
        }
      }

      // Check for constant product formula
      if (content.includes('x * y') || content.includes('constant_product') || 
          content.includes('xy=k') || content.includes('k_constant')) {
        if (!content.includes('fee') || !content.includes('protocol')) {
          findings.push({
            id: 'SOL245',
            severity: 'low',
            title: 'AMM Without Fee',
            description: 'Constant product AMM without trading fee. Arbitrageurs will extract value.',
            location: `Function: ${fn.name}`,
            recommendation: 'Include trading fee (typically 0.3%). Direct portion to liquidity providers.',
          });
        }
      }

      // Check for floor price mechanisms
      if (content.includes('floor_price') || content.includes('minimum_price') ||
          content.includes('backing_value')) {
        if (!content.includes('treasury') || !content.includes('protocol_owned')) {
          findings.push({
            id: 'SOL245',
            severity: 'medium',
            title: 'Floor Price Without Treasury Backing',
            description: 'Floor price mechanism without protocol-owned backing. Floor may not be maintainable.',
            location: `Function: ${fn.name}`,
            recommendation: 'Ensure floor price is backed by protocol-owned reserves that cannot be drained.',
          });
        }
      }

      // Check for rebasing token patterns
      if (content.includes('rebase') || content.includes('elastic_supply')) {
        if (!content.includes('snapshot') && !content.includes('checkpoint')) {
          findings.push({
            id: 'SOL245',
            severity: 'high',
            title: 'Rebasing Token Without Snapshots',
            description: 'Rebasing token lacks snapshots. Interactions with lending/AMMs may be exploitable.',
            location: `Function: ${fn.name}`,
            recommendation: 'Implement balance snapshots. Warn integrators about rebase mechanics.',
          });
        }
      }

      // Check for buy/sell asymmetry
      if ((content.includes('buy') || content.includes('mint')) && 
          (content.includes('sell') || content.includes('burn'))) {
        if (content.includes('fee')) {
          const buyFeeMatch = content.match(/buy.*fee.*(\d+)/);
          const sellFeeMatch = content.match(/sell.*fee.*(\d+)/);
          // Can't accurately compare, but flag if significantly different patterns
          if (content.includes('buy_fee') && content.includes('sell_fee') && 
              !content.includes('symmetric') && !content.includes('equal')) {
            findings.push({
              id: 'SOL245',
              severity: 'low',
              title: 'Asymmetric Buy/Sell Fees',
              description: 'Different fees for buy vs sell. May create arbitrage opportunities.',
              location: `Function: ${fn.name}`,
              recommendation: 'Document fee asymmetry clearly. Consider implications for arbitrage.',
            });
          }
        }
      }
    }
  }

  if (idl) {
    // Check for curve-related instructions
    for (const instruction of idl.instructions) {
      const name = instruction.name.toLowerCase();
      
      if (name.includes('mint') || name.includes('buy') || name.includes('curve')) {
        // Check for oracle/price account
        const hasPriceInput = instruction.accounts.some(acc => 
          acc.name.toLowerCase().includes('price') ||
          acc.name.toLowerCase().includes('oracle')
        );

        if (!hasPriceInput && name.includes('curve')) {
          findings.push({
            id: 'SOL245',
            severity: 'medium',
            title: 'Bonding Curve Without External Price Reference',
            description: `${instruction.name} lacks external price reference. Curve can diverge from market.`,
            location: `Instruction: ${instruction.name}`,
            recommendation: 'Consider oracle integration for curve pricing or rate limiting.',
          });
        }
      }
    }
  }

  return findings;
}
