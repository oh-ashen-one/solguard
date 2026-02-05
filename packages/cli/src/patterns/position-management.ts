import type { Finding } from '../commands/audit.js';
import type { PatternInput } from './index.js';

export function checkPositionManagement(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  const content = input.rust?.content || '';
  const fileName = input.rust?.filePath || 'unknown';

  // Check for position size limits
  const positionPatterns = [
    /fn\s+open_position/gi,
    /fn\s+increase_position/gi,
    /fn\s+create_position/gi,
    /position_size/gi,
  ];

  for (const pattern of positionPatterns) {
    const matches = [...content.matchAll(pattern)];
    for (const match of matches) {
      const contextEnd = Math.min(content.length, match.index! + 1500);
      const functionContext = content.substring(match.index!, contextEnd);
      
      // Check for max position size
      if (!functionContext.includes('max_size') && !functionContext.includes('max_position') &&
          !functionContext.includes('limit') && !functionContext.includes('cap')) {
        const lineNumber = content.substring(0, match.index).split('\n').length;
        findings.push({
          id: 'SOL171',
          title: 'Position Without Size Limit',
          severity: 'high',
          description: 'Position creation without maximum size limit. Single position could dominate protocol.',
          location: { file: fileName, line: lineNumber },
          recommendation: 'Implement maximum position size relative to total pool/market size.',
        });
      }

      // Check for margin requirements
      if (functionContext.includes('leverage') && !functionContext.includes('margin') &&
          !functionContext.includes('collateral')) {
        const lineNumber = content.substring(0, match.index).split('\n').length;
        findings.push({
          id: 'SOL171',
          title: 'Leveraged Position Without Margin Check',
          severity: 'critical',
          description: 'Leveraged position without margin verification. Undercollateralized positions possible.',
          location: { file: fileName, line: lineNumber },
          recommendation: 'Verify margin/collateral meets minimum requirements for leverage level.',
        });
      }
    }
  }

  // Check for position liquidation
  if (content.includes('position') && (content.includes('close') || content.includes('liquidate'))) {
    const liquidationPatterns = [
      /fn\s+liquidate/gi,
      /fn\s+force_close/gi,
      /margin_call/gi,
    ];

    let hasLiquidation = false;
    for (const pattern of liquidationPatterns) {
      if (pattern.test(content)) {
        hasLiquidation = true;
        
        const matches = [...content.matchAll(pattern)];
        for (const match of matches) {
          const contextEnd = Math.min(content.length, match.index! + 1500);
          const functionContext = content.substring(match.index!, contextEnd);
          
          // Check for partial liquidation
          if (!functionContext.includes('partial') && !functionContext.includes('portion') &&
              !functionContext.includes('amount')) {
            const lineNumber = content.substring(0, match.index).split('\n').length;
            findings.push({
              id: 'SOL171',
              title: 'Full Liquidation Only',
              severity: 'medium',
              description: 'Liquidation appears to be all-or-nothing. Partial liquidation is more user-friendly.',
              location: { file: fileName, line: lineNumber },
              recommendation: 'Implement partial liquidation to only close enough to restore health.',
            });
          }

          // Check for liquidation incentive
          if (!functionContext.includes('bonus') && !functionContext.includes('discount') &&
              !functionContext.includes('penalty') && !functionContext.includes('incentive')) {
            const lineNumber = content.substring(0, match.index).split('\n').length;
            findings.push({
              id: 'SOL171',
              title: 'Liquidation Without Incentive',
              severity: 'high',
              description: 'Liquidation without liquidator incentive. May not be profitable to liquidate.',
              location: { file: fileName, line: lineNumber },
              recommendation: 'Provide liquidation bonus/discount to incentivize keepers.',
            });
          }
        }
      }
    }

    if (!hasLiquidation && content.includes('leverage')) {
      findings.push({
        id: 'SOL171',
        title: 'Leveraged Positions Without Liquidation',
        severity: 'critical',
        description: 'Leveraged positions exist but no liquidation mechanism found. Bad debt can accumulate.',
        location: { file: fileName, line: 1 },
        recommendation: 'Implement liquidation mechanism for undercollateralized positions.',
      });
    }
  }

  // Check for position PnL calculation
  const pnlPatterns = [
    /fn\s+(?:calculate_)?pnl/gi,
    /profit_loss/gi,
    /unrealized_pnl/gi,
  ];

  for (const pattern of pnlPatterns) {
    const matches = [...content.matchAll(pattern)];
    for (const match of matches) {
      const contextEnd = Math.min(content.length, match.index! + 1000);
      const functionContext = content.substring(match.index!, contextEnd);
      
      // Check for funding rate inclusion
      if (functionContext.includes('perp') && !functionContext.includes('funding')) {
        const lineNumber = content.substring(0, match.index).split('\n').length;
        findings.push({
          id: 'SOL171',
          title: 'Perpetual PnL Without Funding',
          severity: 'high',
          description: 'Perpetual position PnL calculation without funding rate. Inaccurate PnL.',
          location: { file: fileName, line: lineNumber },
          recommendation: 'Include accrued funding payments in position PnL calculation.',
        });
      }

      // Check for price impact
      if (!functionContext.includes('impact') && !functionContext.includes('slippage') &&
          functionContext.includes('close')) {
        const lineNumber = content.substring(0, match.index).split('\n').length;
        findings.push({
          id: 'SOL171',
          title: 'Position Close Without Price Impact',
          severity: 'medium',
          description: 'Position close may not account for price impact of the trade.',
          location: { file: fileName, line: lineNumber },
          recommendation: 'Consider price impact when calculating position close values.',
        });
      }
    }
  }

  // Check for position tracking
  if (content.includes('position')) {
    const hasTracker = content.includes('PositionTracker') || content.includes('position_count') ||
                       content.includes('open_interest') || content.includes('total_positions');
    
    if (!hasTracker) {
      findings.push({
        id: 'SOL171',
        title: 'No Global Position Tracking',
        severity: 'medium',
        description: 'No apparent global position/open interest tracking. Hard to assess protocol risk.',
        location: { file: fileName, line: 1 },
        recommendation: 'Track total open interest and position counts for risk management.',
      });
    }
  }

  return findings;
}
