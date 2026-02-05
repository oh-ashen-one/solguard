import type { Finding } from '../commands/audit.js';
import type { PatternInput } from './index.js';

export function checkCollateralValidation(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  const content = input.rust?.content || '';
  const fileName = input.rust?.filePath || 'unknown';

  // Check for collateral verification patterns (Cashio-style vulnerability)
  const mintPatterns = [
    /fn\s+(?:mint|issue|create)_(?:token|asset)/gi,
    /fn\s+mint\s*\(/gi,
    /mint_to\s*\(/gi,
    /MintTo\s*\{/gi,
  ];

  for (const pattern of mintPatterns) {
    const matches = [...content.matchAll(pattern)];
    for (const match of matches) {
      const contextEnd = Math.min(content.length, match.index! + 2000);
      const functionContext = content.substring(match.index!, contextEnd);
      
      // Check for missing collateral validation
      const hasCollateralCheck = 
        functionContext.includes('collateral') ||
        functionContext.includes('backing') ||
        functionContext.includes('reserve') ||
        functionContext.includes('require!(') ||
        functionContext.includes('constraint =');

      if (!hasCollateralCheck) {
        const lineNumber = content.substring(0, match.index).split('\n').length;
        findings.push({
          id: 'SOL157',
          title: 'Token Minting Without Collateral Validation',
          severity: 'critical',
          description: 'Token minting function without apparent collateral/backing validation. The Cashio exploit ($52M) was caused by minting tokens with worthless fake collateral.',
          location: { file: fileName, line: lineNumber },
          recommendation: 'Validate collateral authenticity and value before minting. Verify collateral comes from trusted sources with proper ownership checks.',
        });
      }

      // Check for root of trust verification
      if (functionContext.includes('collateral') && !functionContext.includes('root') && 
          !functionContext.includes('trusted') && !functionContext.includes('whitelist')) {
        const lineNumber = content.substring(0, match.index).split('\n').length;
        findings.push({
          id: 'SOL157',
          title: 'Missing Root of Trust for Collateral',
          severity: 'critical',
          description: 'Collateral validation without establishing root of trust. Attackers can create fake collateral accounts that pass basic validation.',
          location: { file: fileName, line: lineNumber },
          recommendation: 'Establish a chain of trust: verify collateral account ownership traces back to a known, trusted root (e.g., verified token mint).',
        });
      }
    }
  }

  // Check for borrow functions with insufficient collateral checks
  const borrowPatterns = [
    /fn\s+borrow\s*\(/gi,
    /fn\s+take_loan\s*\(/gi,
    /fn\s+leverage\s*\(/gi,
  ];

  for (const pattern of borrowPatterns) {
    const matches = [...content.matchAll(pattern)];
    for (const match of matches) {
      const contextEnd = Math.min(content.length, match.index! + 2000);
      const functionContext = content.substring(match.index!, contextEnd);
      
      // Check for collateral ratio validation
      if (!functionContext.includes('ratio') && !functionContext.includes('ltv') && 
          !functionContext.includes('health_factor')) {
        const lineNumber = content.substring(0, match.index).split('\n').length;
        findings.push({
          id: 'SOL157',
          title: 'Borrow Without Collateral Ratio Check',
          severity: 'critical',
          description: 'Borrowing function without collateral ratio/LTV validation. Users can borrow more than their collateral supports.',
          location: { file: fileName, line: lineNumber },
          recommendation: 'Implement and enforce loan-to-value (LTV) ratio checks before allowing borrows.',
        });
      }

      // Check for oracle price usage
      if (!functionContext.includes('price') && !functionContext.includes('oracle') && 
          !functionContext.includes('value')) {
        const lineNumber = content.substring(0, match.index).split('\n').length;
        findings.push({
          id: 'SOL157',
          title: 'Borrow Without Price Oracle',
          severity: 'critical',
          description: 'Borrowing function without price oracle integration. Cannot properly value collateral for LTV calculations.',
          location: { file: fileName, line: lineNumber },
          recommendation: 'Integrate reliable price oracle (e.g., Pyth, Switchboard) to value collateral before allowing borrows.',
        });
      }
    }
  }

  // Check for LP token collateral validation
  if (content.includes('lp_token') || content.includes('LP') || content.includes('liquidity_token')) {
    if (content.includes('collateral') || content.includes('mint')) {
      const hasLpValidation = content.includes('pool_state') || content.includes('amm') || 
                              content.includes('reserve_a') || content.includes('reserve_b');
      if (!hasLpValidation) {
        findings.push({
          id: 'SOL157',
          title: 'LP Token Collateral Without Pool Validation',
          severity: 'high',
          description: 'LP tokens used as collateral without validating the underlying pool state. Attackers can manipulate LP token value through pool manipulation.',
          location: { file: fileName, line: 1 },
          recommendation: 'Verify LP token comes from expected pool and validate pool reserves match expected state.',
        });
      }
    }
  }

  // Check for wrapped token collateral
  if (content.includes('wrapped') || content.includes('wSOL') || content.includes('wBTC')) {
    if (!content.includes('unwrap') && !content.includes('underlying')) {
      findings.push({
        id: 'SOL157',
        title: 'Wrapped Token Collateral Validation',
        severity: 'medium',
        description: 'Wrapped tokens used without validation of underlying backing.',
        location: { file: fileName, line: 1 },
        recommendation: 'Verify wrapped token is properly backed and from trusted wrapper contract.',
      });
    }
  }

  return findings;
}
