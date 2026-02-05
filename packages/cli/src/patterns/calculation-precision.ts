import type { Finding } from '../commands/audit.js';
import type { PatternInput } from './index.js';

export function checkCalculationPrecision(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  const content = input.rust?.content || '';
  const fileName = input.rust?.filePath || 'unknown';

  // Check for division before multiplication
  const divBeforeMulPattern = /\/\s*\w+\s*\*/g;
  const divMatches = [...content.matchAll(divBeforeMulPattern)];
  
  for (const match of divMatches) {
    const lineNumber = content.substring(0, match.index).split('\n').length;
    findings.push({
      id: 'SOL175',
      title: 'Division Before Multiplication',
      severity: 'high',
      description: 'Division performed before multiplication causes precision loss. Integer division truncates.',
      location: { file: fileName, line: lineNumber },
      recommendation: 'Restructure to multiply first: (a * c) / b instead of (a / b) * c',
    });
  }

  // Check for basis points handling
  const basisPointsPatterns = [
    /10000|10_000/g,
    /100_00/g,
    /BPS|bps|basis_points/gi,
  ];

  for (const pattern of basisPointsPatterns) {
    const matches = [...content.matchAll(pattern)];
    for (const match of matches) {
      const contextStart = Math.max(0, match.index! - 200);
      const contextEnd = Math.min(content.length, match.index! + 200);
      const context = content.substring(contextStart, contextEnd);
      
      // Check for proper scaling
      if (context.includes('/') && !context.includes('checked_div') && !context.includes('u128')) {
        const lineNumber = content.substring(0, match.index).split('\n').length;
        findings.push({
          id: 'SOL175',
          title: 'Basis Points Calculation Precision',
          severity: 'medium',
          description: 'Basis points calculation may lose precision with small amounts.',
          location: { file: fileName, line: lineNumber },
          recommendation: 'Use u128 for intermediate calculations: (amount as u128 * bps as u128) / 10000',
        });
      }
    }
  }

  // Check for percentage calculations
  const percentPattern = /\*\s*(?:100|1000)\s*\/|\*\s*\d+\s*%|percent|percentage/gi;
  const percentMatches = [...content.matchAll(percentPattern)];
  
  for (const match of percentMatches) {
    const contextEnd = Math.min(content.length, match.index! + 300);
    const context = content.substring(match.index!, contextEnd);
    
    if (!context.includes('u128') && !context.includes('checked_')) {
      const lineNumber = content.substring(0, match.index).split('\n').length;
      findings.push({
        id: 'SOL175',
        title: 'Percentage Calculation Without High Precision',
        severity: 'medium',
        description: 'Percentage calculation without using higher precision intermediate values.',
        location: { file: fileName, line: lineNumber },
        recommendation: 'Cast to u128 before percentage calculation to avoid overflow and precision loss.',
      });
    }
  }

  // Check for rounding direction
  const roundingPatterns = [
    { pattern: /\/\s*2\s*\)/g, context: 'half calculation', severity: 'medium' as const },
    { pattern: /floor|ceil|round/gi, context: 'explicit rounding', severity: 'low' as const },
  ];

  for (const { pattern, context, severity } of roundingPatterns) {
    const matches = [...content.matchAll(pattern)];
    for (const match of matches) {
      const contextStart = Math.max(0, match.index! - 300);
      const contextEnd = Math.min(content.length, match.index! + 300);
      const codeContext = content.substring(contextStart, contextEnd);
      
      // Check if rounding direction matters
      if (codeContext.includes('fee') || codeContext.includes('share') || 
          codeContext.includes('reward') || codeContext.includes('interest')) {
        const lineNumber = content.substring(0, match.index).split('\n').length;
        findings.push({
          id: 'SOL175',
          title: `Rounding Direction in ${context}`,
          severity,
          description: `Rounding in financial calculation (${context}). Verify rounding direction favors protocol (round fees up, round user amounts down).`,
          location: { file: fileName, line: lineNumber },
          recommendation: 'Use ceiling division for protocol fees: (amount + divisor - 1) / divisor',
        });
      }
    }
  }

  // Check for power/exponent calculations
  const powerPatterns = [
    /pow\s*\(/gi,
    /\*\*\s*\d+/g,
    /\.pow\s*\(/g,
  ];

  for (const pattern of powerPatterns) {
    const matches = [...content.matchAll(pattern)];
    for (const match of matches) {
      const contextEnd = Math.min(content.length, match.index! + 500);
      const context = content.substring(match.index!, contextEnd);
      
      if (!context.includes('checked_pow') && !context.includes('saturating_pow')) {
        const lineNumber = content.substring(0, match.index).split('\n').length;
        findings.push({
          id: 'SOL175',
          title: 'Unchecked Power Calculation',
          severity: 'high',
          description: 'Power/exponent calculation without overflow checking. Can easily overflow.',
          location: { file: fileName, line: lineNumber },
          recommendation: 'Use checked_pow or saturating_pow to handle overflow safely.',
        });
      }
    }
  }

  // Check for square root calculations
  if (content.includes('sqrt') || content.includes('Sqrt')) {
    const sqrtPattern = /sqrt|square_root/gi;
    const sqrtMatches = [...content.matchAll(sqrtPattern)];
    
    for (const match of sqrtMatches) {
      const contextEnd = Math.min(content.length, match.index! + 300);
      const context = content.substring(match.index!, contextEnd);
      
      // Check for Newton's method or proper implementation
      if (!context.includes('newton') && !context.includes('babylon') && 
          !context.includes('isqrt') && !context.includes('integer_sqrt')) {
        const lineNumber = content.substring(0, match.index).split('\n').length;
        findings.push({
          id: 'SOL175',
          title: 'Custom Square Root Implementation',
          severity: 'medium',
          description: 'Custom sqrt implementation. Verify precision and correctness.',
          location: { file: fileName, line: lineNumber },
          recommendation: 'Use well-tested integer sqrt implementation (e.g., Uniswap-style).',
        });
      }
    }
  }

  // Check for fee calculations
  const feePattern = /fee\s*[=*/]/gi;
  const feeMatches = [...content.matchAll(feePattern)];
  
  for (const match of feeMatches) {
    const contextStart = Math.max(0, match.index! - 100);
    const contextEnd = Math.min(content.length, match.index! + 200);
    const context = content.substring(contextStart, contextEnd);
    
    // Check for zero amount handling
    if (!context.includes('> 0') && !context.includes('>= 0') && 
        !context.includes('!= 0') && !context.includes('max(')) {
      const lineNumber = content.substring(0, match.index).split('\n').length;
      findings.push({
        id: 'SOL175',
        title: 'Fee Calculation Without Zero Check',
        severity: 'medium',
        description: 'Fee calculation without handling zero amounts. May result in zero fees for dust amounts.',
        location: { file: fileName, line: lineNumber },
        recommendation: 'Handle dust amounts - either enforce minimum fee or minimum transaction size.',
      });
    }
  }

  return findings;
}
