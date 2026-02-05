import type { Finding } from '../commands/audit.js';
import type { PatternInput } from './index.js';

export function checkTokenStandard(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  const content = input.rust?.content || '';
  const fileName = input.rust?.filePath || 'unknown';

  // Check for Token-2022 extension handling
  if (content.includes('token_2022') || content.includes('Token2022') || content.includes('spl_token_2022')) {
    // Check for transfer fee handling
    if (content.includes('transfer') && !content.includes('transfer_fee') &&
        !content.includes('get_transfer_fee')) {
      findings.push({
        id: 'SOL172',
        title: 'Token-2022 Without Transfer Fee Handling',
        severity: 'high',
        description: 'Token-2022 integration without handling transfer fee extension. Actual received amount may differ.',
        location: { file: fileName, line: 1 },
        recommendation: 'Check if token has transfer fee extension and calculate actual amounts accordingly.',
      });
    }

    // Check for interest bearing tokens
    if (!content.includes('interest_bearing') && !content.includes('InterestBearing')) {
      findings.push({
        id: 'SOL172',
        title: 'No Interest-Bearing Token Handling',
        severity: 'medium',
        description: 'Token-2022 used without interest-bearing extension consideration. Token values may change over time.',
        location: { file: fileName, line: 1 },
        recommendation: 'Consider interest-bearing tokens when calculating values and balances.',
      });
    }

    // Check for confidential transfers
    if (content.includes('confidential') || content.includes('ConfidentialTransfer')) {
      if (!content.includes('decrypt') && !content.includes('ElGamal')) {
        findings.push({
          id: 'SOL172',
          title: 'Confidential Transfer Missing Decryption',
          severity: 'high',
          description: 'Confidential transfer extension used but decryption not handled.',
          location: { file: fileName, line: 1 },
          recommendation: 'Properly handle confidential transfer decryption for balance tracking.',
        });
      }
    }

    // Check for permanent delegate
    if (content.includes('permanent_delegate') || content.includes('PermanentDelegate')) {
      if (!content.includes('delegate_authority') && !content.includes('has_permanent_delegate')) {
        findings.push({
          id: 'SOL172',
          title: 'Permanent Delegate Not Validated',
          severity: 'high',
          description: 'Permanent delegate tokens can be transferred by delegate at any time.',
          location: { file: fileName, line: 1 },
          recommendation: 'Check for permanent delegate extension and validate authority.',
        });
      }
    }
  }

  // Check for standard SPL token safety
  const tokenPatterns = [
    /spl_token/gi,
    /TokenAccount/gi,
    /token::instruction/gi,
  ];

  for (const pattern of tokenPatterns) {
    const matches = [...content.matchAll(pattern)];
    for (const match of matches) {
      const contextEnd = Math.min(content.length, match.index! + 1500);
      const functionContext = content.substring(match.index!, contextEnd);
      
      // Check for mint/freeze authority awareness
      if (functionContext.includes('mint') || functionContext.includes('Mint')) {
        if (!functionContext.includes('mint_authority') && !functionContext.includes('freeze_authority')) {
          const lineNumber = content.substring(0, match.index).split('\n').length;
          findings.push({
            id: 'SOL172',
            title: 'Mint Without Authority Awareness',
            severity: 'medium',
            description: 'Mint operations without checking mint/freeze authority. May interact with controllable tokens.',
            location: { file: fileName, line: lineNumber },
            recommendation: 'Verify mint authority is as expected (null for decentralized tokens).',
          });
        }
      }
    }
  }

  // Check for decimal handling
  if (content.includes('decimal') || content.includes('Decimal')) {
    const decimalPatterns = [
      /decimals/gi,
      /\.decimals\(\)/g,
      /get_decimals/gi,
    ];

    let hasDecimalHandling = false;
    for (const pattern of decimalPatterns) {
      if (pattern.test(content)) {
        hasDecimalHandling = true;
        break;
      }
    }

    if (!hasDecimalHandling && (content.includes('amount') || content.includes('price'))) {
      findings.push({
        id: 'SOL172',
        title: 'Missing Decimal Normalization',
        severity: 'high',
        description: 'Token amounts used without decimal normalization. Different decimal tokens will be mispriced.',
        location: { file: fileName, line: 1 },
        recommendation: 'Normalize all token amounts to common decimal precision for calculations.',
      });
    }
  }

  // Check for token program verification
  if (content.includes('token_program') || content.includes('TokenProgram')) {
    const programCheckPattern = /token_program.*==|TokenProgram.*==|TOKEN_PROGRAM_ID/gi;
    if (!programCheckPattern.test(content)) {
      findings.push({
        id: 'SOL172',
        title: 'Token Program Not Verified',
        severity: 'high',
        description: 'Token program account passed without verification. Could be malicious program.',
        location: { file: fileName, line: 1 },
        recommendation: 'Verify token_program matches spl_token::ID or spl_token_2022::ID.',
      });
    }
  }

  // Check for associated token account handling
  if (content.includes('associated_token') || content.includes('AssociatedToken')) {
    const ataPatterns = [
      /get_associated_token_address/gi,
      /create_associated_token_account/gi,
      /AssociatedToken/gi,
    ];

    for (const pattern of ataPatterns) {
      const matches = [...content.matchAll(pattern)];
      for (const match of matches) {
        const contextEnd = Math.min(content.length, match.index! + 800);
        const functionContext = content.substring(match.index!, contextEnd);
        
        // Check for init_if_needed pattern
        if (functionContext.includes('init_if_needed') && !functionContext.includes('payer')) {
          const lineNumber = content.substring(0, match.index).split('\n').length;
          findings.push({
            id: 'SOL172',
            title: 'ATA Init Without Payer Verification',
            severity: 'medium',
            description: 'ATA created with init_if_needed but payer not verified. Could charge wrong account.',
            location: { file: fileName, line: lineNumber },
            recommendation: 'Verify payer is authorized to pay for ATA creation.',
          });
        }
      }
    }
  }

  // Check for metadata handling
  if (content.includes('metaplex') || content.includes('Metadata')) {
    const metadataPatterns = [
      /Metadata::from_account_info/gi,
      /metadata_account/gi,
    ];

    for (const pattern of metadataPatterns) {
      const matches = [...content.matchAll(pattern)];
      for (const match of matches) {
        const contextEnd = Math.min(content.length, match.index! + 600);
        const functionContext = content.substring(match.index!, contextEnd);
        
        if (!functionContext.includes('key') && !functionContext.includes('verify')) {
          const lineNumber = content.substring(0, match.index).split('\n').length;
          findings.push({
            id: 'SOL172',
            title: 'Metadata Account Not Verified',
            severity: 'high',
            description: 'Metadata account used without verifying it matches expected mint.',
            location: { file: fileName, line: lineNumber },
            recommendation: 'Verify metadata PDA derives from expected mint.',
          });
        }
      }
    }
  }

  return findings;
}
