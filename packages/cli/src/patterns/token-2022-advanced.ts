import type { Finding } from '../commands/audit.js';
import type { ParsedIdl } from '../parsers/idl.js';
import type { ParsedRust } from '../parsers/rust.js';

/**
 * SOL401-SOL410: Advanced Token-2022 Extension Security
 * 
 * Token-2022 introduces powerful extensions that require careful handling:
 * transfer hooks, confidential transfers, permanent delegate, etc.
 */
export function checkToken2022Advanced(input: { idl?: ParsedIdl; rust?: ParsedRust }): Finding[] {
  const findings: Finding[] = [];
  
  if (input.rust?.sourceCode) {
    const code = input.rust.sourceCode;
    
    // SOL401: Transfer hook reentrancy
    if (/transfer_hook|TransferHook/i.test(code) && 
        !/reentrancy_guard|lock|mutex/.test(code)) {
      findings.push({
        id: 'SOL401',
        severity: 'critical',
        title: 'Transfer Hook Reentrancy Risk',
        description: 'Transfer hooks can be called recursively, enabling reentrancy attacks.',
        location: 'Transfer hook implementation',
        recommendation: 'Implement reentrancy guards in transfer hook logic.',
      });
    }
    
    // SOL402: Confidential transfer balance validation
    if (/confidential_transfer|ConfidentialTransfer/i.test(code) && 
        !/verify_ciphertext|decrypt_balance/.test(code)) {
      findings.push({
        id: 'SOL402',
        severity: 'high',
        title: 'Missing Confidential Balance Validation',
        description: 'Confidential transfers require proper ciphertext validation.',
        location: 'Confidential transfer handling',
        recommendation: 'Verify ciphertext validity before processing confidential transfers.',
      });
    }
    
    // SOL403: Permanent delegate abuse
    if (/permanent_delegate|PermanentDelegate/i.test(code) && 
        !/owner_check|authority_check/.test(code)) {
      findings.push({
        id: 'SOL403',
        severity: 'critical',
        title: 'Permanent Delegate Can Drain Tokens',
        description: 'Permanent delegate extension allows unlimited transfers without owner consent.',
        location: 'Token account handling',
        recommendation: 'Verify permanent delegate status before accepting tokens.',
      });
    }
    
    // SOL404: Non-transferable token bypass
    if (/non_transferable|NonTransferable/i.test(code) && 
        /transfer|send/i.test(code) &&
        !/check_extension|is_non_transferable/.test(code)) {
      findings.push({
        id: 'SOL404',
        severity: 'high',
        title: 'Non-Transferable Token Check Missing',
        description: 'Code attempts transfer without checking non-transferable extension.',
        location: 'Token transfer logic',
        recommendation: 'Check for non-transferable extension before transfer attempts.',
      });
    }
    
    // SOL405: Interest-bearing token accounting
    if (/interest_bearing|InterestBearing/i.test(code) && 
        !/calculate_interest|accrued_interest/.test(code)) {
      findings.push({
        id: 'SOL405',
        severity: 'high',
        title: 'Interest-Bearing Token Accounting Error',
        description: 'Interest-bearing tokens require proper interest calculation.',
        location: 'Token balance handling',
        recommendation: 'Calculate accrued interest when reading interest-bearing token balances.',
      });
    }
    
    // SOL406: Transfer fee extension handling
    if (/transfer_fee|TransferFee/i.test(code) && 
        !/get_fee|calculate_fee|withheld_amount/.test(code)) {
      findings.push({
        id: 'SOL406',
        severity: 'high',
        title: 'Transfer Fee Not Accounted',
        description: 'Token-2022 transfer fees must be calculated in amount handling.',
        location: 'Token transfer logic',
        recommendation: 'Account for transfer fees when calculating received amounts.',
      });
    }
    
    // SOL407: CPI guard bypass
    if (/cpi_guard|CpiGuard/i.test(code) && 
        /invoke|cpi/i.test(code) &&
        !/check_cpi_guard|is_cpi_guard_enabled/.test(code)) {
      findings.push({
        id: 'SOL407',
        severity: 'medium',
        title: 'CPI Guard Extension Not Checked',
        description: 'CPI guard prevents certain operations via CPI, must be checked.',
        location: 'CPI logic',
        recommendation: 'Check CPI guard status before performing CPI operations on token accounts.',
      });
    }
    
    // SOL408: Metadata pointer validation
    if (/metadata_pointer|MetadataPointer/i.test(code) && 
        !/validate_metadata|verify_pointer/.test(code)) {
      findings.push({
        id: 'SOL408',
        severity: 'medium',
        title: 'Metadata Pointer Not Validated',
        description: 'Metadata pointer can point to arbitrary accounts.',
        location: 'Metadata handling',
        recommendation: 'Validate metadata pointer destination before trusting metadata.',
      });
    }
    
    // SOL409: Group pointer security
    if (/group_pointer|GroupPointer|group_member_pointer/i.test(code) && 
        !/verify_group|validate_member/.test(code)) {
      findings.push({
        id: 'SOL409',
        severity: 'medium',
        title: 'Token Group Membership Not Verified',
        description: 'Token group extensions require membership verification.',
        location: 'Token group handling',
        recommendation: 'Verify group membership when processing grouped tokens.',
      });
    }
    
    // SOL410: Default account state issues
    if (/default_account_state|DefaultAccountState/i.test(code) && 
        /frozen/i.test(code) &&
        !/thaw|unfreeze/.test(code)) {
      findings.push({
        id: 'SOL410',
        severity: 'medium',
        title: 'Default Frozen Account State Issue',
        description: 'Tokens with default frozen state require explicit thawing.',
        location: 'Token account creation',
        recommendation: 'Handle default account state extension properly in account setup.',
      });
    }
  }
  
  return findings;
}
