import type { Finding } from '../commands/audit.js';
import type { ParsedIdl } from '../parsers/idl.js';
import type { ParsedRust } from '../parsers/rust.js';

/**
 * SOL421-SOL430: NFT Lending Protocol Security
 * 
 * NFT lending protocols (Sharky, Citrus, etc.) have unique risks:
 * collateral valuation, liquidation timing, royalty bypasses.
 */
export function checkNftLending(input: { idl?: ParsedIdl; rust?: ParsedRust }): Finding[] {
  const findings: Finding[] = [];
  
  if (input.rust?.sourceCode) {
    const code = input.rust.sourceCode;
    
    // SOL421: NFT valuation manipulation
    if (/nft.*collateral|collateral.*nft/i.test(code) && 
        !/floor_price|oracle_price|time_weighted/.test(code)) {
      findings.push({
        id: 'SOL421',
        severity: 'critical',
        title: 'NFT Collateral Valuation Vulnerable',
        description: 'NFT collateral value can be manipulated without proper price feeds.',
        location: 'Collateral valuation',
        recommendation: 'Use time-weighted floor prices or multiple oracle sources.',
      });
    }
    
    // SOL422: Instant liquidation exploit
    if (/liquidat|foreclose/i.test(code) && 
        /nft/i.test(code) &&
        !/grace_period|delay|buffer/.test(code)) {
      findings.push({
        id: 'SOL422',
        severity: 'high',
        title: 'No Liquidation Grace Period',
        description: 'Instant liquidation can enable oracle manipulation attacks.',
        location: 'Liquidation logic',
        recommendation: 'Add grace period before NFT collateral liquidation.',
      });
    }
    
    // SOL423: NFT ownership during loan
    if (/escrow|custody/i.test(code) && 
        /nft/i.test(code) &&
        !/freeze|lock|transfer_guard/.test(code)) {
      findings.push({
        id: 'SOL423',
        severity: 'high',
        title: 'NFT Can Be Transferred During Loan',
        description: 'Collateral NFT must be locked or frozen during loan period.',
        location: 'NFT custody',
        recommendation: 'Use escrow or freeze authority to prevent collateral transfer.',
      });
    }
    
    // SOL424: Collection verification missing
    if (/nft|collection/i.test(code) && 
        /lending|loan|borrow/i.test(code) &&
        !/verify_collection|certified_collection/.test(code)) {
      findings.push({
        id: 'SOL424',
        severity: 'high',
        title: 'NFT Collection Not Verified',
        description: 'Fake collection NFTs can be used as fraudulent collateral.',
        location: 'NFT validation',
        recommendation: 'Verify NFT collection certification using Metaplex standards.',
      });
    }
    
    // SOL425: Royalty bypass on liquidation
    if (/liquidat|sell|transfer/i.test(code) && 
        /nft/i.test(code) &&
        !/creator_fee|royalt|seller_fee/.test(code)) {
      findings.push({
        id: 'SOL425',
        severity: 'medium',
        title: 'Liquidation May Bypass Royalties',
        description: 'NFT liquidation sales should respect creator royalties.',
        location: 'Liquidation sale',
        recommendation: 'Include royalty payments in liquidation sale logic.',
      });
    }
    
    // SOL426: Interest rate manipulation
    if (/interest_rate|apr|apy/i.test(code) && 
        /nft.*lend|lend.*nft/i.test(code) &&
        !/max_rate|rate_cap|rate_limit/.test(code)) {
      findings.push({
        id: 'SOL426',
        severity: 'high',
        title: 'Unbounded Interest Rate',
        description: 'Interest rates should have reasonable caps to prevent abuse.',
        location: 'Interest calculation',
        recommendation: 'Cap interest rates and validate rate parameters.',
      });
    }
    
    // SOL427: Loan extension abuse
    if (/extend|rollover|refinance/i.test(code) && 
        /loan|borrow/i.test(code) &&
        !/extension_limit|max_extend/.test(code)) {
      findings.push({
        id: 'SOL427',
        severity: 'medium',
        title: 'Unlimited Loan Extensions',
        description: 'Unlimited extensions can cause perpetual undercollateralization.',
        location: 'Loan management',
        recommendation: 'Limit number of extensions and revalidate collateral value.',
      });
    }
    
    // SOL428: Compressed NFT handling
    if (/compressed|cnft|merkle_tree/i.test(code) && 
        /collateral|lending/i.test(code) &&
        !/verify_leaf|proof/.test(code)) {
      findings.push({
        id: 'SOL428',
        severity: 'high',
        title: 'Compressed NFT Proof Not Verified',
        description: 'cNFT collateral requires merkle proof verification.',
        location: 'cNFT handling',
        recommendation: 'Verify merkle proof when accepting cNFT as collateral.',
      });
    }
    
    // SOL429: Multiple loan on same NFT
    if (/nft.*collateral/i.test(code) && 
        !/unique_collateral|collateral_check|already_used/.test(code)) {
      findings.push({
        id: 'SOL429',
        severity: 'critical',
        title: 'Double-Collateralization Possible',
        description: 'Same NFT can potentially be used as collateral for multiple loans.',
        location: 'Loan creation',
        recommendation: 'Track and prevent duplicate use of NFT collateral.',
      });
    }
    
    // SOL430: Auction manipulation
    if (/auction|bid/i.test(code) && 
        /nft.*liquidat|liquidat.*nft/i.test(code) &&
        !/min_bid|reserve_price|anti_snipe/.test(code)) {
      findings.push({
        id: 'SOL430',
        severity: 'high',
        title: 'Liquidation Auction Vulnerable',
        description: 'Liquidation auctions need protections against manipulation.',
        location: 'Auction logic',
        recommendation: 'Add minimum bids, anti-sniping, and reserve prices.',
      });
    }
  }
  
  return findings;
}
