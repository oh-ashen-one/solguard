import type { Finding } from '../commands/audit.js';
import type { PatternInput } from './index.js';

export function checkNftRoyalty(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  const content = input.rust?.content || '';
  const fileName = input.rust?.filePath || 'unknown';

  // Check for royalty bypass in NFT sales
  const salePatterns = [
    /fn\s+(?:sell|buy|purchase|transfer)_nft/gi,
    /fn\s+execute_sale/gi,
    /fn\s+list/gi,
    /fn\s+accept_offer/gi,
  ];

  for (const pattern of salePatterns) {
    const matches = [...content.matchAll(pattern)];
    for (const match of matches) {
      const contextEnd = Math.min(content.length, match.index! + 2000);
      const functionContext = content.substring(match.index!, contextEnd);
      
      // Check for royalty enforcement
      const hasRoyalty = functionContext.includes('royalty') || 
                         functionContext.includes('creator_fee') ||
                         functionContext.includes('seller_fee_basis_points');
      
      if (!hasRoyalty) {
        const lineNumber = content.substring(0, match.index).split('\n').length;
        findings.push({
          id: 'SOL159',
          title: 'NFT Sale Without Royalty Enforcement',
          severity: 'high',
          description: 'NFT sale function without royalty payment enforcement. Creator royalties may be bypassed.',
          location: { file: fileName, line: lineNumber },
          recommendation: 'Implement mandatory royalty payment based on metadata seller_fee_basis_points. Consider using Metaplex royalty enforcement.',
        });
      }

      // Check for royalty recipient validation
      if (hasRoyalty && !functionContext.includes('creators') && !functionContext.includes('verified')) {
        const lineNumber = content.substring(0, match.index).split('\n').length;
        findings.push({
          id: 'SOL159',
          title: 'Royalty Without Creator Verification',
          severity: 'medium',
          description: 'Royalty payment without verifying creator addresses from metadata. Royalties may go to wrong recipients.',
          location: { file: fileName, line: lineNumber },
          recommendation: 'Verify royalty recipients match creators array from NFT metadata with verified = true.',
        });
      }
    }
  }

  // Check for collection verification
  if (content.includes('collection') || content.includes('Collection')) {
    const collectionPatterns = [
      /collection_mint/gi,
      /collection_key/gi,
      /verify_collection/gi,
    ];

    let hasCollectionCheck = false;
    for (const pattern of collectionPatterns) {
      if (pattern.test(content)) {
        hasCollectionCheck = true;
        break;
      }
    }

    if (!hasCollectionCheck && content.includes('nft') && content.includes('metadata')) {
      findings.push({
        id: 'SOL159',
        title: 'Missing Collection Verification',
        severity: 'high',
        description: 'NFT operations without collection verification. Fake NFTs from unrelated collections can be processed.',
        location: { file: fileName, line: 1 },
        recommendation: 'Verify NFT belongs to expected collection: check metadata.collection and collection.verified = true.',
      });
    }
  }

  // Check for creator verification
  if (content.includes('creator') && content.includes('nft')) {
    if (!content.includes('verified') && !content.includes('is_verified')) {
      findings.push({
        id: 'SOL159',
        title: 'Missing Creator Verification',
        severity: 'high',
        description: 'Creator check without verification flag. Unverified creators can claim NFT ownership.',
        location: { file: fileName, line: 1 },
        recommendation: 'Check creator.verified == true before trusting creator data.',
      });
    }
  }

  // Check for metadata manipulation protection
  const metadataPatterns = [
    /update_metadata/gi,
    /UpdateMetadata/gi,
    /set_metadata/gi,
  ];

  for (const pattern of metadataPatterns) {
    const matches = [...content.matchAll(pattern)];
    for (const match of matches) {
      const contextEnd = Math.min(content.length, match.index! + 1000);
      const functionContext = content.substring(match.index!, contextEnd);
      
      if (!functionContext.includes('update_authority') && !functionContext.includes('is_mutable')) {
        const lineNumber = content.substring(0, match.index).split('\n').length;
        findings.push({
          id: 'SOL159',
          title: 'Metadata Update Without Authority Check',
          severity: 'critical',
          description: 'Metadata update without verifying update authority. Unauthorized users may modify NFT metadata.',
          location: { file: fileName, line: lineNumber },
          recommendation: 'Verify signer matches metadata.update_authority before allowing updates.',
        });
      }
    }
  }

  // Check for edition/supply manipulation
  if (content.includes('edition') || content.includes('Edition') || content.includes('print')) {
    const editionPatterns = [
      /max_supply/gi,
      /edition_number/gi,
      /print_edition/gi,
    ];

    const hasEditionCheck = editionPatterns.some(p => p.test(content));
    if (!hasEditionCheck) {
      findings.push({
        id: 'SOL159',
        title: 'Missing Edition Supply Check',
        severity: 'high',
        description: 'Edition/print operations without supply validation. May allow unlimited minting.',
        location: { file: fileName, line: 1 },
        recommendation: 'Verify edition number against max_supply before allowing new prints.',
      });
    }
  }

  // Check for auction/bid safety
  const auctionPatterns = [
    /fn\s+place_bid/gi,
    /fn\s+create_auction/gi,
    /fn\s+end_auction/gi,
  ];

  for (const pattern of auctionPatterns) {
    const matches = [...content.matchAll(pattern)];
    for (const match of matches) {
      const contextEnd = Math.min(content.length, match.index! + 1500);
      const functionContext = content.substring(match.index!, contextEnd);
      
      if (functionContext.includes('bid') && !functionContext.includes('escrow') && 
          !functionContext.includes('vault')) {
        const lineNumber = content.substring(0, match.index).split('\n').length;
        findings.push({
          id: 'SOL159',
          title: 'Auction Bid Without Escrow',
          severity: 'high',
          description: 'Auction bid without apparent escrow mechanism. Bids may not be backed by actual funds.',
          location: { file: fileName, line: lineNumber },
          recommendation: 'Require bid funds to be escrowed in program-controlled vault.',
        });
      }
    }
  }

  return findings;
}
