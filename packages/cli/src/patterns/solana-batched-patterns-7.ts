import type { Finding } from '../commands/audit.js';
import type { PatternInput } from './index.js';

/** SOL286: Token Account State Check */
export function checkTokenAccountState(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  const { rust, path } = input;
  if (!rust) return findings;
  if (rust.content.includes('TokenAccount') && !rust.content.includes('state ==') && !rust.content.includes('is_frozen')) {
    findings.push({ id: 'SOL286', severity: 'medium', title: 'Missing Token State Check', description: 'Token account without frozen state check.', location: { file: path, line: 1 }, recommendation: 'Check token account state before operations.' });
  }
  return findings;
}

/** SOL287: Missing Associated Token Check */
export function checkMissingAssociatedTokenCheck(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  const { rust, path } = input;
  if (!rust) return findings;
  if (rust.content.includes('get_associated_token_address') && !rust.content.includes('key() ==')) {
    findings.push({ id: 'SOL287', severity: 'high', title: 'Unvalidated ATA', description: 'ATA derivation without validation.', location: { file: path, line: 1 }, recommendation: 'Verify ATA matches expected address.' });
  }
  return findings;
}

/** SOL288: Missing Metadata Validation */
export function checkMissingMetadataValidation(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  const { rust, path } = input;
  if (!rust) return findings;
  if (rust.content.includes('Metadata') && !rust.content.includes('verify') && !rust.content.includes('collection')) {
    findings.push({ id: 'SOL288', severity: 'medium', title: 'NFT Metadata Unverified', description: 'Metadata used without verification.', location: { file: path, line: 1 }, recommendation: 'Verify NFT collection and creator.' });
  }
  return findings;
}

/** SOL289: Missing Edition Check */
export function checkMissingEditionCheck(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  const { rust, path } = input;
  if (!rust) return findings;
  if (rust.content.includes('Edition') && !rust.content.includes('max_supply') && !rust.content.includes('edition_number')) {
    findings.push({ id: 'SOL289', severity: 'medium', title: 'Edition Not Validated', description: 'NFT edition without proper check.', location: { file: path, line: 1 }, recommendation: 'Validate edition supply and number.' });
  }
  return findings;
}

/** SOL290: Missing Master Edition */
export function checkMissingMasterEdition(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  const { rust, path } = input;
  if (!rust) return findings;
  if (rust.content.includes('print_edition') && !rust.content.includes('master_edition')) {
    findings.push({ id: 'SOL290', severity: 'high', title: 'Missing Master Edition', description: 'Print edition without master check.', location: { file: path, line: 1 }, recommendation: 'Validate against master edition.' });
  }
  return findings;
}

/** SOL291: Missing Token Record */
export function checkMissingTokenRecord(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  const { rust, path } = input;
  if (!rust) return findings;
  if (rust.content.includes('pnft') || rust.content.includes('programmable')) {
    if (!rust.content.includes('token_record')) {
      findings.push({ id: 'SOL291', severity: 'high', title: 'Missing Token Record', description: 'pNFT without token record.', location: { file: path, line: 1 }, recommendation: 'Include token record for pNFTs.' });
    }
  }
  return findings;
}

/** SOL292: Unsafe Compression */
export function checkUnsafeCompression(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  const { rust, path } = input;
  if (!rust) return findings;
  if (rust.content.includes('compress') || rust.content.includes('merkle')) {
    if (!rust.content.includes('verify_leaf') && !rust.content.includes('proof')) {
      findings.push({ id: 'SOL292', severity: 'critical', title: 'Unverified Compression', description: 'Compressed data without proof.', location: { file: path, line: 1 }, recommendation: 'Always verify Merkle proofs.' });
    }
  }
  return findings;
}

/** SOL293: Missing Creator Verification */
export function checkMissingCreatorVerification(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  const { rust, path } = input;
  if (!rust) return findings;
  if (rust.content.includes('creator') && !rust.content.includes('verified')) {
    findings.push({ id: 'SOL293', severity: 'high', title: 'Unverified Creator', description: 'Creator used without verification.', location: { file: path, line: 1 }, recommendation: 'Check creator verified flag.' });
  }
  return findings;
}

/** SOL294: Missing Royalty Check */
export function checkMissingRoyaltyCheck(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  const { rust, path } = input;
  if (!rust) return findings;
  if (rust.content.includes('seller_fee') && !rust.content.includes('royalt')) {
    findings.push({ id: 'SOL294', severity: 'medium', title: 'Missing Royalty Handling', description: 'Seller fee without royalty logic.', location: { file: path, line: 1 }, recommendation: 'Implement royalty distribution.' });
  }
  return findings;
}

/** SOL295: Unsafe Collection Update */
export function checkUnsafeCollectionUpdate(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  const { rust, path } = input;
  if (!rust) return findings;
  if (rust.content.includes('update_collection') || rust.content.includes('set_collection')) {
    findings.push({ id: 'SOL295', severity: 'high', title: 'Collection Update', description: 'Collection modification requires care.', location: { file: path, line: 1 }, recommendation: 'Verify collection authority.' });
  }
  return findings;
}

/** SOL296: Missing Delegate Authority */
export function checkMissingDelegateAuthority(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  const { rust, path } = input;
  if (!rust) return findings;
  if (rust.content.includes('delegate') && rust.content.includes('transfer') && !rust.content.includes('authority')) {
    findings.push({ id: 'SOL296', severity: 'high', title: 'Delegate Without Authority', description: 'Delegate operation without authority.', location: { file: path, line: 1 }, recommendation: 'Validate delegate authority.' });
  }
  return findings;
}

/** SOL297: Missing Lock Check */
export function checkMissingLockCheck(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  const { rust, path } = input;
  if (!rust) return findings;
  if (rust.content.includes('lock') && !rust.content.includes('is_locked') && !rust.content.includes('locked ==')) {
    findings.push({ id: 'SOL297', severity: 'high', title: 'Missing Lock Validation', description: 'Lock operation without state check.', location: { file: path, line: 1 }, recommendation: 'Verify lock state before operations.' });
  }
  return findings;
}

/** SOL298: Missing Use Authority */
export function checkMissingUseAuthority(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  const { rust, path } = input;
  if (!rust) return findings;
  if (rust.content.includes('use_record') && !rust.content.includes('use_authority')) {
    findings.push({ id: 'SOL298', severity: 'high', title: 'Missing Use Authority', description: 'Use record without authority check.', location: { file: path, line: 1 }, recommendation: 'Validate use authority.' });
  }
  return findings;
}

/** SOL299: Excessive Account Rent */
export function checkExcessiveAccountRent(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  const { rust, path } = input;
  if (!rust) return findings;
  const lines = rust.content.split('\n');
  for (let i = 0; i < lines.length; i++) {
    if (/space\s*=\s*\d{5,}/.test(lines[i])) {
      findings.push({ id: 'SOL299', severity: 'medium', title: 'Large Account Space', description: 'Account requires significant rent.', location: { file: path, line: i + 1 }, recommendation: 'Optimize account size.' });
    }
  }
  return findings;
}

/** SOL300: Missing Realloc Check */
export function checkMissingReallocCheck(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  const { rust, path } = input;
  if (!rust) return findings;
  if (rust.content.includes('realloc') && !rust.content.includes('MAX_SIZE') && !rust.content.includes('max_size')) {
    findings.push({ id: 'SOL300', severity: 'high', title: 'Unbounded Realloc', description: 'Account realloc without size limit.', location: { file: path, line: 1 }, recommendation: 'Set maximum account size.' });
  }
  return findings;
}
