/**
 * Maps SolShield vulnerability patterns to official Solana documentation.
 * Uses Solana's LLM-ready docs format (.md URLs).
 * 
 * @see https://x.com/solana_devs/status/2019123339642695783
 */

export interface DocReference {
  title: string;
  url: string;
  mdUrl: string; // LLM-friendly markdown version
  section?: string;
}

// Solana core docs base
const DOCS_BASE = 'https://solana.com/docs';

// Map pattern IDs to relevant Solana documentation
export const patternDocs: Record<string, DocReference[]> = {
  // === CRITICAL: Account & Ownership ===
  'SOL001': [
    { 
      title: 'Accounts', 
      url: `${DOCS_BASE}/core/accounts`,
      mdUrl: `${DOCS_BASE}/core/accounts.md`,
      section: 'Account Ownership'
    },
    {
      title: 'Programs',
      url: `${DOCS_BASE}/core/programs`,
      mdUrl: `${DOCS_BASE}/core/programs.md`,
      section: 'Owner Validation'
    }
  ],
  
  // === CRITICAL: Signer Checks ===
  'SOL002': [
    {
      title: 'Transactions',
      url: `${DOCS_BASE}/core/transactions`,
      mdUrl: `${DOCS_BASE}/core/transactions.md`,
      section: 'Signatures'
    },
    {
      title: 'Accounts',
      url: `${DOCS_BASE}/core/accounts`,
      mdUrl: `${DOCS_BASE}/core/accounts.md`,
      section: 'Account Structure'
    }
  ],
  
  // === HIGH: Integer Overflow ===
  'SOL003': [
    {
      title: 'Developing Programs - Rust',
      url: `${DOCS_BASE}/programs/lang-rust`,
      mdUrl: `${DOCS_BASE}/programs/lang-rust.md`,
      section: 'Arithmetic Safety'
    }
  ],
  
  // === HIGH: PDA Validation ===
  'SOL004': [
    {
      title: 'Program Derived Addresses',
      url: `${DOCS_BASE}/core/pda`,
      mdUrl: `${DOCS_BASE}/core/pda.md`,
      section: 'Canonical Bumps'
    }
  ],
  
  // === CRITICAL: Authority Bypass ===
  'SOL005': [
    {
      title: 'Programs',
      url: `${DOCS_BASE}/core/programs`,
      mdUrl: `${DOCS_BASE}/core/programs.md`,
      section: 'Access Control'
    },
    {
      title: 'Accounts',
      url: `${DOCS_BASE}/core/accounts`,
      mdUrl: `${DOCS_BASE}/core/accounts.md`,
      section: 'Account Ownership'
    }
  ],
  
  // === CRITICAL: Initialization ===
  'SOL006': [
    {
      title: 'Accounts',
      url: `${DOCS_BASE}/core/accounts`,
      mdUrl: `${DOCS_BASE}/core/accounts.md`,
      section: 'Creating Accounts'
    }
  ],
  
  // === HIGH: CPI Vulnerabilities ===
  'SOL007': [
    {
      title: 'Cross Program Invocation',
      url: `${DOCS_BASE}/core/cpi`,
      mdUrl: `${DOCS_BASE}/core/cpi.md`,
      section: 'CPI Security'
    }
  ],
  
  // === MEDIUM: Rounding Errors ===
  'SOL008': [
    {
      title: 'Developing Programs - Rust',
      url: `${DOCS_BASE}/programs/lang-rust`,
      mdUrl: `${DOCS_BASE}/programs/lang-rust.md`,
      section: 'Numeric Precision'
    }
  ],
  
  // === HIGH: Account Confusion ===
  'SOL009': [
    {
      title: 'Accounts',
      url: `${DOCS_BASE}/core/accounts`,
      mdUrl: `${DOCS_BASE}/core/accounts.md`,
      section: 'Account Validation'
    }
  ],
  
  // === CRITICAL: Closing Accounts ===
  'SOL010': [
    {
      title: 'Accounts',
      url: `${DOCS_BASE}/core/accounts`,
      mdUrl: `${DOCS_BASE}/core/accounts.md`,
      section: 'Closing Accounts'
    },
    {
      title: 'Fees on Solana',
      url: `${DOCS_BASE}/core/fees`,
      mdUrl: `${DOCS_BASE}/core/fees.md`,
      section: 'Rent'
    }
  ],
  
  // === HIGH: Reentrancy ===
  'SOL011': [
    {
      title: 'Cross Program Invocation',
      url: `${DOCS_BASE}/core/cpi`,
      mdUrl: `${DOCS_BASE}/core/cpi.md`,
      section: 'CPI Depth'
    }
  ],
  
  // === CRITICAL: Arbitrary CPI ===
  'SOL012': [
    {
      title: 'Cross Program Invocation',
      url: `${DOCS_BASE}/core/cpi`,
      mdUrl: `${DOCS_BASE}/core/cpi.md`,
      section: 'Program ID Validation'
    }
  ],
  
  // === HIGH: Duplicate Mutable ===
  'SOL013': [
    {
      title: 'Transactions',
      url: `${DOCS_BASE}/core/transactions`,
      mdUrl: `${DOCS_BASE}/core/transactions.md`,
      section: 'Account Locking'
    }
  ],
  
  // === MEDIUM: Rent Exemption ===
  'SOL014': [
    {
      title: 'Fees on Solana',
      url: `${DOCS_BASE}/core/fees`,
      mdUrl: `${DOCS_BASE}/core/fees.md`,
      section: 'Rent'
    }
  ],
  
  // === CRITICAL: Type Cosplay ===
  'SOL015': [
    {
      title: 'Accounts',
      url: `${DOCS_BASE}/core/accounts`,
      mdUrl: `${DOCS_BASE}/core/accounts.md`,
      section: 'Account Discriminators'
    }
  ],
  
  // === HIGH: Bump Seeds ===
  'SOL016': [
    {
      title: 'Program Derived Addresses',
      url: `${DOCS_BASE}/core/pda`,
      mdUrl: `${DOCS_BASE}/core/pda.md`,
      section: 'Canonical Bumps'
    }
  ],
  
  // === MEDIUM: Freeze Authority ===
  'SOL017': [
    {
      title: 'Tokens on Solana',
      url: `${DOCS_BASE}/core/tokens`,
      mdUrl: `${DOCS_BASE}/core/tokens.md`,
      section: 'Token Authorities'
    }
  ],
  
  // === HIGH: Oracle Manipulation ===
  'SOL018': [
    {
      title: 'Programs',
      url: `${DOCS_BASE}/core/programs`,
      mdUrl: `${DOCS_BASE}/core/programs.md`,
      section: 'External Data'
    }
  ],
  
  // === CRITICAL: Flash Loans ===
  'SOL019': [
    {
      title: 'Transactions',
      url: `${DOCS_BASE}/core/transactions`,
      mdUrl: `${DOCS_BASE}/core/transactions.md`,
      section: 'Atomicity'
    }
  ],
  
  // === HIGH: Unsafe Math ===
  'SOL020': [
    {
      title: 'Developing Programs - Rust',
      url: `${DOCS_BASE}/programs/lang-rust`,
      mdUrl: `${DOCS_BASE}/programs/lang-rust.md`,
      section: 'Checked Arithmetic'
    }
  ],
  
  // === CRITICAL: Sysvar Manipulation ===
  'SOL021': [
    {
      title: 'Accounts',
      url: `${DOCS_BASE}/core/accounts`,
      mdUrl: `${DOCS_BASE}/core/accounts.md`,
      section: 'Sysvar Accounts'
    }
  ],
  
  // === MEDIUM: Upgrade Authority ===
  'SOL022': [
    {
      title: 'Programs',
      url: `${DOCS_BASE}/core/programs`,
      mdUrl: `${DOCS_BASE}/core/programs.md`,
      section: 'Program Deployment'
    }
  ],
  
  // === HIGH: Token Validation ===
  'SOL023': [
    {
      title: 'Tokens on Solana',
      url: `${DOCS_BASE}/core/tokens`,
      mdUrl: `${DOCS_BASE}/core/tokens.md`,
      section: 'Token Accounts'
    }
  ],
  
  // === HIGH: Cross-Program State ===
  'SOL024': [
    {
      title: 'Cross Program Invocation',
      url: `${DOCS_BASE}/core/cpi`,
      mdUrl: `${DOCS_BASE}/core/cpi.md`,
      section: 'State Dependencies'
    }
  ],
  
  // === HIGH: Lamport Balance ===
  'SOL025': [
    {
      title: 'Accounts',
      url: `${DOCS_BASE}/core/accounts`,
      mdUrl: `${DOCS_BASE}/core/accounts.md`,
      section: 'Lamports'
    },
    {
      title: 'Fees on Solana',
      url: `${DOCS_BASE}/core/fees`,
      mdUrl: `${DOCS_BASE}/core/fees.md`,
      section: 'Rent'
    }
  ],
  
  // PDA & Seeds
  'SOL026': [
    {
      title: 'Program Derived Addresses',
      url: `${DOCS_BASE}/core/pda`,
      mdUrl: `${DOCS_BASE}/core/pda.md`,
      section: 'Seeds'
    }
  ],
  
  // Error Handling
  'SOL027': [
    {
      title: 'Developing Programs - Rust',
      url: `${DOCS_BASE}/programs/lang-rust`,
      mdUrl: `${DOCS_BASE}/programs/lang-rust.md`,
      section: 'Error Handling'
    }
  ],
  
  // Events
  'SOL028': [
    {
      title: 'Programs',
      url: `${DOCS_BASE}/core/programs`,
      mdUrl: `${DOCS_BASE}/core/programs.md`,
      section: 'Logging'
    }
  ],
  
  // Instruction Introspection
  'SOL029': [
    {
      title: 'Transactions',
      url: `${DOCS_BASE}/core/transactions`,
      mdUrl: `${DOCS_BASE}/core/transactions.md`,
      section: 'Instructions'
    }
  ],
  
  // Anchor
  'SOL030': [
    {
      title: 'Anchor Framework',
      url: `${DOCS_BASE}/programs/anchor`,
      mdUrl: `${DOCS_BASE}/programs/anchor.md`,
      section: 'Account Constraints'
    }
  ],
  
  // Access Control
  'SOL031': [
    {
      title: 'Programs',
      url: `${DOCS_BASE}/core/programs`,
      mdUrl: `${DOCS_BASE}/core/programs.md`,
      section: 'Authorization'
    }
  ],
  
  // Time Lock
  'SOL032': [
    {
      title: 'Accounts',
      url: `${DOCS_BASE}/core/accounts`,
      mdUrl: `${DOCS_BASE}/core/accounts.md`,
      section: 'Clock Sysvar'
    }
  ],
  
  // Signature Replay
  'SOL033': [
    {
      title: 'Transactions',
      url: `${DOCS_BASE}/core/transactions`,
      mdUrl: `${DOCS_BASE}/core/transactions.md`,
      section: 'Signatures'
    }
  ],
  
  // Storage Collision
  'SOL034': [
    {
      title: 'Accounts',
      url: `${DOCS_BASE}/core/accounts`,
      mdUrl: `${DOCS_BASE}/core/accounts.md`,
      section: 'Account Data'
    }
  ],
  
  // Token operations
  'SOL038': [
    {
      title: 'Token Extensions',
      url: `${DOCS_BASE}/core/tokens`,
      mdUrl: `${DOCS_BASE}/core/tokens.md`,
      section: 'Token-2022'
    }
  ],
  
  // CPI Guard
  'SOL040': [
    {
      title: 'Cross Program Invocation',
      url: `${DOCS_BASE}/core/cpi`,
      mdUrl: `${DOCS_BASE}/core/cpi.md`,
      section: 'CPI Security'
    }
  ],
};

// Topic to docs mapping for the learn command
export const topicDocs: Record<string, DocReference[]> = {
  'accounts': [
    {
      title: 'Accounts',
      url: `${DOCS_BASE}/core/accounts`,
      mdUrl: `${DOCS_BASE}/core/accounts.md`
    }
  ],
  'pda': [
    {
      title: 'Program Derived Addresses',
      url: `${DOCS_BASE}/core/pda`,
      mdUrl: `${DOCS_BASE}/core/pda.md`
    }
  ],
  'cpi': [
    {
      title: 'Cross Program Invocation',
      url: `${DOCS_BASE}/core/cpi`,
      mdUrl: `${DOCS_BASE}/core/cpi.md`
    }
  ],
  'tokens': [
    {
      title: 'Tokens on Solana',
      url: `${DOCS_BASE}/core/tokens`,
      mdUrl: `${DOCS_BASE}/core/tokens.md`
    }
  ],
  'transactions': [
    {
      title: 'Transactions',
      url: `${DOCS_BASE}/core/transactions`,
      mdUrl: `${DOCS_BASE}/core/transactions.md`
    }
  ],
  'programs': [
    {
      title: 'Programs on Solana',
      url: `${DOCS_BASE}/core/programs`,
      mdUrl: `${DOCS_BASE}/core/programs.md`
    }
  ],
  'fees': [
    {
      title: 'Fees on Solana',
      url: `${DOCS_BASE}/core/fees`,
      mdUrl: `${DOCS_BASE}/core/fees.md`
    }
  ],
  'rent': [
    {
      title: 'Fees on Solana',
      url: `${DOCS_BASE}/core/fees`,
      mdUrl: `${DOCS_BASE}/core/fees.md`,
      section: 'Rent'
    }
  ],
  'anchor': [
    {
      title: 'Anchor Framework',
      url: `${DOCS_BASE}/programs/anchor`,
      mdUrl: `${DOCS_BASE}/programs/anchor.md`
    }
  ],
  'rust': [
    {
      title: 'Developing Programs in Rust',
      url: `${DOCS_BASE}/programs/lang-rust`,
      mdUrl: `${DOCS_BASE}/programs/lang-rust.md`
    }
  ],
};

/**
 * Get documentation references for a pattern ID
 */
export function getDocsForPattern(patternId: string): DocReference[] {
  return patternDocs[patternId] || [];
}

/**
 * Get documentation references for a topic
 */
export function getDocsForTopic(topic: string): DocReference[] {
  const normalized = topic.toLowerCase().replace(/[^a-z0-9]/g, '');
  return topicDocs[normalized] || [];
}

/**
 * Fetch markdown content from Solana docs
 */
export async function fetchDocContent(mdUrl: string): Promise<string> {
  try {
    const response = await fetch(mdUrl);
    if (!response.ok) {
      throw new Error(`Failed to fetch: ${response.status}`);
    }
    return await response.text();
  } catch (error) {
    throw new Error(`Could not fetch documentation: ${error}`);
  }
}
