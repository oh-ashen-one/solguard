import type { Finding } from '../commands/audit.js';
import type { ParsedIdl } from '../parsers/idl.js';
import type { ParsedRust } from '../parsers/rust.js';

/**
 * SOL237: Phantom/Wallet DoS Protection
 * Detects patterns that could cause wallet DoS or poor UX
 * Reference: Phantom wallet DDoS incident, wallet rendering issues
 */
export function checkPhantomDos(idl: ParsedIdl | null, rust: ParsedRust | null): Finding[] {
  const findings: Finding[] = [];

  if (rust) {
    for (const fn of rust.functions) {
      const content = fn.body.toLowerCase();

      // Check for excessive account creation
      if (content.includes('create_account') || content.includes('init ')) {
        if (content.includes('loop') || content.includes('for ') || content.includes('while ')) {
          findings.push({
            id: 'SOL237',
            severity: 'medium',
            title: 'Mass Account Creation',
            description: 'Account creation in a loop could spam a wallet with many accounts, causing DoS in wallet UIs.',
            location: `Function: ${fn.name}`,
            recommendation: 'Rate limit account creation. Consider batching or using PDAs to reduce account spam.',
          });
        }
      }

      // Check for token account spam
      if (content.includes('associated_token') || content.includes('init_if_needed')) {
        if (content.includes('mint') && !content.includes('close')) {
          findings.push({
            id: 'SOL237',
            severity: 'low',
            title: 'Potential Token Account Spam',
            description: 'Token accounts can be created for a wallet without their consent, spamming their wallet view.',
            location: `Function: ${fn.name}`,
            recommendation: 'Consider whitelist mechanisms or allow users to hide/close unwanted token accounts.',
          });
        }
      }

      // Check for NFT spam patterns
      if (content.includes('nft') || content.includes('metadata')) {
        if (content.includes('create') && content.includes('airdrop')) {
          findings.push({
            id: 'SOL237',
            severity: 'medium',
            title: 'NFT Airdrop Spam Vector',
            description: 'Unsolicited NFT airdrops can spam wallets and some contain malicious metadata URLs.',
            location: `Function: ${fn.name}`,
            recommendation: 'Consider requiring user opt-in for airdrops. Validate metadata URLs are from trusted sources.',
          });
        }
      }

      // Check for memo spam
      if (content.includes('memo') || content.includes('spl_memo')) {
        if (!content.includes('signer') || content.includes('arbitrary')) {
          findings.push({
            id: 'SOL237',
            severity: 'low',
            title: 'Memo Spam Potential',
            description: 'Memos can be attached to transactions targeting any wallet, potentially spamming transaction history.',
            location: `Function: ${fn.name}`,
            recommendation: 'Wallets should filter/hide memo spam. Programs should validate memo senders if relevant.',
          });
        }
      }

      // Check for large account data
      if (content.includes('realloc') || content.includes('account_info.data_len')) {
        if (content.includes('max_size') || content.includes('10240') || /\d{5,}/.test(fn.body)) {
          findings.push({
            id: 'SOL237',
            severity: 'low',
            title: 'Large Account Data',
            description: 'Very large account data can slow down wallet loading and RPC responses.',
            location: `Function: ${fn.name}`,
            recommendation: 'Paginate large data or use multiple smaller accounts. Consider lazy loading in clients.',
          });
        }
      }

      // Check for simulation-heavy operations
      if (content.includes('simulate') || content.includes('preflight')) {
        if (content.includes('retry') || content.includes('loop')) {
          findings.push({
            id: 'SOL237',
            severity: 'info',
            title: 'Heavy Simulation Pattern',
            description: 'Repeated transaction simulation can strain RPC nodes and slow wallet responsiveness.',
            location: `Function: ${fn.name}`,
            recommendation: 'Cache simulation results. Use exponential backoff for retries.',
          });
        }
      }

      // Check for deep CPI chains
      let cpiCount = 0;
      const matches = content.match(/invoke/g);
      if (matches) {
        cpiCount = matches.length;
      }
      if (cpiCount >= 3) {
        findings.push({
          id: 'SOL237',
          severity: 'low',
          title: 'Deep CPI Chain',
          description: `Function has ${cpiCount} CPIs. Deep CPI chains can be hard for wallets to simulate and display.`,
          location: `Function: ${fn.name}`,
          recommendation: 'Minimize CPI depth. Consider restructuring to reduce nested calls.',
        });
      }
    }
  }

  if (idl) {
    // Check instruction complexity
    for (const instruction of idl.instructions) {
      if (instruction.accounts.length > 20) {
        findings.push({
          id: 'SOL237',
          severity: 'low',
          title: 'High Account Count Instruction',
          description: `Instruction ${instruction.name} requires ${instruction.accounts.length} accounts. May be slow to simulate.`,
          location: `Instruction: ${instruction.name}`,
          recommendation: 'Consider splitting into multiple instructions or using remaining_accounts for optional accounts.',
        });
      }

      // Check for remaining_accounts abuse potential
      if (instruction.name.toLowerCase().includes('batch') || 
          instruction.name.toLowerCase().includes('multi')) {
        findings.push({
          id: 'SOL237',
          severity: 'info',
          title: 'Batch Operation',
          description: 'Batch operations with many remaining accounts can be slow to process in wallets.',
          location: `Instruction: ${instruction.name}`,
          recommendation: 'Set reasonable limits on batch sizes. Provide gas estimates to users.',
        });
      }
    }
  }

  return findings;
}
