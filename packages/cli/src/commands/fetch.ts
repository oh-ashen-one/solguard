import chalk from 'chalk';
import ora from 'ora';
import { Connection, PublicKey } from '@solana/web3.js';
import { writeFileSync, mkdirSync, existsSync } from 'fs';
import { join } from 'path';
import { auditCommand } from './audit.js';

interface FetchOptions {
  rpc?: string;
  output?: 'terminal' | 'json' | 'markdown';
  ai?: boolean;
  verbose?: boolean;
}

const DEFAULT_RPC = 'https://api.mainnet-beta.solana.com';

/**
 * Fetch a program's IDL from on-chain and audit it
 */
export async function fetchAndAuditCommand(programId: string, options: FetchOptions) {
  const spinner = ora('Connecting to Solana...').start();
  
  try {
    // Validate program ID
    let pubkey: PublicKey;
    try {
      pubkey = new PublicKey(programId);
    } catch {
      spinner.fail('Invalid program ID');
      process.exit(1);
    }

    const rpcUrl = options.rpc || process.env.SOLANA_RPC_URL || DEFAULT_RPC;
    const connection = new Connection(rpcUrl, 'confirmed');

    // Check if program exists
    spinner.text = 'Checking program account...';
    const accountInfo = await connection.getAccountInfo(pubkey);
    
    if (!accountInfo) {
      spinner.fail(`Program not found: ${programId}`);
      process.exit(1);
    }

    if (!accountInfo.executable) {
      spinner.fail(`Account is not a program: ${programId}`);
      process.exit(1);
    }

    // Try to fetch IDL (Anchor programs store IDL on-chain)
    spinner.text = 'Fetching IDL...';
    
    // Anchor IDL address derivation
    const [idlAddress] = PublicKey.findProgramAddressSync(
      [Buffer.from('anchor:idl'), pubkey.toBuffer()],
      pubkey
    );

    const idlAccount = await connection.getAccountInfo(idlAddress);
    
    if (!idlAccount) {
      spinner.warn('No Anchor IDL found on-chain');
      console.log(chalk.yellow('\n  This program may not be an Anchor program, or IDL was not published.'));
      console.log(chalk.yellow('  Try auditing the source code directly instead.\n'));
      process.exit(1);
    }

    // Parse IDL data (skip 8-byte discriminator + 4-byte length)
    const idlData = idlAccount.data.slice(12);
    
    // Decompress if needed (Anchor compresses large IDLs)
    let idlJson: string;
    try {
      // Try to parse as raw JSON first
      idlJson = idlData.toString('utf8');
      JSON.parse(idlJson); // Validate it's valid JSON
    } catch {
      // May be compressed - for now, skip
      spinner.fail('IDL appears to be compressed. Decompression not yet supported.');
      process.exit(1);
    }

    // Save IDL to temp file
    const tempDir = join(process.cwd(), '.solguard-temp');
    if (!existsSync(tempDir)) {
      mkdirSync(tempDir, { recursive: true });
    }

    const idlPath = join(tempDir, `${programId}.json`);
    writeFileSync(idlPath, idlJson);

    spinner.succeed(`IDL fetched for ${programId}`);
    console.log(chalk.gray(`  Saved to: ${idlPath}\n`));

    // Run audit on the IDL
    await auditCommand(idlPath, {
      output: options.output || 'terminal',
      ai: options.ai !== false,
      verbose: options.verbose || false,
    });

  } catch (error: any) {
    spinner.fail(`Failed to fetch program: ${error.message}`);
    if (options.verbose) {
      console.error(error);
    }
    process.exit(1);
  }
}

/**
 * List popular Solana programs for reference
 */
export function listKnownPrograms() {
  const programs = [
    { name: 'Token Program', id: 'TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA' },
    { name: 'Token 2022', id: 'TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb' },
    { name: 'Associated Token', id: 'ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL' },
    { name: 'Metaplex Token Metadata', id: 'metaqbxxUerdq28cj1RbAWkYQm3ybzjb6a8bt518x1s' },
    { name: 'Metaplex Bubblegum', id: 'BGUMAp9Gq7iTEuizy4pqaxsTyUCBK68MDfK752saRPUY' },
    { name: 'Marinade Finance', id: 'MarBmsSgKXdrN1egZf5sqe1TMai9K1rChYNDJgjq7aD' },
    { name: 'Raydium AMM', id: '675kPX9MHTjS2zt1qfr1NYHuzeLXfQM9H24wFSUt1Mp8' },
    { name: 'Orca Whirlpools', id: 'whirLbMiicVdio4qvUfM5KAg6Ct8VwpYzGff3uctyCc' },
    { name: 'Jupiter Aggregator', id: 'JUP6LkbZbjS1jKKwapdHNy74zcZ3tLUZoi5QNyVTaV4' },
    { name: 'Squads V3', id: 'SMPLecH534NA9acpos4G6x7uf3LWbCAwZQE9e8ZekMu' },
  ];

  console.log(chalk.bold('\n  Known Solana Programs:\n'));
  
  for (const program of programs) {
    console.log(chalk.cyan(`  ${program.name}`));
    console.log(chalk.gray(`    ${program.id}\n`));
  }

  console.log(chalk.dim('  Use: solguard fetch <program-id> to audit\n'));
}
