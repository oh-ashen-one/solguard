import { readFileSync } from 'fs';

export interface IdlInstruction {
  name: string;
  accounts: IdlAccount[];
  args: IdlArg[];
}

export interface IdlAccount {
  name: string;
  isMut: boolean;
  isSigner: boolean;
  isOptional?: boolean;
  pda?: {
    seeds: IdlSeed[];
  };
}

export interface IdlArg {
  name: string;
  type: string | object;
}

export interface IdlSeed {
  kind: string;
  value?: any;
  path?: string;
}

export interface IdlType {
  name: string;
  type: {
    kind: string;
    fields?: any[];
  };
}

export interface IdlError {
  code: number;
  name: string;
  msg: string;
}

export interface ParsedIdl {
  name: string;
  version: string;
  instructions: IdlInstruction[];
  accounts: IdlType[];
  types: IdlType[];
  errors: IdlError[];
  metadata?: any;
}

export async function parseIdl(idlPath: string): Promise<ParsedIdl> {
  const content = readFileSync(idlPath, 'utf-8');
  const idl = JSON.parse(content);
  
  // Normalize IDL format (Anchor IDL can vary between versions)
  const instructions: IdlInstruction[] = (idl.instructions || []).map((ix: any) => ({
    name: ix.name,
    accounts: (ix.accounts || []).map((acc: any) => ({
      name: acc.name,
      isMut: acc.isMut ?? acc.writable ?? false,
      isSigner: acc.isSigner ?? acc.signer ?? false,
      isOptional: acc.isOptional ?? false,
      pda: acc.pda,
    })),
    args: (ix.args || []).map((arg: any) => ({
      name: arg.name,
      type: arg.type,
    })),
  }));

  const accounts: IdlType[] = (idl.accounts || []).map((acc: any) => ({
    name: acc.name,
    type: acc.type,
  }));

  const types: IdlType[] = (idl.types || []).map((t: any) => ({
    name: t.name,
    type: t.type,
  }));

  const errors: IdlError[] = (idl.errors || []).map((e: any) => ({
    code: e.code,
    name: e.name,
    msg: e.msg,
  }));

  return {
    name: idl.name || idl.metadata?.name || 'unknown',
    version: idl.version || idl.metadata?.version || '0.0.0',
    instructions,
    accounts,
    types,
    errors,
    metadata: idl.metadata,
  };
}

// Utility functions for IDL analysis
export function getAccountsWithoutSigner(idl: ParsedIdl): { instruction: string; account: string }[] {
  const results: { instruction: string; account: string }[] = [];
  
  for (const ix of idl.instructions) {
    // Check if instruction has any signer
    const hasSigner = ix.accounts.some(acc => acc.isSigner);
    if (!hasSigner && ix.accounts.length > 0) {
      results.push({
        instruction: ix.name,
        account: ix.accounts[0].name,
      });
    }
  }
  
  return results;
}

export function getMutableAccountsWithoutOwnerCheck(idl: ParsedIdl): { instruction: string; account: string }[] {
  const results: { instruction: string; account: string }[] = [];
  
  for (const ix of idl.instructions) {
    for (const acc of ix.accounts) {
      // Mutable accounts that aren't PDAs and aren't system accounts
      if (acc.isMut && !acc.pda && !isSystemAccount(acc.name)) {
        results.push({
          instruction: ix.name,
          account: acc.name,
        });
      }
    }
  }
  
  return results;
}

function isSystemAccount(name: string): boolean {
  const systemAccounts = [
    'system_program',
    'systemProgram',
    'token_program',
    'tokenProgram',
    'rent',
    'clock',
    'associated_token_program',
    'associatedTokenProgram',
  ];
  return systemAccounts.includes(name);
}
