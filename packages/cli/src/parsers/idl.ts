/**
 * IDL Parser - Parses Anchor IDL files for security analysis
 */

import { readFileSync, existsSync } from 'fs';
import { join } from 'path';

export interface IdlInstruction {
  name: string;
  accounts: { name: string; isMut: boolean; isSigner: boolean }[];
  args: { name: string; type: string }[];
}

export interface IdlAccount {
  name: string;
  type: { kind: string; fields: { name: string; type: string }[] };
}

export interface ParsedIdl {
  version: string;
  name: string;
  instructions: IdlInstruction[];
  accounts: IdlAccount[];
  types: any[];
  events: any[];
  errors: any[];
  raw: any;
}

/**
 * Parse Anchor IDL file
 */
export async function parseIdl(programPath: string): Promise<ParsedIdl | null> {
  // Try to find IDL file
  const possiblePaths = [
    join(programPath, 'target', 'idl', '*.json'),
    join(programPath, 'idl.json'),
    join(programPath, '..', 'target', 'idl', '*.json'),
  ];
  
  // For now, look for any JSON file that looks like an IDL
  const searchDir = (dir: string): string | null => {
    try {
      const idlPath = join(dir, 'target', 'idl');
      if (existsSync(idlPath)) {
        const { readdirSync } = require('fs');
        const files = readdirSync(idlPath);
        const idlFile = files.find((f: string) => f.endsWith('.json'));
        if (idlFile) return join(idlPath, idlFile);
      }
    } catch {}
    return null;
  };
  
  const idlPath = searchDir(programPath);
  
  if (!idlPath) {
    return null;
  }
  
  try {
    const content = readFileSync(idlPath, 'utf-8');
    const idl = JSON.parse(content);
    
    return {
      version: idl.version || '0.0.0',
      name: idl.name || 'unknown',
      instructions: idl.instructions || [],
      accounts: idl.accounts || [],
      types: idl.types || [],
      events: idl.events || [],
      errors: idl.errors || [],
      raw: idl,
    };
  } catch (error) {
    console.warn(`Failed to parse IDL at ${idlPath}: ${error}`);
    return null;
  }
}

export type { ParsedIdl as default };
