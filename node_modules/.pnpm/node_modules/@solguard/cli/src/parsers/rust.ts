import { readFileSync } from 'fs';

// Note: For MVP, we'll use regex-based parsing
// tree-sitter can be added later for more robust AST analysis

export interface RustFile {
  path: string;
  content: string;
  lines: string[];
}

export interface ParsedRust {
  files: RustFile[];
  functions: RustFunction[];
  structs: RustStruct[];
  implBlocks: RustImpl[];
}

export interface RustFunction {
  name: string;
  file: string;
  line: number;
  isPublic: boolean;
  content: string;
}

export interface RustStruct {
  name: string;
  file: string;
  line: number;
  fields: { name: string; type: string }[];
  attributes: string[];
}

export interface RustImpl {
  structName: string;
  file: string;
  line: number;
  methods: RustFunction[];
}

export async function parseRustFiles(paths: string[]): Promise<ParsedRust> {
  const files: RustFile[] = paths.map(path => {
    const content = readFileSync(path, 'utf-8');
    return {
      path,
      content,
      lines: content.split('\n'),
    };
  });

  const functions: RustFunction[] = [];
  const structs: RustStruct[] = [];
  const implBlocks: RustImpl[] = [];

  for (const file of files) {
    // Parse functions
    const fnMatches = file.content.matchAll(/^(\s*)(pub\s+)?fn\s+(\w+)/gm);
    for (const match of fnMatches) {
      const line = file.content.substring(0, match.index).split('\n').length;
      functions.push({
        name: match[3],
        file: file.path,
        line,
        isPublic: !!match[2],
        content: extractBlock(file.content, match.index!),
      });
    }

    // Parse structs with #[derive(Accounts)] or #[account]
    const structMatches = file.content.matchAll(/((?:#\[[\w\(\)]+\]\s*)+)?pub\s+struct\s+(\w+)/gm);
    for (const match of structMatches) {
      const line = file.content.substring(0, match.index).split('\n').length;
      const attributes = match[1] ? match[1].match(/#\[[\w\(\),\s=]+\]/g) || [] : [];
      
      structs.push({
        name: match[2],
        file: file.path,
        line,
        fields: [], // Would need proper parsing for fields
        attributes,
      });
    }

    // Parse impl blocks
    const implMatches = file.content.matchAll(/impl(?:<[^>]+>)?\s+(\w+)/gm);
    for (const match of implMatches) {
      const line = file.content.substring(0, match.index).split('\n').length;
      implBlocks.push({
        structName: match[1],
        file: file.path,
        line,
        methods: [],
      });
    }
  }

  return { files, functions, structs, implBlocks };
}

function extractBlock(content: string, startIndex: number): string {
  let braceCount = 0;
  let started = false;
  let endIndex = startIndex;

  for (let i = startIndex; i < content.length; i++) {
    if (content[i] === '{') {
      braceCount++;
      started = true;
    } else if (content[i] === '}') {
      braceCount--;
      if (started && braceCount === 0) {
        endIndex = i + 1;
        break;
      }
    }
  }

  return content.substring(startIndex, endIndex);
}

// Utility functions for finding patterns
export function findUncheckedArithmetic(rust: ParsedRust): { file: string; line: number; code: string }[] {
  const results: { file: string; line: number; code: string }[] = [];
  
  // Look for raw arithmetic operations not using checked_* methods
  const arithmeticPattern = /(\w+)\s*[\+\-\*]\s*(\w+)(?!\s*\.checked_)/g;
  
  for (const file of rust.files) {
    for (let i = 0; i < file.lines.length; i++) {
      const line = file.lines[i];
      // Skip comments
      if (line.trim().startsWith('//')) continue;
      
      const matches = line.matchAll(arithmeticPattern);
      for (const match of matches) {
        // Filter out obvious non-numeric operations
        if (!line.includes('checked_') && !line.includes('.saturating_')) {
          results.push({
            file: file.path,
            line: i + 1,
            code: line.trim(),
          });
        }
      }
    }
  }
  
  return results;
}

export function findMissingOwnerChecks(rust: ParsedRust): { file: string; line: number; account: string }[] {
  const results: { file: string; line: number; account: string }[] = [];
  
  // NOTE: Anchor's Account<'info, T> already validates ownership for #[account] types.
  // We only flag AccountInfo<'info> used without manual owner verification,
  // or external types like TokenAccount that need explicit owner constraints.
  
  const externalAccountTypes = ['TokenAccount', 'Mint', 'AssociatedTokenAccount'];
  
  for (const file of rust.files) {
    const content = file.content;
    
    // Check for external account types without owner constraint
    for (const extType of externalAccountTypes) {
      const pattern = new RegExp(`pub\\s+(\\w+):\\s*Account<'info,\\s*${extType}>`, 'g');
      const ownerPattern = /#\[account\([^)]*(?:owner|token::authority|associated_token::authority)\s*=/;
      
      const matches = content.matchAll(pattern);
      for (const match of matches) {
        const lineIndex = content.substring(0, match.index).split('\n').length - 1;
        const precedingLines = file.lines.slice(Math.max(0, lineIndex - 5), lineIndex + 1).join('\n');
        
        if (!ownerPattern.test(precedingLines)) {
          results.push({
            file: file.path,
            line: lineIndex + 1,
            account: match[1],
          });
        }
      }
    }
    
    // Check for raw AccountInfo without owner verification in the function body
    const accountInfoPattern = /pub\s+(\w+):\s*(?:UncheckedAccount|AccountInfo)<'info>/g;
    const matches = content.matchAll(accountInfoPattern);
    
    for (const match of matches) {
      const lineIndex = content.substring(0, match.index).split('\n').length - 1;
      const accountName = match[1];
      
      // Skip if it has a CHECK comment (intentionally unchecked)
      const precedingLines = file.lines.slice(Math.max(0, lineIndex - 3), lineIndex + 1).join('\n');
      if (/\/\/\/?\s*CHECK:/.test(precedingLines)) continue;
      
      // Skip system accounts that don't need owner checks
      if (/system_program|rent|clock|token_program|associated_token_program/i.test(accountName)) continue;
      
      // Look for owner verification in the file
      const ownerCheckPattern = new RegExp(`${accountName}\\s*\\.\\s*owner|owner.*${accountName}|require.*${accountName}.*owner`, 'i');
      if (!ownerCheckPattern.test(content)) {
        results.push({
          file: file.path,
          line: lineIndex + 1,
          account: accountName,
        });
      }
    }
  }
  
  return results;
}

export function findMissingSignerChecks(rust: ParsedRust): { file: string; line: number; account: string }[] {
  const results: { file: string; line: number; account: string }[] = [];
  
  // Look for AccountInfo without Signer wrapper
  const accountInfoPattern = /pub\s+(\w+):\s*AccountInfo<'info>/g;
  
  for (const file of rust.files) {
    const matches = file.content.matchAll(accountInfoPattern);
    
    for (const match of matches) {
      const lineIndex = file.content.substring(0, match.index).split('\n').length;
      const accountName = match[1];
      
      // Check if it looks like an authority/admin account
      if (/authority|admin|owner|signer|payer/i.test(accountName)) {
        results.push({
          file: file.path,
          line: lineIndex,
          account: accountName,
        });
      }
    }
  }
  
  return results;
}
