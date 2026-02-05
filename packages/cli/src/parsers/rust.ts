/**
 * Rust Parser - Parses Solana/Anchor Rust files for security analysis
 */

import { readFileSync } from 'fs';

export interface ParsedFile {
  path: string;
  content: string;
  lines: string[];
}

export interface FunctionInfo {
  name: string;
  file: string;
  line: number;
  visibility: string;
  params: string[];
  body: string;
}

export interface StructInfo {
  name: string;
  file: string;
  line: number;
  fields: { name: string; type: string }[];
  attributes: string[];
}

export interface ImplBlock {
  name: string;
  file: string;
  line: number;
  methods: string[];
}

export interface ParsedRust {
  files: ParsedFile[];
  functions: FunctionInfo[];
  structs: StructInfo[];
  implBlocks: ImplBlock[];
  content: string;
  filePath: string;
}

/**
 * Parse Rust files into structured format for pattern analysis
 */
export async function parseRustFiles(filePaths: string[]): Promise<ParsedRust> {
  const files: ParsedFile[] = [];
  const functions: FunctionInfo[] = [];
  const structs: StructInfo[] = [];
  const implBlocks: ImplBlock[] = [];
  let allContent = '';

  for (const filePath of filePaths) {
    try {
      const content = readFileSync(filePath, 'utf-8');
      const lines = content.split('\n');
      allContent += content + '\n';
      
      files.push({ path: filePath, content, lines });
      
      // Parse functions
      const funcRegex = /(?:pub\s+)?fn\s+(\w+)\s*\(([^)]*)\)/g;
      let match;
      while ((match = funcRegex.exec(content)) !== null) {
        const lineNum = content.substring(0, match.index).split('\n').length;
        functions.push({
          name: match[1],
          file: filePath,
          line: lineNum,
          visibility: match[0].includes('pub') ? 'public' : 'private',
          params: match[2].split(',').map(p => p.trim()).filter(Boolean),
          body: extractFunctionBody(content, match.index),
        });
      }
      
      // Parse structs
      const structRegex = /((?:#\[[^\]]+\]\s*)*)?(?:pub\s+)?struct\s+(\w+)/g;
      while ((match = structRegex.exec(content)) !== null) {
        const lineNum = content.substring(0, match.index).split('\n').length;
        structs.push({
          name: match[2],
          file: filePath,
          line: lineNum,
          fields: extractStructFields(content, match.index),
          attributes: match[1] ? match[1].split('#').filter(Boolean).map(a => '#' + a.trim()) : [],
        });
      }
      
      // Parse impl blocks
      const implRegex = /impl(?:\s*<[^>]*>)?\s+(\w+)/g;
      while ((match = implRegex.exec(content)) !== null) {
        const lineNum = content.substring(0, match.index).split('\n').length;
        implBlocks.push({
          name: match[1],
          file: filePath,
          line: lineNum,
          methods: extractImplMethods(content, match.index),
        });
      }
    } catch (error) {
      console.warn(`Failed to parse ${filePath}: ${error}`);
    }
  }

  return {
    files,
    functions,
    structs,
    implBlocks,
    content: allContent,
    filePath: filePaths[0] || '',
  };
}

function extractFunctionBody(content: string, startIndex: number): string {
  let braceCount = 0;
  let started = false;
  let bodyStart = startIndex;
  
  for (let i = startIndex; i < content.length; i++) {
    if (content[i] === '{') {
      if (!started) {
        started = true;
        bodyStart = i;
      }
      braceCount++;
    } else if (content[i] === '}') {
      braceCount--;
      if (started && braceCount === 0) {
        return content.substring(bodyStart, i + 1);
      }
    }
  }
  return '';
}

function extractStructFields(content: string, startIndex: number): { name: string; type: string }[] {
  const fields: { name: string; type: string }[] = [];
  let braceCount = 0;
  let started = false;
  let fieldSection = '';
  
  for (let i = startIndex; i < content.length; i++) {
    if (content[i] === '{') {
      started = true;
      braceCount++;
    } else if (content[i] === '}') {
      braceCount--;
      if (started && braceCount === 0) {
        break;
      }
    } else if (started && braceCount === 1) {
      fieldSection += content[i];
    }
  }
  
  const fieldRegex = /(?:pub\s+)?(\w+)\s*:\s*([^,}]+)/g;
  let match;
  while ((match = fieldRegex.exec(fieldSection)) !== null) {
    fields.push({ name: match[1], type: match[2].trim() });
  }
  
  return fields;
}

function extractImplMethods(content: string, startIndex: number): string[] {
  const methods: string[] = [];
  let braceCount = 0;
  let started = false;
  let implBlock = '';
  
  for (let i = startIndex; i < content.length; i++) {
    if (content[i] === '{') {
      started = true;
      braceCount++;
    } else if (content[i] === '}') {
      braceCount--;
      if (started && braceCount === 0) {
        break;
      }
    }
    if (started) {
      implBlock += content[i];
    }
  }
  
  const methodRegex = /(?:pub\s+)?fn\s+(\w+)/g;
  let match;
  while ((match = methodRegex.exec(implBlock)) !== null) {
    methods.push(match[1]);
  }
  
  return methods;
}

export type { ParsedRust as default };
