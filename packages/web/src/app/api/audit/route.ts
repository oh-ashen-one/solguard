import { NextRequest, NextResponse } from 'next/server';
import { writeFileSync, unlinkSync, mkdirSync, existsSync } from 'fs';
import { execSync } from 'child_process';
import { join } from 'path';
import { randomUUID } from 'crypto';

export async function POST(request: NextRequest) {
  try {
    const { code } = await request.json();
    
    if (!code || typeof code !== 'string') {
      return NextResponse.json(
        { error: 'Code is required' },
        { status: 400 }
      );
    }

    // Create temp directory for the code
    const tempDir = join(process.cwd(), '.tmp');
    if (!existsSync(tempDir)) {
      mkdirSync(tempDir, { recursive: true });
    }
    
    const fileId = randomUUID();
    const filePath = join(tempDir, `${fileId}.rs`);
    
    try {
      // Write code to temp file
      writeFileSync(filePath, code);
      
      // Run solguard CLI
      const cliPath = join(process.cwd(), '..', 'cli', 'dist', 'index.js');
      
      let output: string;
      try {
        output = execSync(
          `node "${cliPath}" audit "${filePath}" --output json --no-ai`,
          { encoding: 'utf-8', timeout: 30000 }
        );
      } catch (execError: any) {
        // CLI exits with code 1 when vulnerabilities found - that's expected
        output = execError.stdout || '';
        if (!output && execError.stderr) {
          throw new Error(execError.stderr);
        }
      }
      
      // Parse JSON output
      const result = JSON.parse(output);
      
      return NextResponse.json(result);
      
    } finally {
      // Clean up temp file
      try {
        unlinkSync(filePath);
      } catch {}
    }
    
  } catch (error: any) {
    console.error('Audit error:', error);
    return NextResponse.json(
      { error: error.message || 'Failed to run audit' },
      { status: 500 }
    );
  }
}
