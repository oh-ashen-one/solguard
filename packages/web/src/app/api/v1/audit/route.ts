import { NextRequest, NextResponse } from 'next/server';
import { writeFileSync, unlinkSync, mkdirSync, existsSync } from 'fs';
import { execSync } from 'child_process';
import { join } from 'path';
import { randomUUID } from 'crypto';

/**
 * SolShield AI Public API for Agents
 * 
 * POST /api/v1/audit
 * 
 * Request body:
 * {
 *   "code": "use anchor_lang::prelude::*; ...",  // Rust source code
 *   "format": "json" | "markdown",               // Optional, default: json
 *   "ai": boolean                                 // Optional, include AI explanations
 * }
 * 
 * Response (success):
 * {
 *   "success": true,
 *   "programPath": "temp file path",
 *   "timestamp": "2026-02-02T...",
 *   "findings": [...],
 *   "summary": { critical: 0, high: 0, ... },
 *   "passed": true,
 *   "severityScore": 0
 * }
 * 
 * Response (error):
 * {
 *   "success": false,
 *   "error": "Error message"
 * }
 */
export async function POST(request: NextRequest) {
  const startTime = Date.now();
  
  try {
    const body = await request.json();
    const { code, format = 'json', ai = false } = body;
    
    // Validate input
    if (!code || typeof code !== 'string') {
      return NextResponse.json(
        { success: false, error: 'Code is required and must be a string' },
        { status: 400 }
      );
    }

    if (code.length > 500000) { // 500KB limit
      return NextResponse.json(
        { success: false, error: 'Code exceeds maximum size (500KB)' },
        { status: 400 }
      );
    }

    // Create temp directory
    const tempDir = join(process.cwd(), '.tmp');
    if (!existsSync(tempDir)) {
      mkdirSync(tempDir, { recursive: true });
    }
    
    const fileId = randomUUID();
    const filePath = join(tempDir, `${fileId}.rs`);
    
    try {
      // Write code to temp file
      writeFileSync(filePath, code);
      
      // Build CLI command
      const cliPath = join(process.cwd(), '..', 'cli', 'dist', 'index.js');
      const aiFlag = ai ? '' : '--no-ai';
      
      let output: string;
      try {
        output = execSync(
          `node "${cliPath}" audit "${filePath}" --output json ${aiFlag}`,
          { 
            encoding: 'utf-8', 
            timeout: 60000, // 60 second timeout
            maxBuffer: 10 * 1024 * 1024, // 10MB buffer
          }
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
      
      // Calculate severity score
      const severityScore = calculateSeverityScore(result.summary);
      
      // Build response
      const response = {
        success: true,
        ...result,
        severityScore,
        executionTimeMs: Date.now() - startTime,
        apiVersion: '1.0.0',
      };

      // Format response
      if (format === 'markdown') {
        return new NextResponse(formatAsMarkdown(result), {
          headers: { 'Content-Type': 'text/markdown' },
        });
      }
      
      return NextResponse.json(response);
      
    } finally {
      // Clean up temp file
      try {
        unlinkSync(filePath);
      } catch {}
    }
    
  } catch (error: any) {
    console.error('Audit API error:', error);
    return NextResponse.json(
      { 
        success: false, 
        error: error.message || 'Failed to run audit',
        executionTimeMs: Date.now() - startTime,
      },
      { status: 500 }
    );
  }
}

function calculateSeverityScore(summary: any): number {
  const weights = { critical: 40, high: 25, medium: 10, low: 3, info: 1 };
  let score = 0;
  score += (summary.critical || 0) * weights.critical;
  score += (summary.high || 0) * weights.high;
  score += (summary.medium || 0) * weights.medium;
  score += (summary.low || 0) * weights.low;
  score += (summary.info || 0) * weights.info;
  return Math.min(100, score);
}

function formatAsMarkdown(result: any): string {
  const lines = [
    '# 🛡️ SolShield AI Audit Report',
    '',
    `**Status:** ${result.passed ? '✅ PASSED' : '❌ FAILED'}`,
    `**Date:** ${result.timestamp}`,
    '',
    '## Summary',
    '',
    `| Severity | Count |`,
    `|----------|-------|`,
    `| 🔴 Critical | ${result.summary.critical} |`,
    `| 🟠 High | ${result.summary.high} |`,
    `| 🟡 Medium | ${result.summary.medium} |`,
    `| 🔵 Low | ${result.summary.low} |`,
    `| ⚪ Info | ${result.summary.info} |`,
    '',
  ];

  if (result.findings.length > 0) {
    lines.push('## Findings', '');
    for (const finding of result.findings) {
      lines.push(`### ${finding.id}: ${finding.title}`);
      lines.push(`**Severity:** ${finding.severity.toUpperCase()}`);
      lines.push(`**Location:** ${finding.location.file}:${finding.location.line || '?'}`);
      lines.push('');
      lines.push(finding.description);
      if (finding.suggestion) {
        lines.push('', '**Recommendation:**', '```rust', finding.suggestion, '```');
      }
      lines.push('');
    }
  }

  lines.push('---', '*Generated by SolShield AI*');
  return lines.join('\n');
}

// Health check endpoint
export async function GET() {
  return NextResponse.json({
    status: 'ok',
    service: 'SolShield AI Audit API',
    version: '1.0.0',
    endpoints: {
      'POST /api/v1/audit': 'Audit Rust/Anchor code',
    },
  });
}
