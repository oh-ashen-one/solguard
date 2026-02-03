/**
 * HTML Report Generator
 * 
 * Generates beautiful, shareable audit reports
 */

import { writeFileSync } from 'fs';
import type { Finding } from './audit.js';
import { listPatterns } from '../patterns/index.js';

interface ReportData {
  programName: string;
  programPath: string;
  timestamp: string;
  findings: Finding[];
  summary: {
    critical: number;
    high: number;
    medium: number;
    low: number;
    info: number;
    total: number;
  };
  passed: boolean;
  duration: number;
}

export function generateHtmlReport(data: ReportData): string {
  const severityColors: Record<string, { bg: string; text: string; border: string }> = {
    critical: { bg: '#fef2f2', text: '#991b1b', border: '#f87171' },
    high: { bg: '#fff7ed', text: '#9a3412', border: '#fb923c' },
    medium: { bg: '#fefce8', text: '#854d0e', border: '#facc15' },
    low: { bg: '#eff6ff', text: '#1e40af', border: '#60a5fa' },
    info: { bg: '#f9fafb', text: '#374151', border: '#d1d5db' },
  };

  const patterns = listPatterns();
  
  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>SolGuard Audit Report - ${data.programName}</title>
  <style>
    * { margin: 0; padding: 0; box-sizing: border-box; }
    body { 
      font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
      background: linear-gradient(135deg, #0f172a 0%, #1e293b 100%);
      color: #e2e8f0;
      min-height: 100vh;
      padding: 2rem;
    }
    .container { max-width: 1000px; margin: 0 auto; }
    
    header {
      text-align: center;
      margin-bottom: 2rem;
      padding: 2rem;
      background: rgba(30, 41, 59, 0.5);
      border-radius: 1rem;
      border: 1px solid rgba(255, 255, 255, 0.1);
    }
    .logo { font-size: 3rem; margin-bottom: 0.5rem; }
    h1 { font-size: 1.5rem; color: #10b981; margin-bottom: 0.5rem; }
    .subtitle { color: #94a3b8; font-size: 0.9rem; }
    
    .meta {
      display: grid;
      grid-template-columns: repeat(4, 1fr);
      gap: 1rem;
      margin-bottom: 2rem;
    }
    .meta-card {
      background: rgba(30, 41, 59, 0.5);
      padding: 1rem;
      border-radius: 0.5rem;
      text-align: center;
      border: 1px solid rgba(255, 255, 255, 0.1);
    }
    .meta-value { font-size: 1.5rem; font-weight: bold; color: #10b981; }
    .meta-label { font-size: 0.75rem; color: #94a3b8; margin-top: 0.25rem; }
    
    .summary {
      display: grid;
      grid-template-columns: repeat(5, 1fr);
      gap: 1rem;
      margin-bottom: 2rem;
    }
    .summary-card {
      padding: 1rem;
      border-radius: 0.5rem;
      text-align: center;
    }
    .summary-card.critical { background: rgba(239, 68, 68, 0.2); border: 1px solid #ef4444; }
    .summary-card.high { background: rgba(249, 115, 22, 0.2); border: 1px solid #f97316; }
    .summary-card.medium { background: rgba(234, 179, 8, 0.2); border: 1px solid #eab308; }
    .summary-card.low { background: rgba(59, 130, 246, 0.2); border: 1px solid #3b82f6; }
    .summary-card.info { background: rgba(107, 114, 128, 0.2); border: 1px solid #6b7280; }
    .summary-count { font-size: 2rem; font-weight: bold; }
    .summary-label { font-size: 0.75rem; text-transform: uppercase; }
    
    .status {
      text-align: center;
      padding: 1.5rem;
      border-radius: 0.5rem;
      margin-bottom: 2rem;
      font-size: 1.25rem;
      font-weight: bold;
    }
    .status.passed { background: rgba(16, 185, 129, 0.2); border: 1px solid #10b981; color: #10b981; }
    .status.failed { background: rgba(239, 68, 68, 0.2); border: 1px solid #ef4444; color: #ef4444; }
    
    .findings { margin-bottom: 2rem; }
    .findings h2 { margin-bottom: 1rem; color: #f1f5f9; }
    
    .finding {
      background: rgba(30, 41, 59, 0.5);
      border-radius: 0.5rem;
      padding: 1.5rem;
      margin-bottom: 1rem;
      border-left: 4px solid;
    }
    .finding.critical { border-left-color: #ef4444; }
    .finding.high { border-left-color: #f97316; }
    .finding.medium { border-left-color: #eab308; }
    .finding.low { border-left-color: #3b82f6; }
    .finding.info { border-left-color: #6b7280; }
    
    .finding-header { display: flex; justify-content: space-between; align-items: flex-start; margin-bottom: 0.75rem; }
    .finding-title { font-weight: 600; color: #f1f5f9; }
    .finding-badge {
      font-size: 0.7rem;
      padding: 0.25rem 0.5rem;
      border-radius: 9999px;
      text-transform: uppercase;
      font-weight: 600;
    }
    .finding-badge.critical { background: #ef4444; color: white; }
    .finding-badge.high { background: #f97316; color: white; }
    .finding-badge.medium { background: #eab308; color: black; }
    .finding-badge.low { background: #3b82f6; color: white; }
    .finding-badge.info { background: #6b7280; color: white; }
    
    .finding-pattern { font-family: monospace; color: #94a3b8; font-size: 0.85rem; margin-bottom: 0.5rem; }
    .finding-desc { color: #cbd5e1; line-height: 1.5; margin-bottom: 0.75rem; }
    .finding-location { font-family: monospace; font-size: 0.85rem; color: #64748b; }
    
    .recommendation {
      margin-top: 1rem;
      padding: 1rem;
      background: rgba(16, 185, 129, 0.1);
      border: 1px solid rgba(16, 185, 129, 0.3);
      border-radius: 0.5rem;
    }
    .recommendation-title { font-size: 0.85rem; color: #10b981; font-weight: 600; margin-bottom: 0.5rem; }
    .recommendation-text { color: #94a3b8; font-size: 0.9rem; }
    
    .patterns {
      background: rgba(30, 41, 59, 0.5);
      border-radius: 0.5rem;
      padding: 1.5rem;
      border: 1px solid rgba(255, 255, 255, 0.1);
    }
    .patterns h2 { margin-bottom: 1rem; color: #f1f5f9; }
    .patterns-grid { display: grid; grid-template-columns: repeat(3, 1fr); gap: 0.75rem; }
    .pattern {
      font-size: 0.85rem;
      padding: 0.5rem 0.75rem;
      background: rgba(15, 23, 42, 0.5);
      border-radius: 0.25rem;
      display: flex;
      justify-content: space-between;
      align-items: center;
    }
    .pattern-id { font-family: monospace; color: #64748b; }
    .pattern-severity {
      font-size: 0.7rem;
      padding: 0.125rem 0.375rem;
      border-radius: 9999px;
      text-transform: uppercase;
    }
    
    footer {
      text-align: center;
      padding: 2rem;
      color: #64748b;
      font-size: 0.85rem;
    }
    footer a { color: #10b981; text-decoration: none; }
    
    @media (max-width: 768px) {
      .meta, .summary { grid-template-columns: repeat(2, 1fr); }
      .patterns-grid { grid-template-columns: 1fr; }
    }
  </style>
</head>
<body>
  <div class="container">
    <header>
      <div class="logo">🛡️</div>
      <h1>SolGuard Security Audit</h1>
      <div class="subtitle">${data.programName}</div>
    </header>
    
    <div class="meta">
      <div class="meta-card">
        <div class="meta-value">${data.findings.length}</div>
        <div class="meta-label">Findings</div>
      </div>
      <div class="meta-card">
        <div class="meta-value">${patterns.length}</div>
        <div class="meta-label">Patterns Checked</div>
      </div>
      <div class="meta-card">
        <div class="meta-value">${data.duration}ms</div>
        <div class="meta-label">Scan Duration</div>
      </div>
      <div class="meta-card">
        <div class="meta-value">${new Date(data.timestamp).toLocaleDateString()}</div>
        <div class="meta-label">Audit Date</div>
      </div>
    </div>
    
    <div class="summary">
      <div class="summary-card critical">
        <div class="summary-count">${data.summary.critical}</div>
        <div class="summary-label">Critical</div>
      </div>
      <div class="summary-card high">
        <div class="summary-count">${data.summary.high}</div>
        <div class="summary-label">High</div>
      </div>
      <div class="summary-card medium">
        <div class="summary-count">${data.summary.medium}</div>
        <div class="summary-label">Medium</div>
      </div>
      <div class="summary-card low">
        <div class="summary-count">${data.summary.low}</div>
        <div class="summary-label">Low</div>
      </div>
      <div class="summary-card info">
        <div class="summary-count">${data.summary.info}</div>
        <div class="summary-label">Info</div>
      </div>
    </div>
    
    <div class="status ${data.passed ? 'passed' : 'failed'}">
      ${data.passed ? '✅ AUDIT PASSED' : '❌ ISSUES FOUND'}
    </div>
    
    ${data.findings.length > 0 ? `
    <div class="findings">
      <h2>Findings (${data.findings.length})</h2>
      ${data.findings.map(f => `
      <div class="finding ${f.severity}">
        <div class="finding-header">
          <div class="finding-title">${escapeHtml(f.title)}</div>
          <span class="finding-badge ${f.severity}">${f.severity}</span>
        </div>
        <div class="finding-pattern">[${f.pattern}]</div>
        <div class="finding-desc">${escapeHtml(f.description)}</div>
        <div class="finding-location">📍 ${escapeHtml(typeof f.location === 'string' ? f.location : f.location.file)}</div>
        ${f.recommendation ? `
        <div class="recommendation">
          <div class="recommendation-title">💡 Recommendation</div>
          <div class="recommendation-text">${escapeHtml(f.recommendation)}</div>
        </div>
        ` : ''}
      </div>
      `).join('')}
    </div>
    ` : ''}
    
    <div class="patterns">
      <h2>Patterns Checked (${patterns.length})</h2>
      <div class="patterns-grid">
        ${patterns.map(p => `
        <div class="pattern">
          <span>
            <span class="pattern-id">${p.id}</span>
            ${p.name}
          </span>
          <span class="pattern-severity" style="background: ${
            p.severity === 'critical' ? '#ef4444' :
            p.severity === 'high' ? '#f97316' :
            p.severity === 'medium' ? '#eab308' :
            p.severity === 'low' ? '#3b82f6' : '#6b7280'
          }; color: ${p.severity === 'medium' ? 'black' : 'white'}">
            ${p.severity}
          </span>
        </div>
        `).join('')}
      </div>
    </div>
    
    <footer>
      <p>Generated by <a href="https://github.com/oh-ashen-one/solguard">SolGuard</a></p>
      <p>Built by Midir 🐉 for the Solana x OpenClaw Agent Hackathon 2026</p>
    </footer>
  </div>
</body>
</html>`;
}

function escapeHtml(str: string): string {
  return str
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#039;');
}

export function saveHtmlReport(data: ReportData, outputPath: string): void {
  const html = generateHtmlReport(data);
  writeFileSync(outputPath, html);
}
