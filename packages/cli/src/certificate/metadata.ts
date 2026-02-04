/**
 * NFT Certificate Metadata Generator
 * 
 * Generates Metaplex-compatible metadata for audit certificates
 */

import type { AuditResult } from '../commands/audit.js';
import { createHash } from 'crypto';

interface CertificateMetadata {
  name: string;
  symbol: string;
  description: string;
  image: string;
  external_url: string;
  attributes: Array<{
    trait_type: string;
    value: string | number;
  }>;
  properties: {
    files: Array<{
      uri: string;
      type: string;
    }>;
    category: string;
  };
}

/**
 * Generate NFT metadata for an audit certificate
 */
export function generateCertificateMetadata(
  result: AuditResult,
  programId: string,
  imageUri: string = 'https://SolShield AI.dev/certificate.png'
): CertificateMetadata {
  const passed = result.passed;
  const findingsHash = createHash('sha256')
    .update(JSON.stringify(result.findings))
    .digest('hex')
    .slice(0, 16);

  return {
    name: `SolShield AI Audit: ${programId.slice(0, 8)}...`,
    symbol: 'AUDIT',
    description: passed
      ? `✅ This program passed the SolShield AI security audit with no critical or high severity issues.`
      : `⚠️ This program was audited by SolShield AI. ${result.summary.critical} critical and ${result.summary.high} high severity issues were found.`,
    image: imageUri,
    external_url: `https://SolShield AI.dev/audit/${programId}`,
    attributes: [
      {
        trait_type: 'Status',
        value: passed ? 'PASSED' : 'FAILED',
      },
      {
        trait_type: 'Critical Issues',
        value: result.summary.critical,
      },
      {
        trait_type: 'High Issues',
        value: result.summary.high,
      },
      {
        trait_type: 'Medium Issues',
        value: result.summary.medium,
      },
      {
        trait_type: 'Low Issues',
        value: result.summary.low,
      },
      {
        trait_type: 'Total Findings',
        value: result.summary.total,
      },
      {
        trait_type: 'Audit Date',
        value: result.timestamp.split('T')[0],
      },
      {
        trait_type: 'Findings Hash',
        value: findingsHash,
      },
      {
        trait_type: 'Auditor',
        value: 'SolShield AI AI',
      },
      {
        trait_type: 'Version',
        value: '1.0.0',
      },
    ],
    properties: {
      files: [
        {
          uri: imageUri,
          type: 'image/png',
        },
      ],
      category: 'image',
    },
  };
}

/**
 * Generate a severity score (0-100, lower is better)
 */
export function calculateSeverityScore(result: AuditResult): number {
  const weights = {
    critical: 40,
    high: 25,
    medium: 10,
    low: 3,
    info: 1,
  };

  let score = 0;
  score += result.summary.critical * weights.critical;
  score += result.summary.high * weights.high;
  score += result.summary.medium * weights.medium;
  score += result.summary.low * weights.low;
  score += result.summary.info * weights.info;

  // Cap at 100
  return Math.min(100, score);
}

/**
 * Generate certificate image SVG (for on-chain generation)
 */
export function generateCertificateSvg(
  programId: string,
  passed: boolean,
  summary: AuditResult['summary'],
  timestamp: string
): string {
  const statusColor = passed ? '#10B981' : '#EF4444';
  const statusText = passed ? 'PASSED' : 'FAILED';
  const date = new Date(timestamp).toLocaleDateString('en-US', {
    year: 'numeric',
    month: 'short',
    day: 'numeric',
  });

  return `
<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 400 500" width="400" height="500">
  <defs>
    <linearGradient id="bg" x1="0%" y1="0%" x2="100%" y2="100%">
      <stop offset="0%" style="stop-color:#18181B"/>
      <stop offset="100%" style="stop-color:#09090B"/>
    </linearGradient>
  </defs>
  
  <!-- Background -->
  <rect width="400" height="500" fill="url(#bg)" rx="16"/>
  
  <!-- Border -->
  <rect x="8" y="8" width="384" height="484" fill="none" stroke="${statusColor}" stroke-width="2" rx="12" opacity="0.5"/>
  
  <!-- Header -->
  <text x="200" y="50" text-anchor="middle" fill="#FAFAFA" font-family="system-ui" font-size="24" font-weight="bold">🛡️ SolShield AI</text>
  <text x="200" y="75" text-anchor="middle" fill="#71717A" font-family="system-ui" font-size="12">Security Audit Certificate</text>
  
  <!-- Status Badge -->
  <rect x="125" y="100" width="150" height="40" fill="${statusColor}" rx="20"/>
  <text x="200" y="127" text-anchor="middle" fill="#FAFAFA" font-family="system-ui" font-size="18" font-weight="bold">${statusText}</text>
  
  <!-- Program ID -->
  <text x="200" y="180" text-anchor="middle" fill="#A1A1AA" font-family="monospace" font-size="10">Program ID</text>
  <text x="200" y="200" text-anchor="middle" fill="#FAFAFA" font-family="monospace" font-size="11">${programId.slice(0, 22)}...</text>
  
  <!-- Findings Summary -->
  <text x="200" y="250" text-anchor="middle" fill="#A1A1AA" font-family="system-ui" font-size="12">Findings Summary</text>
  
  <g transform="translate(50, 270)">
    <rect width="70" height="50" fill="#7F1D1D" rx="8"/>
    <text x="35" y="25" text-anchor="middle" fill="#FCA5A5" font-family="system-ui" font-size="20" font-weight="bold">${summary.critical}</text>
    <text x="35" y="42" text-anchor="middle" fill="#FCA5A5" font-family="system-ui" font-size="9">Critical</text>
  </g>
  
  <g transform="translate(130, 270)">
    <rect width="70" height="50" fill="#78350F" rx="8"/>
    <text x="35" y="25" text-anchor="middle" fill="#FCD34D" font-family="system-ui" font-size="20" font-weight="bold">${summary.high}</text>
    <text x="35" y="42" text-anchor="middle" fill="#FCD34D" font-family="system-ui" font-size="9">High</text>
  </g>
  
  <g transform="translate(210, 270)">
    <rect width="70" height="50" fill="#422006" rx="8"/>
    <text x="35" y="25" text-anchor="middle" fill="#FDE68A" font-family="system-ui" font-size="20" font-weight="bold">${summary.medium}</text>
    <text x="35" y="42" text-anchor="middle" fill="#FDE68A" font-family="system-ui" font-size="9">Medium</text>
  </g>
  
  <g transform="translate(290, 270)">
    <rect width="70" height="50" fill="#1E3A5F" rx="8"/>
    <text x="35" y="25" text-anchor="middle" fill="#93C5FD" font-family="system-ui" font-size="20" font-weight="bold">${summary.low}</text>
    <text x="35" y="42" text-anchor="middle" fill="#93C5FD" font-family="system-ui" font-size="9">Low</text>
  </g>
  
  <!-- Date -->
  <text x="200" y="370" text-anchor="middle" fill="#71717A" font-family="system-ui" font-size="11">Audited on ${date}</text>
  
  <!-- Footer -->
  <text x="200" y="450" text-anchor="middle" fill="#52525B" font-family="system-ui" font-size="10">Powered by AI • SolShield AI.dev</text>
  <text x="200" y="470" text-anchor="middle" fill="#3F3F46" font-family="system-ui" font-size="8">This certificate is stored on the Solana blockchain</text>
</svg>
  `.trim();
}
