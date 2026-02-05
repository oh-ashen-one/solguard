/**
 * Audit Command Types
 */

export interface Finding {
  id: string;
  title: string;
  severity: 'critical' | 'high' | 'medium' | 'low' | 'info';
  description: string;
  location: { file: string; line?: number };
  recommendation?: string;
  code?: string;
}

export interface AuditOptions {
  format?: 'text' | 'json' | 'markdown';
  failOn?: 'critical' | 'high' | 'medium' | 'low' | 'any';
  ai?: boolean;
}

export interface AuditResult {
  path: string;
  timestamp: string;
  duration: number;
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
}
