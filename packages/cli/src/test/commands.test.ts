/**
 * Command tests
 * Tests CLI command functionality
 */

import { describe, it, expect } from 'vitest';

describe('CLI Commands', () => {
  describe('config', () => {
    it('generateExampleConfig returns valid JSON', async () => {
      const { generateExampleConfig } = await import('../config.js');
      const config = generateExampleConfig();
      
      expect(() => JSON.parse(config)).not.toThrow();
      
      const parsed = JSON.parse(config);
      expect(parsed).toHaveProperty('disable');
      expect(parsed).toHaveProperty('minSeverity');
      expect(parsed).toHaveProperty('ignore');
      expect(parsed).toHaveProperty('rules');
      expect(parsed).toHaveProperty('output');
      expect(parsed).toHaveProperty('ci');
    });

    it('config has correct default values', async () => {
      const { generateExampleConfig } = await import('../config.js');
      const config = JSON.parse(generateExampleConfig());
      
      expect(config.minSeverity).toBe('low');
      expect(config.output.format).toBe('terminal');
      expect(config.output.colors).toBe(true);
      expect(config.ci.failOn).toBe('high');
    });
  });

  describe('diff', () => {
    it('diffAudits correctly identifies added findings', async () => {
      const { diffAudits } = await import('../commands/diff.js');
      
      const oldFindings = [
        { pattern: 'SOL001', title: 'Test', severity: 'high' as const, description: '', location: 'test.rs:1' },
      ];
      
      const newFindings = [
        { pattern: 'SOL001', title: 'Test', severity: 'high' as const, description: '', location: 'test.rs:1' },
        { pattern: 'SOL002', title: 'New', severity: 'critical' as const, description: '', location: 'test.rs:5' },
      ];
      
      const diff = diffAudits(oldFindings as any, newFindings as any);
      
      expect(diff.added.length).toBe(1);
      expect(diff.added[0].pattern).toBe('SOL002');
      expect(diff.removed.length).toBe(0);
      expect(diff.unchanged.length).toBe(1);
    });

    it('diffAudits correctly identifies removed findings', async () => {
      const { diffAudits } = await import('../commands/diff.js');
      
      const oldFindings = [
        { pattern: 'SOL001', title: 'Test', severity: 'high' as const, description: '', location: 'test.rs:1' },
        { pattern: 'SOL002', title: 'Fixed', severity: 'critical' as const, description: '', location: 'test.rs:5' },
      ];
      
      const newFindings = [
        { pattern: 'SOL001', title: 'Test', severity: 'high' as const, description: '', location: 'test.rs:1' },
      ];
      
      const diff = diffAudits(oldFindings as any, newFindings as any);
      
      expect(diff.added.length).toBe(0);
      expect(diff.removed.length).toBe(1);
      expect(diff.removed[0].pattern).toBe('SOL002');
      expect(diff.summary.improved).toBe(true);
    });

    it('diffAudits marks as improved when critical removed', async () => {
      const { diffAudits } = await import('../commands/diff.js');
      
      const oldFindings = [
        { pattern: 'SOL001', title: 'Critical', severity: 'critical' as const, description: '', location: 'test.rs:1' },
      ];
      
      const newFindings = [
        { pattern: 'SOL002', title: 'Low', severity: 'low' as const, description: '', location: 'test.rs:5' },
      ];
      
      const diff = diffAudits(oldFindings as any, newFindings as any);
      
      // Removing critical (100 weight) vs adding low (2 weight) = improved
      expect(diff.summary.improved).toBe(true);
    });
  });

  describe('report', () => {
    it('generateHtmlReport returns valid HTML', async () => {
      const { generateHtmlReport } = await import('../commands/report.js');
      
      const html = generateHtmlReport({
        programName: 'test-program',
        programPath: '/test',
        timestamp: new Date().toISOString(),
        findings: [],
        summary: { critical: 0, high: 0, medium: 0, low: 0, info: 0, total: 0 },
        passed: true,
        duration: 100,
      });
      
      expect(html).toContain('<!DOCTYPE html>');
      expect(html).toContain('SolShield AI');
      expect(html).toContain('test-program');
      expect(html).toContain('AUDIT PASSED');
    });

    it('generateHtmlReport shows findings', async () => {
      const { generateHtmlReport } = await import('../commands/report.js');
      
      const html = generateHtmlReport({
        programName: 'vuln-program',
        programPath: '/test',
        timestamp: new Date().toISOString(),
        findings: [
          { pattern: 'SOL001', title: 'Missing Owner', severity: 'critical' as const, description: 'Bad!', location: 'lib.rs:10' },
        ],
        summary: { critical: 1, high: 0, medium: 0, low: 0, info: 0, total: 1 },
        passed: false,
        duration: 50,
      });
      
      expect(html).toContain('ISSUES FOUND');
      expect(html).toContain('SOL001');
      expect(html).toContain('Missing Owner');
      expect(html).toContain('critical');
    });
  });

  describe('list', () => {
    it('list patterns are available', async () => {
      const { listPatterns } = await import('../patterns/index.js');
      const patterns = listPatterns();
      
      // Should have descriptions for key patterns
      expect(patterns.find(p => p.id === 'SOL001')).toBeDefined();
      expect(patterns.find(p => p.id === 'SOL002')).toBeDefined();
      expect(patterns.find(p => p.id === 'SOL015')).toBeDefined();
    });
  });
});
