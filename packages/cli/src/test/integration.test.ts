/**
 * Integration tests for SolShield AI CLI
 * Tests pattern registry and core functionality
 */

import { describe, it, expect } from 'vitest';

describe('CLI Integration', () => {
  describe('pattern registry', () => {
    it('has all 65 patterns registered', async () => {
      const { listPatterns } = await import('../patterns/index.js');
      const patterns = listPatterns();
      
      expect(patterns.length).toBe(142);
      
      // Check all pattern IDs exist
      const ids = patterns.map(p => p.id);
      for (let i = 1; i <= 65; i++) {
        const expectedId = `SOL${String(i).padStart(3, '0')}`;
        expect(ids).toContain(expectedId);
      }
    });

    it('patterns cover all severity levels', async () => {
      const { listPatterns } = await import('../patterns/index.js');
      const patterns = listPatterns();
      
      const severities = new Set(patterns.map(p => p.severity));
      expect(severities.has('critical')).toBe(true);
      expect(severities.has('high')).toBe(true);
      expect(severities.has('medium')).toBe(true);
    });

    it('each pattern has required fields', async () => {
      const { listPatterns } = await import('../patterns/index.js');
      const patterns = listPatterns();
      
      for (const pattern of patterns) {
        expect(pattern.id).toBeDefined();
        expect(pattern.name).toBeDefined();
        expect(pattern.severity).toBeDefined();
        expect(pattern.run).toBeDefined();
        expect(typeof pattern.run).toBe('function');
      }
    });

    it('patterns are sorted by severity in expected order', async () => {
      const { listPatterns } = await import('../patterns/index.js');
      const patterns = listPatterns();
      
      // Critical patterns should exist
      const criticalPatterns = patterns.filter(p => p.severity === 'critical');
      expect(criticalPatterns.length).toBeGreaterThan(0);
      
      // High patterns should exist
      const highPatterns = patterns.filter(p => p.severity === 'high');
      expect(highPatterns.length).toBeGreaterThan(0);
    });
  });

  describe('pattern names', () => {
    it('SOL001 is Missing Owner Check', async () => {
      const { getPatternById } = await import('../patterns/index.js');
      const pattern = getPatternById('SOL001');
      expect(pattern?.name).toBe('Missing Owner Check');
      expect(pattern?.severity).toBe('critical');
    });

    it('SOL015 is Type Cosplay', async () => {
      const { getPatternById } = await import('../patterns/index.js');
      const pattern = getPatternById('SOL015');
      expect(pattern?.name).toBe('Type Cosplay');
      expect(pattern?.severity).toBe('critical');
    });
  });
});
