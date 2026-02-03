import { describe, it, expect } from 'vitest';
import { runPatterns } from '../patterns/index.js';
import { parseRustFiles } from '../parsers/rust.js';
import { join } from 'path';

const examplesDir = join(__dirname, '..', '..', '..', '..', 'examples');

describe('Vulnerability Patterns', () => {
  describe('Safe Programs', () => {
    it('passes safe counter with no findings', async () => {
      const safeFile = join(examplesDir, 'safe', 'counter', 'src', 'lib.rs');
      const rust = await parseRustFiles([safeFile]);
      const findings = await runPatterns({ idl: null, rust, path: safeFile });
      
      // Safe programs should have no critical/high findings
      const criticalOrHigh = findings.filter(f => 
        f.severity === 'critical' || f.severity === 'high'
      );
      expect(criticalOrHigh.length).toBe(0);
    });
  });

  describe('Vulnerable Programs', () => {
    it('detects issues in vulnerable token vault', async () => {
      const vulnFile = join(examplesDir, 'vulnerable', 'token-vault', 'src', 'lib.rs');
      const rust = await parseRustFiles([vulnFile]);
      const findings = await runPatterns({ idl: null, rust, path: vulnFile });
      
      // Should find multiple issues
      expect(findings.length).toBeGreaterThan(5);
      
      // Should include critical findings
      const critical = findings.filter(f => f.severity === 'critical');
      expect(critical.length).toBeGreaterThan(0);
      
      // Should detect signer issues
      const signerIssues = findings.filter(f => f.id.startsWith('SOL002'));
      expect(signerIssues.length).toBeGreaterThan(0);
      
      // Should detect overflow issues
      const overflowIssues = findings.filter(f => f.id.startsWith('SOL003'));
      expect(overflowIssues.length).toBeGreaterThan(0);
    });

    it('detects DeFi vulnerabilities', async () => {
      const defiFile = join(examplesDir, 'vulnerable', 'defi-vault', 'src', 'lib.rs');
      const rust = await parseRustFiles([defiFile]);
      const findings = await runPatterns({ idl: null, rust, path: defiFile });
      
      // Should find many issues in the DeFi vault
      expect(findings.length).toBeGreaterThan(15);
      
      // Should detect CPI issues
      const cpiIssues = findings.filter(f => f.id.startsWith('SOL007'));
      expect(cpiIssues.length).toBeGreaterThan(0);
      
      // Should detect rounding issues
      const roundingIssues = findings.filter(f => f.id.startsWith('SOL008'));
      expect(roundingIssues.length).toBeGreaterThan(0);
      
      // Should detect account confusion
      const confusionIssues = findings.filter(f => f.id.startsWith('SOL009'));
      expect(confusionIssues.length).toBeGreaterThan(0);
    });
  });

  describe('Pattern Coverage', () => {
    it('has 45 registered patterns', async () => {
      const { listPatterns } = await import('../patterns/index.js');
      const patterns = listPatterns();
      expect(patterns.length).toBe(45);
    });

    it('patterns have required fields', async () => {
      const { listPatterns } = await import('../patterns/index.js');
      const patterns = listPatterns();
      
      for (const pattern of patterns) {
        expect(pattern.id).toBeDefined();
        expect(pattern.name).toBeDefined();
        expect(pattern.severity).toMatch(/^(critical|high|medium|low|info)$/);
        expect(typeof pattern.run).toBe('function');
      }
    });
  });
});
