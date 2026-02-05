import type { Finding } from '../commands/audit.js';
import type { ParsedIdl } from '../parsers/idl.js';
import type { ParsedRust } from '../parsers/rust.js';

/**
 * SOL396-SOL400: Solana Actions / Blinks Security
 * 
 * Blinks (blockchain links) allow executing transactions from URLs.
 * Security concerns: URL parameter injection, unsigned transactions,
 * missing validation on action providers.
 */
export function checkBlinkActions(input: { idl?: ParsedIdl; rust?: ParsedRust }): Finding[] {
  const findings: Finding[] = [];
  
  if (input.rust?.sourceCode) {
    const code = input.rust.sourceCode;
    
    // SOL396: Missing URL parameter sanitization
    if (/actions?\s*=\s*url\.search_params/i.test(code) && 
        !/sanitize|validate|escape/.test(code)) {
      findings.push({
        id: 'SOL396',
        severity: 'high',
        title: 'Missing URL Parameter Sanitization in Blink/Action',
        description: 'Action parameters from URL should be sanitized to prevent injection attacks.',
        location: 'Action handler',
        recommendation: 'Validate and sanitize all URL parameters before using in transaction building.',
      });
    }
    
    // SOL397: Unbounded action parameters
    if (/get_param|query_param/i.test(code) && 
        !/max_len|limit|bounds/.test(code)) {
      findings.push({
        id: 'SOL397',
        severity: 'medium',
        title: 'Unbounded Action Parameters',
        description: 'Action parameters should have length/value bounds to prevent abuse.',
        location: 'Action parameter handling',
        recommendation: 'Add maximum length and value bounds for all action parameters.',
      });
    }
    
    // SOL398: Missing action.json validation
    if (/actions?\.json/i.test(code) && 
        !/verify|validate|schema/.test(code)) {
      findings.push({
        id: 'SOL398',
        severity: 'medium',
        title: 'Missing actions.json Schema Validation',
        description: 'Action metadata should be validated against schema.',
        location: 'Action metadata',
        recommendation: 'Validate actions.json against the Solana Actions spec.',
      });
    }
    
    // SOL399: Transaction not requiring signature verification
    if (/create_transaction|build_tx/i.test(code) && 
        /blink|action/i.test(code) &&
        !/require_signature|verify_signature/.test(code)) {
      findings.push({
        id: 'SOL399',
        severity: 'high',
        title: 'Blink Transaction Missing Signature Requirement',
        description: 'Blink-built transactions should require proper signature verification.',
        location: 'Transaction building',
        recommendation: 'Ensure all blink transactions require appropriate signatures.',
      });
    }
    
    // SOL400: Missing CORS configuration for Actions
    if (/action|blink/i.test(code) && 
        /http|server|endpoint/i.test(code) &&
        !/cors|access-control|origin/.test(code)) {
      findings.push({
        id: 'SOL400',
        severity: 'medium',
        title: 'Missing CORS Configuration for Actions Endpoint',
        description: 'Action endpoints need proper CORS headers for browser compatibility.',
        location: 'HTTP endpoint',
        recommendation: 'Configure CORS headers as per Solana Actions specification.',
      });
    }
  }
  
  return findings;
}
