import type { Finding } from '../commands/audit.js';
import type { ParsedIdl } from '../parsers/idl.js';
import type { ParsedRust } from '../parsers/rust.js';

/**
 * SOL235: ELF Address Alignment Vulnerability
 * Detects patterns related to the Solana ELF address alignment vulnerability
 * Reference: Solana ELF Address Alignment Vulnerability (Core Protocol)
 */
export function checkElfAlignment(idl: ParsedIdl | null, rust: ParsedRust | null): Finding[] {
  const findings: Finding[] = [];

  if (rust) {
    for (const fn of rust.functions) {
      const content = fn.body;

      // Check for unsafe memory operations that could be affected by alignment
      if (content.includes('unsafe') && (content.includes('as *const') || content.includes('as *mut'))) {
        if (content.includes('read_unaligned') === false && content.includes('write_unaligned') === false) {
          findings.push({
            id: 'SOL235',
            severity: 'high',
            title: 'Potentially Unaligned Memory Access',
            description: 'Raw pointer cast detected without explicit alignment handling. On BPF, unaligned accesses can cause undefined behavior.',
            location: `Function: ${fn.name}`,
            recommendation: 'Use read_unaligned/write_unaligned for potentially unaligned data, or ensure proper alignment with #[repr(C, align(N))].',
          });
        }
      }

      // Check for borsh deserialization without alignment considerations
      if (content.includes('BorshDeserialize') || content.includes('try_from_slice')) {
        if (content.includes('&data[') && !content.includes('align')) {
          findings.push({
            id: 'SOL235',
            severity: 'medium',
            title: 'Deserialization Alignment Risk',
            description: 'Deserialization from byte slice without explicit alignment check. BPF programs require proper data alignment.',
            location: `Function: ${fn.name}`,
            recommendation: 'Ensure account data slices are properly aligned before deserialization. Consider using zero-copy with bytemuck.',
          });
        }
      }

      // Check for zero-copy patterns
      if (content.includes('zero_copy') || content.includes('bytemuck') || content.includes('Pod')) {
        if (!content.includes('repr(C)') && !content.includes('#[repr(C)]')) {
          findings.push({
            id: 'SOL235',
            severity: 'medium',
            title: 'Zero-Copy Without Repr(C)',
            description: 'Zero-copy type may lack #[repr(C)] annotation. Rust struct layout is not guaranteed without explicit representation.',
            location: `Function: ${fn.name}`,
            recommendation: 'Add #[repr(C)] or #[repr(packed)] to all zero-copy structs to ensure deterministic memory layout.',
          });
        }
      }

      // Check for transmute operations
      if (content.includes('transmute')) {
        findings.push({
          id: 'SOL235',
          severity: 'high',
          title: 'Unsafe Transmute Operation',
          description: 'std::mem::transmute can cause alignment violations and undefined behavior if source and target types have different alignment requirements.',
          location: `Function: ${fn.name}`,
          recommendation: 'Avoid transmute. Use safe alternatives like bytemuck::cast_slice or explicit serialization.',
        });
      }

      // Check for slice::from_raw_parts
      if (content.includes('from_raw_parts') || content.includes('slice::from_raw')) {
        findings.push({
          id: 'SOL235',
          severity: 'high',
          title: 'Raw Slice Construction',
          description: 'Creating slices from raw parts requires the pointer to be properly aligned for the element type.',
          location: `Function: ${fn.name}`,
          recommendation: 'Verify pointer alignment before constructing slices. Use align_to for safe alignment checking.',
        });
      }

      // Check for packed structs
      if (content.includes('#[repr(packed)]') || content.includes('repr(packed)')) {
        if (content.includes('&self.') || content.includes('& self.')) {
          findings.push({
            id: 'SOL235',
            severity: 'high',
            title: 'Reference to Packed Field',
            description: 'Taking references to fields in packed structs is undefined behavior as the field may be unaligned.',
            location: `Function: ${fn.name}`,
            recommendation: 'Copy packed fields to local variables before taking references. Use {field} instead of &self.field.',
          });
        }
      }
    }

    // Check struct definitions
    for (const struct of rust.structs) {
      const hasReprC = struct.attributes?.includes('repr(C)') || struct.attributes?.includes('repr(packed)');
      const hasZeroCopy = struct.attributes?.includes('zero_copy') || struct.attributes?.includes('Pod');
      
      if (hasZeroCopy && !hasReprC) {
        findings.push({
          id: 'SOL235',
          severity: 'medium',
          title: 'Zero-Copy Struct Missing Repr Attribute',
          description: `Struct ${struct.name} uses zero-copy but lacks explicit memory representation.`,
          location: `Struct: ${struct.name}`,
          recommendation: 'Add #[repr(C)] to ensure consistent memory layout across compilations.',
        });
      }
    }
  }

  return findings;
}
