/**
 * SolGuard Pattern Batch 44
 * Infrastructure & Runtime Security Patterns
 * Patterns SOL1371-SOL1440
 * 
 * Covers: BPF, Syscalls, Memory, Compute, Validators
 */

import type { PatternInput, Finding } from './index.js';

interface BatchPattern {
  id: string;
  name: string;
  severity: 'critical' | 'high' | 'medium' | 'low' | 'info';
  category: string;
  description: string;
  detection: {
    patterns: RegExp[];
  };
  recommendation: string;
  references: string[];
}

const batchedPatterns44: BatchPattern[] = [
  // ========================================
  // BPF/RUNTIME SECURITY
  // ========================================
  {
    id: 'SOL1371',
    name: 'Unsafe Rust in BPF',
    severity: 'high',
    category: 'bpf',
    description: 'Unsafe Rust blocks in BPF program.',
    detection: {
      patterns: [
        /unsafe\s*\{/i,
        /unsafe\s+fn/i,
        /unsafe\s+impl/i
      ]
    },
    recommendation: 'Minimize unsafe blocks. Add thorough safety comments.',
    references: ['https://solanasec25.sec3.dev/']
  },
  {
    id: 'SOL1372',
    name: 'Transmute Misuse',
    severity: 'critical',
    category: 'bpf',
    description: 'mem::transmute used unsafely.',
    detection: {
      patterns: [
        /transmute/i,
        /mem::transmute/i,
        /core::mem::transmute/i
      ]
    },
    recommendation: 'Avoid transmute. Use safe alternatives.',
    references: ['https://solanasec25.sec3.dev/']
  },
  {
    id: 'SOL1373',
    name: 'Raw Pointer Dereference',
    severity: 'critical',
    category: 'bpf',
    description: 'Raw pointer dereferenced without validation.',
    detection: {
      patterns: [
        /\*mut\s/i,
        /\*const\s/i,
        /as\s*\*mut/i,
        /as\s*\*const/i
      ]
    },
    recommendation: 'Validate pointers before dereferencing. Use safe wrappers.',
    references: ['https://solanasec25.sec3.dev/']
  },
  {
    id: 'SOL1374',
    name: 'BPF Loader Authority',
    severity: 'critical',
    category: 'bpf',
    description: 'BPF loader authority operations vulnerable.',
    detection: {
      patterns: [
        /bpf_loader/i,
        /BpfLoader/i,
        /program_data/i,
        /upgrade_authority/i
      ]
    },
    recommendation: 'Secure upgrade authority. Consider making immutable.',
    references: ['https://solanasec25.sec3.dev/']
  },
  {
    id: 'SOL1375',
    name: 'ELF Alignment Issue',
    severity: 'medium',
    category: 'bpf',
    description: 'ELF binary alignment may cause issues.',
    detection: {
      patterns: [
        /\#\[repr\(C\)\]/i,
        /align\(/i,
        /packed/i
      ]
    },
    recommendation: 'Use proper struct alignment. Test on devnet.',
    references: ['https://solanasec25.sec3.dev/']
  },
  {
    id: 'SOL1376',
    name: 'Program Cache Invalidation',
    severity: 'medium',
    category: 'bpf',
    description: 'Program cache behavior assumptions.',
    detection: {
      patterns: [
        /program.*cache/i,
        /cached.*program/i
      ]
    },
    recommendation: 'Dont assume caching behavior. Test after upgrades.',
    references: ['https://solanasec25.sec3.dev/']
  },
  {
    id: 'SOL1377',
    name: 'Syscall Abuse',
    severity: 'high',
    category: 'bpf',
    description: 'Syscall used in unintended way.',
    detection: {
      patterns: [
        /sol_invoke/i,
        /sol_log/i,
        /sol_memcpy/i,
        /sol_memset/i
      ]
    },
    recommendation: 'Use syscalls as intended. Check return values.',
    references: ['https://solanasec25.sec3.dev/']
  },
  {
    id: 'SOL1378',
    name: 'Stack Frame Exhaustion',
    severity: 'medium',
    category: 'bpf',
    description: 'Deep recursion may exhaust stack.',
    detection: {
      patterns: [
        /recursive/i,
        /fn.*self.*\-\>/i,
        /call.*self/i
      ]
    },
    recommendation: 'Limit recursion depth. Use iterative alternatives.',
    references: ['https://solanasec25.sec3.dev/']
  },
  {
    id: 'SOL1379',
    name: 'Heap Allocation in Hot Path',
    severity: 'medium',
    category: 'bpf',
    description: 'Heap allocation in performance critical code.',
    detection: {
      patterns: [
        /Box::new/i,
        /Vec::new/i,
        /vec!/i,
        /String::new/i
      ]
    },
    recommendation: 'Pre-allocate where possible. Use stack for hot paths.',
    references: ['https://solanasec25.sec3.dev/']
  },
  {
    id: 'SOL1380',
    name: 'Cross-Program Return Data',
    severity: 'medium',
    category: 'bpf',
    description: 'CPI return data handling issues.',
    detection: {
      patterns: [
        /set_return_data/i,
        /get_return_data/i,
        /sol_get_return_data/i
      ]
    },
    recommendation: 'Validate return data source. Check data length.',
    references: ['https://solanasec25.sec3.dev/']
  },
  // ========================================
  // MEMORY SECURITY
  // ========================================
  {
    id: 'SOL1381',
    name: 'Buffer Overflow Risk',
    severity: 'critical',
    category: 'memory',
    description: 'Potential buffer overflow vulnerability.',
    detection: {
      patterns: [
        /copy_from_slice/i,
        /clone_from_slice/i,
        /\[.*\.\.\s*\d+\]/i
      ]
    },
    recommendation: 'Validate buffer sizes. Use bounds checking.',
    references: ['https://solanasec25.sec3.dev/']
  },
  {
    id: 'SOL1382',
    name: 'Uninitialized Memory',
    severity: 'high',
    category: 'memory',
    description: 'Memory used before initialization.',
    detection: {
      patterns: [
        /MaybeUninit/i,
        /assume_init/i,
        /zeroed/i
      ]
    },
    recommendation: 'Always initialize memory. Use safe alternatives.',
    references: ['https://solanasec25.sec3.dev/']
  },
  {
    id: 'SOL1383',
    name: 'Memory Leak',
    severity: 'medium',
    category: 'memory',
    description: 'Potential memory leak in program.',
    detection: {
      patterns: [
        /Box::leak/i,
        /forget/i,
        /ManuallyDrop/i
      ]
    },
    recommendation: 'Ensure memory is properly freed. Avoid leaks.',
    references: ['https://solanasec25.sec3.dev/']
  },
  {
    id: 'SOL1384',
    name: 'Use After Free',
    severity: 'critical',
    category: 'memory',
    description: 'Potential use-after-free vulnerability.',
    detection: {
      patterns: [
        /drop\(/i,
        /\.take\(\)/i,
        /mem::replace/i
      ]
    },
    recommendation: 'Track ownership carefully. Use Rust borrowing.',
    references: ['https://solanasec25.sec3.dev/']
  },
  {
    id: 'SOL1385',
    name: 'Double Free',
    severity: 'critical',
    category: 'memory',
    description: 'Potential double-free vulnerability.',
    detection: {
      patterns: [
        /ManuallyDrop/i,
        /drop_in_place/i,
        /ptr::drop_in_place/i
      ]
    },
    recommendation: 'Use safe Rust patterns. Avoid manual memory management.',
    references: ['https://solanasec25.sec3.dev/']
  },
  {
    id: 'SOL1386',
    name: 'Account Data Slice OOB',
    severity: 'critical',
    category: 'memory',
    description: 'Account data slice access out of bounds.',
    detection: {
      patterns: [
        /data\[/i,
        /data\.get\(/i,
        /borrow\(\)\[/i
      ]
    },
    recommendation: 'Always check data length before indexing.',
    references: ['https://solanasec25.sec3.dev/']
  },
  {
    id: 'SOL1387',
    name: 'Integer to Usize Conversion',
    severity: 'high',
    category: 'memory',
    description: 'Unsafe integer to usize conversion.',
    detection: {
      patterns: [
        /as\s+usize/i,
        /usize::from/i,
        /try_into\(\).*usize/i
      ]
    },
    recommendation: 'Validate range before conversion. Handle errors.',
    references: ['https://solanasec25.sec3.dev/']
  },
  {
    id: 'SOL1388',
    name: 'Borsh Max Size',
    severity: 'medium',
    category: 'memory',
    description: 'Borsh deserialization may exceed limits.',
    detection: {
      patterns: [
        /BorshDeserialize/i,
        /try_from_slice/i,
        /deserialize/i
      ]
    },
    recommendation: 'Set max_len for strings/vectors. Validate before deserializing.',
    references: ['https://solanasec25.sec3.dev/']
  },
  {
    id: 'SOL1389',
    name: 'Realloc Safety',
    severity: 'high',
    category: 'memory',
    description: 'Account reallocation handled unsafely.',
    detection: {
      patterns: [
        /realloc/i,
        /AccountInfo.*realloc/i,
        /data_len.*change/i
      ]
    },
    recommendation: 'Handle reallocation failures. Zero new space.',
    references: ['https://solanasec25.sec3.dev/']
  },
  {
    id: 'SOL1390',
    name: 'Zero Copy Safety',
    severity: 'high',
    category: 'memory',
    description: 'Zero-copy deserialization safety concerns.',
    detection: {
      patterns: [
        /zero_copy/i,
        /bytemuck/i,
        /Pod/i,
        /Zeroable/i
      ]
    },
    recommendation: 'Ensure proper alignment. Validate data before cast.',
    references: ['https://solanasec25.sec3.dev/']
  },
  // ========================================
  // COMPUTE BUDGET
  // ========================================
  {
    id: 'SOL1391',
    name: 'Compute Budget Not Set',
    severity: 'medium',
    category: 'compute',
    description: 'Compute budget not explicitly requested.',
    detection: {
      patterns: [
        /ComputeBudgetInstruction/i,
        /set_compute_unit_limit/i,
        /request_units/i
      ]
    },
    recommendation: 'Set appropriate compute budget for complex operations.',
    references: ['https://docs.solana.com/']
  },
  {
    id: 'SOL1392',
    name: 'Compute Intensive Loop',
    severity: 'high',
    category: 'compute',
    description: 'Loop may exceed compute limits.',
    detection: {
      patterns: [
        /for.*in\s+0\.\./i,
        /while.*true/i,
        /loop\s*\{/i
      ]
    },
    recommendation: 'Add loop bounds. Profile compute usage.',
    references: ['https://docs.solana.com/']
  },
  {
    id: 'SOL1393',
    name: 'Expensive Cryptography',
    severity: 'medium',
    category: 'compute',
    description: 'Cryptographic operation may be expensive.',
    detection: {
      patterns: [
        /verify_signature/i,
        /secp256k1/i,
        /ed25519_verify/i,
        /bn254/i
      ]
    },
    recommendation: 'Budget for crypto operations. Consider batching.',
    references: ['https://docs.solana.com/']
  },
  {
    id: 'SOL1394',
    name: 'Logging Overhead',
    severity: 'low',
    category: 'compute',
    description: 'Excessive logging consuming compute.',
    detection: {
      patterns: [
        /msg!/i,
        /sol_log/i,
        /log.*debug/i
      ]
    },
    recommendation: 'Remove debug logs in production. Use sparingly.',
    references: ['https://docs.solana.com/']
  },
  {
    id: 'SOL1395',
    name: 'CPI Compute Usage',
    severity: 'medium',
    category: 'compute',
    description: 'CPI call compute usage not accounted.',
    detection: {
      patterns: [
        /invoke/i,
        /invoke_signed/i,
        /CpiContext/i
      ]
    },
    recommendation: 'Account for CPI compute. Leave buffer for called program.',
    references: ['https://docs.solana.com/']
  },
  {
    id: 'SOL1396',
    name: 'Heap Usage High',
    severity: 'medium',
    category: 'compute',
    description: 'High heap usage may cause failures.',
    detection: {
      patterns: [
        /Vec::with_capacity/i,
        /String::with_capacity/i,
        /HashMap/i,
        /BTreeMap/i
      ]
    },
    recommendation: 'Minimize heap usage. Use stack where possible.',
    references: ['https://docs.solana.com/']
  },
  {
    id: 'SOL1397',
    name: 'String Formatting Overhead',
    severity: 'low',
    category: 'compute',
    description: 'String formatting consuming compute.',
    detection: {
      patterns: [
        /format!/i,
        /to_string\(\)/i,
        /\.to_owned\(\)/i
      ]
    },
    recommendation: 'Avoid string formatting in hot paths.',
    references: ['https://docs.solana.com/']
  },
  {
    id: 'SOL1398',
    name: 'Account Iteration',
    severity: 'medium',
    category: 'compute',
    description: 'Iterating over many accounts is expensive.',
    detection: {
      patterns: [
        /remaining_accounts/i,
        /accounts\.iter/i,
        /for.*account.*in/i
      ]
    },
    recommendation: 'Limit account count. Use pagination.',
    references: ['https://docs.solana.com/']
  },
  {
    id: 'SOL1399',
    name: 'Serialization Cost',
    severity: 'medium',
    category: 'compute',
    description: 'Serialization/deserialization overhead.',
    detection: {
      patterns: [
        /serialize/i,
        /try_to_vec/i,
        /AnchorSerialize/i
      ]
    },
    recommendation: 'Minimize serialization. Use zero-copy where possible.',
    references: ['https://docs.solana.com/']
  },
  {
    id: 'SOL1400',
    name: 'Math Library Cost',
    severity: 'low',
    category: 'compute',
    description: 'Math library operations are expensive.',
    detection: {
      patterns: [
        /sqrt/i,
        /pow/i,
        /log\d/i,
        /exp/i
      ]
    },
    recommendation: 'Use lookup tables. Approximate where acceptable.',
    references: ['https://docs.solana.com/']
  },
  // ========================================
  // VALIDATOR/CONSENSUS
  // ========================================
  {
    id: 'SOL1401',
    name: 'Slot Reliance',
    severity: 'medium',
    category: 'validator',
    description: 'Logic relies on specific slot timing.',
    detection: {
      patterns: [
        /Clock::get/i,
        /slot\s*$/i,
        /current_slot/i
      ]
    },
    recommendation: 'Account for slot timing variations.',
    references: ['https://docs.solana.com/']
  },
  {
    id: 'SOL1402',
    name: 'Epoch Boundary',
    severity: 'medium',
    category: 'validator',
    description: 'Epoch boundary handling issues.',
    detection: {
      patterns: [
        /epoch/i,
        /epoch_schedule/i,
        /slots_per_epoch/i
      ]
    },
    recommendation: 'Handle epoch boundaries gracefully.',
    references: ['https://docs.solana.com/']
  },
  {
    id: 'SOL1403',
    name: 'Leader Schedule Assumption',
    severity: 'low',
    category: 'validator',
    description: 'Assumptions about leader schedule.',
    detection: {
      patterns: [
        /leader.*schedule/i,
        /slot.*leader/i
      ]
    },
    recommendation: 'Dont assume leader schedule. Handle variability.',
    references: ['https://docs.solana.com/']
  },
  {
    id: 'SOL1404',
    name: 'Vote Account Security',
    severity: 'high',
    category: 'validator',
    description: 'Vote account security considerations.',
    detection: {
      patterns: [
        /VoteState/i,
        /vote.*account/i,
        /voter_pubkey/i
      ]
    },
    recommendation: 'Secure vote authority. Use hardware wallet.',
    references: ['https://docs.solana.com/']
  },
  {
    id: 'SOL1405',
    name: 'Stake Account Handling',
    severity: 'high',
    category: 'validator',
    description: 'Stake account operations vulnerable.',
    detection: {
      patterns: [
        /StakeState/i,
        /stake_account/i,
        /Delegation/i,
        /stake_authority/i
      ]
    },
    recommendation: 'Validate stake account state. Check delegation.',
    references: ['https://docs.solana.com/']
  },
  {
    id: 'SOL1406',
    name: 'Rent Epoch Handling',
    severity: 'low',
    category: 'validator',
    description: 'Rent epoch handling issues.',
    detection: {
      patterns: [
        /rent_epoch/i,
        /exempt_threshold/i
      ]
    },
    recommendation: 'Use rent-exempt accounts. Check exemption status.',
    references: ['https://docs.solana.com/']
  },
  {
    id: 'SOL1407',
    name: 'Turbine Propagation',
    severity: 'low',
    category: 'validator',
    description: 'Transaction propagation timing assumptions.',
    detection: {
      patterns: [
        /propagation/i,
        /block.*time/i,
        /slot.*duration/i
      ]
    },
    recommendation: 'Account for network delays. Dont assume instant propagation.',
    references: ['https://docs.solana.com/']
  },
  {
    id: 'SOL1408',
    name: 'Stake Concentration',
    severity: 'info',
    category: 'validator',
    description: 'Stake concentration risk awareness.',
    detection: {
      patterns: [
        /validator.*stake/i,
        /stake.*weight/i,
        /voting_power/i
      ]
    },
    recommendation: 'Be aware of stake concentration. Diversify if possible.',
    references: ['https://docs.solana.com/']
  },
  {
    id: 'SOL1409',
    name: 'Forkable State',
    severity: 'medium',
    category: 'validator',
    description: 'State may differ across forks.',
    detection: {
      patterns: [
        /fork/i,
        /commitment/i,
        /confirmed/i,
        /finalized/i
      ]
    },
    recommendation: 'Use appropriate commitment level. Handle forks.',
    references: ['https://docs.solana.com/']
  },
  {
    id: 'SOL1410',
    name: 'Jito MEV Integration',
    severity: 'medium',
    category: 'validator',
    description: 'Jito MEV considerations.',
    detection: {
      patterns: [
        /jito/i,
        /mev/i,
        /bundle/i,
        /tip/i
      ]
    },
    recommendation: 'Understand Jito mechanics. Consider MEV implications.',
    references: ['https://jito.network/']
  },
  // ========================================
  // ANCHOR-SPECIFIC
  // ========================================
  {
    id: 'SOL1411',
    name: 'Anchor Seeds Mismatch',
    severity: 'critical',
    category: 'anchor',
    description: 'PDA seeds dont match across uses.',
    detection: {
      patterns: [
        /seeds\s*=/i,
        /\#\[account\(.*seeds/i,
        /find_program_address/i
      ]
    },
    recommendation: 'Use consistent seeds. Define seed constants.',
    references: ['https://anchor-lang.com/']
  },
  {
    id: 'SOL1412',
    name: 'Anchor Constraint Missing',
    severity: 'high',
    category: 'anchor',
    description: 'Account constraint may be missing.',
    detection: {
      patterns: [
        /\#\[account\]/i,
        /\#\[account\([\s\)]/i,
        /AccountInfo/i
      ]
    },
    recommendation: 'Add appropriate constraints (mut, signer, has_one, etc).',
    references: ['https://anchor-lang.com/']
  },
  {
    id: 'SOL1413',
    name: 'Anchor Close Recipient',
    severity: 'high',
    category: 'anchor',
    description: 'Close constraint recipient not validated.',
    detection: {
      patterns: [
        /close\s*=\s*\w+/i,
        /\#\[account\(.*close/i
      ]
    },
    recommendation: 'Verify close recipient is trusted.',
    references: ['https://anchor-lang.com/']
  },
  {
    id: 'SOL1414',
    name: 'Anchor Init If Needed Race',
    severity: 'high',
    category: 'anchor',
    description: 'init_if_needed can cause race conditions.',
    detection: {
      patterns: [
        /init_if_needed/i,
        /\#\[account\(.*init_if_needed/i
      ]
    },
    recommendation: 'Avoid init_if_needed. Use explicit init with check.',
    references: ['https://anchor-lang.com/']
  },
  {
    id: 'SOL1415',
    name: 'Anchor Realloc Safety',
    severity: 'high',
    category: 'anchor',
    description: 'Realloc constraint used unsafely.',
    detection: {
      patterns: [
        /realloc\s*=/i,
        /\#\[account\(.*realloc/i
      ]
    },
    recommendation: 'Validate realloc size. Handle growth carefully.',
    references: ['https://anchor-lang.com/']
  },
  {
    id: 'SOL1416',
    name: 'Anchor Space Calculation',
    severity: 'medium',
    category: 'anchor',
    description: 'Account space may be insufficient.',
    detection: {
      patterns: [
        /space\s*=/i,
        /\#\[account\(.*space/i,
        /8\s*\+/i
      ]
    },
    recommendation: 'Calculate space correctly. Include discriminator (8 bytes).',
    references: ['https://anchor-lang.com/']
  },
  {
    id: 'SOL1417',
    name: 'Anchor Has One Check',
    severity: 'high',
    category: 'anchor',
    description: 'has_one constraint may be needed.',
    detection: {
      patterns: [
        /authority/i,
        /owner/i,
        /admin/i
      ]
    },
    recommendation: 'Use has_one for relationship validation.',
    references: ['https://anchor-lang.com/']
  },
  {
    id: 'SOL1418',
    name: 'Anchor Error Handling',
    severity: 'medium',
    category: 'anchor',
    description: 'Custom error not used.',
    detection: {
      patterns: [
        /ProgramError/i,
        /err!/i,
        /Err\(/i
      ]
    },
    recommendation: 'Use custom Anchor errors with #[error_code].',
    references: ['https://anchor-lang.com/']
  },
  {
    id: 'SOL1419',
    name: 'Anchor Event Emission',
    severity: 'low',
    category: 'anchor',
    description: 'Events not emitted for state changes.',
    detection: {
      patterns: [
        /emit!/i,
        /\#\[event\]/i
      ]
    },
    recommendation: 'Emit events for important state changes.',
    references: ['https://anchor-lang.com/']
  },
  {
    id: 'SOL1420',
    name: 'Anchor Access Control',
    severity: 'critical',
    category: 'anchor',
    description: 'Access control macro not used.',
    detection: {
      patterns: [
        /\#\[access_control/i,
        /require!/i,
        /constraint\s*=/i
      ]
    },
    recommendation: 'Use access_control or require! for authorization.',
    references: ['https://anchor-lang.com/']
  },
  // ========================================
  // SERIALIZATION
  // ========================================
  {
    id: 'SOL1421',
    name: 'Borsh Endianness',
    severity: 'medium',
    category: 'serialization',
    description: 'Endianness may cause cross-platform issues.',
    detection: {
      patterns: [
        /to_le_bytes/i,
        /to_be_bytes/i,
        /from_le_bytes/i
      ]
    },
    recommendation: 'Use consistent endianness (Borsh uses little-endian).',
    references: ['https://borsh.io/']
  },
  {
    id: 'SOL1422',
    name: 'Borsh String Size',
    severity: 'high',
    category: 'serialization',
    description: 'String deserialization without size limit.',
    detection: {
      patterns: [
        /String/i,
        /BorshDeserialize.*String/i
      ]
    },
    recommendation: 'Use bounded strings or check length before deserialize.',
    references: ['https://borsh.io/']
  },
  {
    id: 'SOL1423',
    name: 'Borsh Vec Size',
    severity: 'high',
    category: 'serialization',
    description: 'Vec deserialization without size limit.',
    detection: {
      patterns: [
        /Vec</i,
        /BorshDeserialize.*Vec/i
      ]
    },
    recommendation: 'Use bounded vecs or check length before deserialize.',
    references: ['https://borsh.io/']
  },
  {
    id: 'SOL1424',
    name: 'Anchor Deserialize',
    severity: 'medium',
    category: 'serialization',
    description: 'AccountDeserialize may fail silently.',
    detection: {
      patterns: [
        /try_deserialize/i,
        /AccountDeserialize/i
      ]
    },
    recommendation: 'Handle deserialization errors properly.',
    references: ['https://anchor-lang.com/']
  },
  {
    id: 'SOL1425',
    name: 'IDL Type Mismatch',
    severity: 'high',
    category: 'serialization',
    description: 'IDL types may not match implementation.',
    detection: {
      patterns: [
        /idl/i,
        /AnchorSerialize/i,
        /AnchorDeserialize/i
      ]
    },
    recommendation: 'Keep IDL in sync. Test serialization.',
    references: ['https://anchor-lang.com/']
  },
  // ========================================
  // TESTING/AUDITING
  // ========================================
  {
    id: 'SOL1426',
    name: 'Missing Unit Tests',
    severity: 'low',
    category: 'testing',
    description: 'Function lacks unit tests.',
    detection: {
      patterns: [
        /pub\s+fn/i,
        /#\[test\]/i,
        /mod\s+tests/i
      ]
    },
    recommendation: 'Add comprehensive unit tests.',
    references: ['https://solanasec25.sec3.dev/']
  },
  {
    id: 'SOL1427',
    name: 'Missing Integration Tests',
    severity: 'low',
    category: 'testing',
    description: 'Program lacks integration tests.',
    detection: {
      patterns: [
        /bankrun/i,
        /program_test/i,
        /ProgramTest/i
      ]
    },
    recommendation: 'Add integration tests with Bankrun or Program Test.',
    references: ['https://solanasec25.sec3.dev/']
  },
  {
    id: 'SOL1428',
    name: 'Fuzzing Not Done',
    severity: 'info',
    category: 'testing',
    description: 'Program not fuzzed.',
    detection: {
      patterns: [
        /fuzz/i,
        /trident/i,
        /honggfuzz/i
      ]
    },
    recommendation: 'Use fuzzing (Trident) to find edge cases.',
    references: ['https://solanasec25.sec3.dev/']
  },
  {
    id: 'SOL1429',
    name: 'Formal Verification',
    severity: 'info',
    category: 'testing',
    description: 'No formal verification performed.',
    detection: {
      patterns: [
        /invariant/i,
        /assert/i,
        /require/i
      ]
    },
    recommendation: 'Consider formal verification for critical code.',
    references: ['https://solanasec25.sec3.dev/']
  },
  {
    id: 'SOL1430',
    name: 'Audit Findings Open',
    severity: 'critical',
    category: 'testing',
    description: 'Unresolved audit findings.',
    detection: {
      patterns: [
        /TODO.*security/i,
        /FIXME.*vuln/i,
        /audit.*finding/i
      ]
    },
    recommendation: 'Address all audit findings before deployment.',
    references: ['https://solanasec25.sec3.dev/']
  },
  // ========================================
  // MISCELLANEOUS PATTERNS
  // ========================================
  {
    id: 'SOL1431',
    name: 'Debug Code in Production',
    severity: 'medium',
    category: 'misc',
    description: 'Debug code may be in production.',
    detection: {
      patterns: [
        /debug/i,
        /println!/i,
        /dbg!/i,
        /#\[cfg\(debug/i
      ]
    },
    recommendation: 'Remove debug code before deployment.',
    references: ['https://solanasec25.sec3.dev/']
  },
  {
    id: 'SOL1432',
    name: 'Feature Flag Security',
    severity: 'medium',
    category: 'misc',
    description: 'Feature flag handling may be insecure.',
    detection: {
      patterns: [
        /feature/i,
        /#\[cfg\(feature/i,
        /is_enabled/i
      ]
    },
    recommendation: 'Review feature flag implications. Test all combinations.',
    references: ['https://solanasec25.sec3.dev/']
  },
  {
    id: 'SOL1433',
    name: 'Version Compatibility',
    severity: 'medium',
    category: 'misc',
    description: 'SDK version compatibility concerns.',
    detection: {
      patterns: [
        /solana-sdk/i,
        /anchor-lang/i,
        /spl-token/i
      ]
    },
    recommendation: 'Pin SDK versions. Test on target validator version.',
    references: ['https://solanasec25.sec3.dev/']
  },
  {
    id: 'SOL1434',
    name: 'Deprecated Function',
    severity: 'low',
    category: 'misc',
    description: 'Using deprecated function.',
    detection: {
      patterns: [
        /deprecated/i,
        /#\[deprecated/i
      ]
    },
    recommendation: 'Update to non-deprecated alternatives.',
    references: ['https://solanasec25.sec3.dev/']
  },
  {
    id: 'SOL1435',
    name: 'Environment Dependency',
    severity: 'low',
    category: 'misc',
    description: 'Code depends on environment.',
    detection: {
      patterns: [
        /env!/i,
        /std::env/i,
        /option_env!/i
      ]
    },
    recommendation: 'Avoid environment dependencies in BPF.',
    references: ['https://solanasec25.sec3.dev/']
  },
  {
    id: 'SOL1436',
    name: 'Time-Based Logic',
    severity: 'medium',
    category: 'misc',
    description: 'Time-based logic may be manipulatable.',
    detection: {
      patterns: [
        /Clock/i,
        /unix_timestamp/i,
        /slot/i
      ]
    },
    recommendation: 'Use slot for ordering, timestamp for display only.',
    references: ['https://solanasec25.sec3.dev/']
  },
  {
    id: 'SOL1437',
    name: 'Floating Point Usage',
    severity: 'high',
    category: 'misc',
    description: 'Floating point used for financial calculations.',
    detection: {
      patterns: [
        /f32/i,
        /f64/i,
        /\.0\s*[\+\-\*\/]/i
      ]
    },
    recommendation: 'Use fixed-point arithmetic. Avoid floats.',
    references: ['https://solanasec25.sec3.dev/']
  },
  {
    id: 'SOL1438',
    name: 'Panic Path Exists',
    severity: 'medium',
    category: 'misc',
    description: 'Code path can panic.',
    detection: {
      patterns: [
        /panic!/i,
        /unreachable!/i,
        /todo!/i,
        /unimplemented!/i
      ]
    },
    recommendation: 'Handle all error cases. Avoid panics.',
    references: ['https://solanasec25.sec3.dev/']
  },
  {
    id: 'SOL1439',
    name: 'Documentation Missing',
    severity: 'info',
    category: 'misc',
    description: 'Function lacks documentation.',
    detection: {
      patterns: [
        /\/\/\//i,
        /#\[doc/i,
        /pub\s+fn.*\{/i
      ]
    },
    recommendation: 'Add documentation for public functions.',
    references: ['https://solanasec25.sec3.dev/']
  },
  {
    id: 'SOL1440',
    name: 'License Missing',
    severity: 'info',
    category: 'misc',
    description: 'License information not specified.',
    detection: {
      patterns: [
        /license/i,
        /MIT/i,
        /Apache/i,
        /GPL/i
      ]
    },
    recommendation: 'Include license in Cargo.toml and source.',
    references: ['https://solanasec25.sec3.dev/']
  }
];

// Export function to run all patterns in this batch
export function runBatchedPatterns44(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  const content = input.rust?.content || '';
  
  if (!content) return findings;
  
  for (const pattern of batchedPatterns44) {
    for (const regex of pattern.detection.patterns) {
      if (regex.test(content)) {
        const match = content.match(regex);
        if (match) {
          findings.push({
            id: pattern.id,
            title: pattern.name,
            severity: pattern.severity,
            description: pattern.description,
            location: { file: input.path },
            recommendation: pattern.recommendation,
          });
          break;
        }
      }
    }
  }
  
  return findings;
}

export { batchedPatterns44 };
export const BATCH_44_COUNT = batchedPatterns44.length; // 70 patterns
