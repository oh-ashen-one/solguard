'use client';

import { useState, useMemo } from 'react';
import Link from 'next/link';

const patterns = [
  // Core Security
  { id: 'SOL001', name: 'Missing Owner Check', severity: 'critical', category: 'Core Security' },
  { id: 'SOL002', name: 'Missing Signer Check', severity: 'critical', category: 'Core Security' },
  { id: 'SOL003', name: 'Integer Overflow', severity: 'high', category: 'Core Security' },
  { id: 'SOL004', name: 'PDA Validation Gap', severity: 'high', category: 'Core Security' },
  { id: 'SOL005', name: 'Authority Bypass', severity: 'critical', category: 'Core Security' },
  { id: 'SOL006', name: 'Missing Init Check', severity: 'critical', category: 'Core Security' },
  { id: 'SOL007', name: 'CPI Vulnerability', severity: 'high', category: 'CPI Security' },
  { id: 'SOL008', name: 'Rounding Error', severity: 'medium', category: 'Math' },
  { id: 'SOL009', name: 'Account Confusion', severity: 'high', category: 'Account Safety' },
  { id: 'SOL010', name: 'Closing Vulnerability', severity: 'critical', category: 'Account Safety' },
  
  // Extended patterns
  { id: 'SOL011', name: 'Cross-Program Reentrancy', severity: 'high', category: 'CPI Security' },
  { id: 'SOL012', name: 'Arbitrary CPI', severity: 'critical', category: 'CPI Security' },
  { id: 'SOL013', name: 'Duplicate Mutable', severity: 'high', category: 'Account Safety' },
  { id: 'SOL014', name: 'Missing Rent Check', severity: 'medium', category: 'Account Safety' },
  { id: 'SOL015', name: 'Type Cosplay', severity: 'critical', category: 'Account Safety' },
  { id: 'SOL016', name: 'Bump Seed', severity: 'high', category: 'PDA Security' },
  { id: 'SOL017', name: 'Freeze Authority', severity: 'medium', category: 'Token Security' },
  { id: 'SOL018', name: 'Oracle Manipulation', severity: 'high', category: 'DeFi' },
  { id: 'SOL019', name: 'Flash Loan', severity: 'critical', category: 'DeFi' },
  { id: 'SOL020', name: 'Unsafe Math', severity: 'high', category: 'Math' },
  
  // More patterns (21-40)
  { id: 'SOL021', name: 'Sysvar Manipulation', severity: 'critical', category: 'Core Security' },
  { id: 'SOL022', name: 'Upgrade Authority', severity: 'medium', category: 'Program Safety' },
  { id: 'SOL023', name: 'Token Validation', severity: 'high', category: 'Token Security' },
  { id: 'SOL024', name: 'Cross-Program State', severity: 'high', category: 'CPI Security' },
  { id: 'SOL025', name: 'Lamport Balance', severity: 'high', category: 'Account Safety' },
  { id: 'SOL026', name: 'Seeded Account', severity: 'medium', category: 'PDA Security' },
  { id: 'SOL027', name: 'Error Handling', severity: 'medium', category: 'Code Quality' },
  { id: 'SOL028', name: 'Event Emission', severity: 'low', category: 'Code Quality' },
  { id: 'SOL029', name: 'Instruction Introspection', severity: 'high', category: 'Core Security' },
  { id: 'SOL030', name: 'Anchor Macros', severity: 'medium', category: 'Anchor' },
  { id: 'SOL031', name: 'Access Control', severity: 'critical', category: 'Core Security' },
  { id: 'SOL032', name: 'Time Lock', severity: 'medium', category: 'Operations' },
  { id: 'SOL033', name: 'Signature Replay', severity: 'critical', category: 'Core Security' },
  { id: 'SOL034', name: 'Storage Collision', severity: 'high', category: 'Account Safety' },
  { id: 'SOL035', name: 'Denial of Service', severity: 'high', category: 'Operations' },
  { id: 'SOL036', name: 'Input Validation', severity: 'medium', category: 'Code Quality' },
  { id: 'SOL037', name: 'State Initialization', severity: 'medium', category: 'Account Safety' },
  { id: 'SOL038', name: 'Token-2022', severity: 'medium', category: 'Token Security' },
  { id: 'SOL039', name: 'Memo Logging', severity: 'medium', category: 'Code Quality' },
  { id: 'SOL040', name: 'CPI Guard', severity: 'high', category: 'CPI Security' },
  
  // DeFi patterns (41-60)
  { id: 'SOL041', name: 'Governance', severity: 'critical', category: 'DeFi' },
  { id: 'SOL042', name: 'NFT Security', severity: 'high', category: 'NFT' },
  { id: 'SOL043', name: 'Staking', severity: 'high', category: 'DeFi' },
  { id: 'SOL044', name: 'AMM/DEX', severity: 'critical', category: 'DeFi' },
  { id: 'SOL045', name: 'Lending Protocol', severity: 'critical', category: 'DeFi' },
  { id: 'SOL046', name: 'Bridge', severity: 'critical', category: 'DeFi' },
  { id: 'SOL047', name: 'Vault', severity: 'high', category: 'DeFi' },
  { id: 'SOL048', name: 'Merkle', severity: 'critical', category: 'Crypto' },
  { id: 'SOL049', name: 'Compression', severity: 'medium', category: 'Advanced' },
  { id: 'SOL050', name: 'Program-Derived Signing', severity: 'high', category: 'PDA Security' },
  { id: 'SOL051', name: 'Account Size', severity: 'medium', category: 'Account Safety' },
  { id: 'SOL052', name: 'Clock Dependency', severity: 'medium', category: 'Operations' },
  { id: 'SOL053', name: 'Account Order', severity: 'medium', category: 'Account Safety' },
  { id: 'SOL054', name: 'Serialization', severity: 'medium', category: 'Code Quality' },
  { id: 'SOL055', name: 'Program ID', severity: 'critical', category: 'Core Security' },
  { id: 'SOL056', name: 'Authority Transfer', severity: 'medium', category: 'Operations' },
  { id: 'SOL057', name: 'Fee Handling', severity: 'high', category: 'DeFi' },
  { id: 'SOL058', name: 'Pause Mechanism', severity: 'medium', category: 'Operations' },
  { id: 'SOL059', name: 'Withdrawal Pattern', severity: 'critical', category: 'DeFi' },
  { id: 'SOL060', name: 'Init Frontrunning', severity: 'critical', category: 'Core Security' },
  
  // Advanced patterns (61-80)
  { id: 'SOL061', name: 'Data Validation', severity: 'high', category: 'Code Quality' },
  { id: 'SOL062', name: 'Compute Budget', severity: 'high', category: 'Operations' },
  { id: 'SOL063', name: 'Privilege Escalation', severity: 'critical', category: 'Core Security' },
  { id: 'SOL064', name: 'Sandwich Attack', severity: 'high', category: 'DeFi' },
  { id: 'SOL065', name: 'Supply Manipulation', severity: 'high', category: 'Token Security' },
  { id: 'SOL066', name: 'Account Borrowing', severity: 'high', category: 'Account Safety' },
  { id: 'SOL067', name: 'Remaining Accounts', severity: 'critical', category: 'Anchor' },
  { id: 'SOL068', name: 'Constraint Validation', severity: 'high', category: 'Anchor' },
  { id: 'SOL069', name: 'Rent Drain', severity: 'high', category: 'Account Safety' },
  { id: 'SOL070', name: 'PDA Collision', severity: 'high', category: 'PDA Security' },
  { id: 'SOL071', name: 'Metaplex Security', severity: 'high', category: 'NFT' },
  { id: 'SOL072', name: 'ATA Security', severity: 'high', category: 'Token Security' },
  { id: 'SOL073', name: 'System Program Abuse', severity: 'critical', category: 'Core Security' },
  { id: 'SOL074', name: 'Wrapped SOL', severity: 'high', category: 'Token Security' },
  { id: 'SOL075', name: 'Account Revival', severity: 'critical', category: 'Account Safety' },
  { id: 'SOL076', name: 'Cross-Instance', severity: 'medium', category: 'Program Safety' },
  { id: 'SOL077', name: 'Program Data Authority', severity: 'critical', category: 'Program Safety' },
  { id: 'SOL078', name: 'Mint Authority', severity: 'critical', category: 'Token Security' },
  { id: 'SOL079', name: 'Discriminator', severity: 'critical', category: 'Account Safety' },
  { id: 'SOL080', name: 'Timestamp Manipulation', severity: 'high', category: 'Operations' },
  
  // More advanced (81-100)
  { id: 'SOL081', name: 'Anchor Account Init', severity: 'medium', category: 'Anchor' },
  { id: 'SOL082', name: 'Token Ownership', severity: 'critical', category: 'Token Security' },
  { id: 'SOL083', name: 'PDA Signer Seeds', severity: 'critical', category: 'PDA Security' },
  { id: 'SOL084', name: 'Constraint Order', severity: 'medium', category: 'Anchor' },
  { id: 'SOL085', name: 'CPI Return Data', severity: 'high', category: 'CPI Security' },
  { id: 'SOL086', name: 'Account Lifetime', severity: 'medium', category: 'Account Safety' },
  { id: 'SOL087', name: 'Arithmetic Precision', severity: 'high', category: 'Math' },
  { id: 'SOL088', name: 'Event Ordering', severity: 'medium', category: 'Code Quality' },
  { id: 'SOL089', name: 'Account Type Safety', severity: 'high', category: 'Account Safety' },
  { id: 'SOL090', name: 'Syscall Security', severity: 'medium', category: 'Core Security' },
  { id: 'SOL091', name: 'SPL Governance', severity: 'high', category: 'DeFi' },
  { id: 'SOL092', name: 'Token Extensions', severity: 'high', category: 'Token Security' },
  { id: 'SOL093', name: 'Lookup Table', severity: 'high', category: 'Advanced' },
  { id: 'SOL094', name: 'Priority Fee', severity: 'medium', category: 'Operations' },
  { id: 'SOL095', name: 'Slot Manipulation', severity: 'high', category: 'Operations' },
  { id: 'SOL096', name: 'Cross-Chain', severity: 'critical', category: 'DeFi' },
  { id: 'SOL097', name: 'Multisig', severity: 'critical', category: 'DeFi' },
  { id: 'SOL098', name: 'Versioning', severity: 'medium', category: 'Operations' },
  { id: 'SOL099', name: 'Atomic Operations', severity: 'high', category: 'Operations' },
  { id: 'SOL100', name: 'Init Order', severity: 'high', category: 'Account Safety' },
  
  // Latest patterns (101-142)
  { id: 'SOL101', name: 'Program Cache', severity: 'low', category: 'Performance' },
  { id: 'SOL102', name: 'Instruction Data', severity: 'high', category: 'Code Quality' },
  { id: 'SOL103', name: 'Anchor CPI Safety', severity: 'high', category: 'Anchor' },
  { id: 'SOL104', name: 'Authority Scope', severity: 'medium', category: 'Core Security' },
  { id: 'SOL105', name: 'Error Propagation', severity: 'medium', category: 'Code Quality' },
  { id: 'SOL106', name: 'Key Derivation', severity: 'high', category: 'Account Safety' },
  { id: 'SOL107', name: 'Token Burn', severity: 'critical', category: 'Token Security' },
  { id: 'SOL108', name: 'Associated Program', severity: 'high', category: 'Token Security' },
  { id: 'SOL109', name: 'Signer Seeds', severity: 'high', category: 'PDA Security' },
  { id: 'SOL110', name: 'Account Reallocation', severity: 'high', category: 'Account Safety' },
  { id: 'SOL111', name: 'Discriminator Check', severity: 'critical', category: 'Account Safety' },
  { id: 'SOL112', name: 'Token Approval', severity: 'high', category: 'Token Security' },
  { id: 'SOL113', name: 'Rent Collection', severity: 'high', category: 'Account Safety' },
  { id: 'SOL114', name: 'Instruction Sysvar', severity: 'medium', category: 'Core Security' },
  { id: 'SOL115', name: 'State Transition', severity: 'high', category: 'Operations' },
  { id: 'SOL116', name: 'Data Matching', severity: 'high', category: 'Code Quality' },
  { id: 'SOL117', name: 'Token Freeze', severity: 'critical', category: 'Token Security' },
  { id: 'SOL118', name: 'Zero-Copy', severity: 'high', category: 'Anchor' },
  { id: 'SOL119', name: 'Program Upgrade', severity: 'critical', category: 'Program Safety' },
  { id: 'SOL120', name: 'Constraint Combos', severity: 'high', category: 'Anchor' },
  { id: 'SOL121', name: 'CPI Depth', severity: 'medium', category: 'CPI Security' },
  { id: 'SOL122', name: 'Close Destination', severity: 'high', category: 'Account Safety' },
  { id: 'SOL123', name: 'Token Account Close', severity: 'high', category: 'Token Security' },
  { id: 'SOL124', name: 'Account Data Init', severity: 'high', category: 'Account Safety' },
  { id: 'SOL125', name: 'Program Signer', severity: 'medium', category: 'PDA Security' },
  { id: 'SOL126', name: 'Lamports Overflow', severity: 'high', category: 'Math' },
  { id: 'SOL127', name: 'Instruction Size', severity: 'medium', category: 'Operations' },
  { id: 'SOL128', name: 'Seed Length', severity: 'medium', category: 'PDA Security' },
  { id: 'SOL129', name: 'Token Decimals', severity: 'high', category: 'Token Security' },
  { id: 'SOL142', name: 'Bump Storage', severity: 'high', category: 'PDA Security' },
];

const severityColors: Record<string, string> = {
  critical: 'bg-red-500/20 text-red-400 border-red-500/30',
  high: 'bg-orange-500/20 text-orange-400 border-orange-500/30',
  medium: 'bg-yellow-500/20 text-yellow-400 border-yellow-500/30',
  low: 'bg-blue-500/20 text-blue-400 border-blue-500/30',
};

const severityBgColors: Record<string, string> = {
  critical: 'bg-red-500/10 border-red-500/20 hover:bg-red-500/20',
  high: 'bg-orange-500/10 border-orange-500/20 hover:bg-orange-500/20',
  medium: 'bg-yellow-500/10 border-yellow-500/20 hover:bg-yellow-500/20',
  low: 'bg-blue-500/10 border-blue-500/20 hover:bg-blue-500/20',
};

const categories = [...new Set(patterns.map(p => p.category))].sort();
const severities = ['critical', 'high', 'medium', 'low'];

export default function PatternsPage() {
  const [search, setSearch] = useState('');
  const [selectedSeverity, setSelectedSeverity] = useState<string | null>(null);
  const [selectedCategory, setSelectedCategory] = useState<string | null>(null);

  const filteredPatterns = useMemo(() => {
    return patterns.filter(p => {
      const matchesSearch = search === '' || 
        p.name.toLowerCase().includes(search.toLowerCase()) ||
        p.id.toLowerCase().includes(search.toLowerCase()) ||
        p.category.toLowerCase().includes(search.toLowerCase());
      const matchesSeverity = !selectedSeverity || p.severity === selectedSeverity;
      const matchesCategory = !selectedCategory || p.category === selectedCategory;
      return matchesSearch && matchesSeverity && matchesCategory;
    });
  }, [search, selectedSeverity, selectedCategory]);

  const clearFilters = () => {
    setSearch('');
    setSelectedSeverity(null);
    setSelectedCategory(null);
  };

  const hasFilters = search || selectedSeverity || selectedCategory;

  return (
    <div className="min-h-screen bg-gradient-to-b from-zinc-900 to-black text-white">
      <header className="border-b border-zinc-800">
        <div className="max-w-6xl mx-auto px-4 py-4 flex items-center justify-between">
          <Link href="/" className="flex items-center gap-2">
            <span className="text-2xl">🛡️</span>
            <span className="text-xl font-bold">SolShield AI</span>
          </Link>
          <nav className="flex items-center gap-6">
            <Link href="/" className="text-zinc-400 hover:text-white">Home</Link>
            <Link href="/patterns" className="text-white font-medium">Patterns</Link>
            <Link href="/api" className="text-zinc-400 hover:text-white">API</Link>
          </nav>
        </div>
      </header>

      <main className="max-w-6xl mx-auto px-4 py-12">
        <h1 className="text-4xl font-bold mb-2">Vulnerability Patterns</h1>
        <p className="text-zinc-400 mb-8">
          142 security patterns covering Solana smart contract vulnerabilities
        </p>

        {/* Search & Filters */}
        <div className="mb-8 space-y-4">
          {/* Search Input */}
          <div className="relative">
            <input
              type="text"
              placeholder="Search patterns by name, ID, or category..."
              value={search}
              onChange={(e) => setSearch(e.target.value)}
              className="w-full px-4 py-3 pl-10 bg-zinc-800 border border-zinc-700 rounded-lg text-white placeholder-zinc-500 focus:outline-none focus:border-emerald-500 transition"
            />
            <svg className="absolute left-3 top-3.5 w-5 h-5 text-zinc-500" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M21 21l-6-6m2-5a7 7 0 11-14 0 7 7 0 0114 0z" />
            </svg>
          </div>

          {/* Severity Filters */}
          <div className="flex flex-wrap items-center gap-2">
            <span className="text-sm text-zinc-500 mr-2">Severity:</span>
            {severities.map(sev => (
              <button
                key={sev}
                onClick={() => setSelectedSeverity(selectedSeverity === sev ? null : sev)}
                className={`px-3 py-1.5 rounded-lg text-sm font-medium border transition ${
                  selectedSeverity === sev 
                    ? severityColors[sev] + ' border-current' 
                    : 'border-zinc-700 text-zinc-400 hover:border-zinc-500'
                }`}
              >
                {sev.charAt(0).toUpperCase() + sev.slice(1)}
                <span className="ml-1 opacity-60">
                  ({patterns.filter(p => p.severity === sev).length})
                </span>
              </button>
            ))}
          </div>

          {/* Category Filters */}
          <div className="flex flex-wrap items-center gap-2">
            <span className="text-sm text-zinc-500 mr-2">Category:</span>
            <select
              value={selectedCategory || ''}
              onChange={(e) => setSelectedCategory(e.target.value || null)}
              className="px-3 py-1.5 bg-zinc-800 border border-zinc-700 rounded-lg text-sm text-zinc-300 focus:outline-none focus:border-emerald-500"
            >
              <option value="">All Categories</option>
              {categories.map(cat => (
                <option key={cat} value={cat}>
                  {cat} ({patterns.filter(p => p.category === cat).length})
                </option>
              ))}
            </select>
            
            {hasFilters && (
              <button
                onClick={clearFilters}
                className="px-3 py-1.5 text-sm text-zinc-400 hover:text-white transition"
              >
                Clear filters ×
              </button>
            )}
          </div>
        </div>

        {/* Results Count */}
        {hasFilters && (
          <p className="text-sm text-zinc-500 mb-4">
            Showing {filteredPatterns.length} of {patterns.length} patterns
          </p>
        )}

        {/* Stats */}
        <div className="grid grid-cols-4 gap-4 mb-8">
          {severities.map(sev => {
            const count = (hasFilters ? filteredPatterns : patterns).filter(p => p.severity === sev).length;
            return (
              <button
                key={sev}
                onClick={() => setSelectedSeverity(selectedSeverity === sev ? null : sev)}
                className={`border rounded-lg p-4 text-center transition ${severityBgColors[sev]} ${
                  selectedSeverity === sev ? 'ring-2 ring-offset-2 ring-offset-zinc-900' : ''
                }`}
                style={{ ['--tw-ring-color' as any]: sev === 'critical' ? 'rgb(239 68 68 / 0.5)' : sev === 'high' ? 'rgb(249 115 22 / 0.5)' : sev === 'medium' ? 'rgb(234 179 8 / 0.5)' : 'rgb(59 142 246 / 0.5)' }}
              >
                <div className={`text-2xl font-bold ${
                  sev === 'critical' ? 'text-red-400' : 
                  sev === 'high' ? 'text-orange-400' : 
                  sev === 'medium' ? 'text-yellow-400' : 'text-blue-400'
                }`}>
                  {count}
                </div>
                <div className="text-sm text-zinc-400 capitalize">{sev}</div>
              </button>
            );
          })}
        </div>

        {/* Pattern Grid */}
        {filteredPatterns.length > 0 ? (
          <div className="grid md:grid-cols-2 lg:grid-cols-3 gap-3">
            {filteredPatterns.map(pattern => (
              <div 
                key={pattern.id}
                className="bg-zinc-800/50 border border-zinc-700 rounded-lg p-4 hover:border-zinc-600 transition cursor-pointer"
                onClick={() => {
                  if (selectedCategory !== pattern.category) {
                    setSelectedCategory(pattern.category);
                  }
                }}
              >
                <div className="flex items-center justify-between mb-2">
                  <span className="font-mono text-emerald-400">{pattern.id}</span>
                  <span className={`px-2 py-0.5 rounded text-xs border ${severityColors[pattern.severity]}`}>
                    {pattern.severity}
                  </span>
                </div>
                <div className="font-medium">{pattern.name}</div>
                <div className="text-xs text-zinc-500 mt-1">{pattern.category}</div>
              </div>
            ))}
          </div>
        ) : (
          <div className="text-center py-12">
            <div className="text-4xl mb-4">🔍</div>
            <p className="text-zinc-400">No patterns match your filters</p>
            <button
              onClick={clearFilters}
              className="mt-4 px-4 py-2 bg-emerald-500 hover:bg-emerald-600 text-black rounded-lg font-medium transition"
            >
              Clear filters
            </button>
          </div>
        )}
      </main>

      <footer className="border-t border-zinc-800 py-8 text-center text-zinc-500">
        <p>Built by Midir 🐉 for the Solana Agent Hackathon 2026</p>
      </footer>
    </div>
  );
}
