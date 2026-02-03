'use client';

import { useState } from 'react';
import Link from 'next/link';

export default function Home() {
  const [code, setCode] = useState('');
  const [isLoading, setIsLoading] = useState(false);
  const [result, setResult] = useState<any>(null);

  const handleAudit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!code.trim()) return;
    
    setIsLoading(true);
    setResult(null);
    
    try {
      const res = await fetch('/api/audit', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ code }),
      });
      const data = await res.json();
      setResult(data);
    } catch (err) {
      setResult({ error: 'Failed to run audit' });
    } finally {
      setIsLoading(false);
    }
  };

  return (
    <div className="min-h-screen bg-gradient-to-b from-zinc-900 to-black text-white">
      {/* Header */}
      <header className="border-b border-zinc-800">
        <div className="max-w-6xl mx-auto px-4 py-4 flex items-center justify-between">
          <div className="flex items-center gap-2">
            <span className="text-2xl">🛡️</span>
            <span className="text-xl font-bold">SolGuard</span>
          </div>
          <nav className="flex items-center gap-6">
            <Link href="#features" className="text-zinc-400 hover:text-white transition">Features</Link>
            <Link href="/patterns" className="text-zinc-400 hover:text-white transition">Patterns</Link>
            <Link href="#audit" className="text-zinc-400 hover:text-white transition">Try It</Link>
            <Link href="/api" className="text-zinc-400 hover:text-white transition">API</Link>
            <a 
              href="https://github.com/oh-ashen-one/solguard" 
              target="_blank" 
              rel="noopener noreferrer"
              className="text-zinc-400 hover:text-white transition"
            >
              GitHub
            </a>
          </nav>
        </div>
      </header>

      {/* Hero */}
      <section className="max-w-6xl mx-auto px-4 pt-20 pb-16 text-center">
        <div className="inline-flex items-center gap-2 bg-emerald-500/10 border border-emerald-500/20 rounded-full px-4 py-1.5 mb-6">
          <span className="w-2 h-2 bg-emerald-500 rounded-full animate-pulse"></span>
          <span className="text-emerald-400 text-sm font-medium">Solana Agent Hackathon 2026</span>
        </div>
        
        <h1 className="text-5xl md:text-6xl font-bold tracking-tight mb-6">
          AI-Powered Security
          <br />
          <span className="text-transparent bg-clip-text bg-gradient-to-r from-emerald-400 to-cyan-400">
            for Solana Smart Contracts
          </span>
        </h1>
        
        <p className="text-xl text-zinc-400 max-w-2xl mx-auto mb-10">
          Detect vulnerabilities in your Anchor programs instantly. 
          Get AI-powered explanations and fix suggestions. 
          Ship secure code faster.
        </p>
        
        <div className="flex flex-col sm:flex-row items-center justify-center gap-4">
          <a 
            href="#audit"
            className="w-full sm:w-auto px-8 py-3 bg-emerald-500 hover:bg-emerald-600 text-black font-semibold rounded-lg transition"
          >
            Try Free Audit
          </a>
          <a 
            href="https://github.com/oh-ashen-one/solguard" 
            target="_blank"
            rel="noopener noreferrer"
            className="w-full sm:w-auto px-8 py-3 border border-zinc-700 hover:border-zinc-500 rounded-lg transition"
          >
            View on GitHub
          </a>
        </div>
      </section>

      {/* Stats */}
      <section className="max-w-6xl mx-auto px-4 py-12">
        <div className="grid grid-cols-2 md:grid-cols-4 gap-8">
          <div className="text-center">
            <div className="text-4xl font-bold text-emerald-400">120</div>
            <div className="text-zinc-500">Vuln Patterns</div>
          </div>
          <div className="text-center">
            <div className="text-4xl font-bold text-emerald-400">7</div>
            <div className="text-zinc-500">CLI Commands</div>
          </div>
          <div className="text-center">
            <div className="text-4xl font-bold text-emerald-400">$0</div>
            <div className="text-zinc-500">Price (Beta)</div>
          </div>
          <div className="text-center">
            <div className="text-4xl font-bold text-emerald-400">100%</div>
            <div className="text-zinc-500">Agent-Coded</div>
          </div>
        </div>
      </section>
      
      {/* CLI Preview */}
      <section className="max-w-6xl mx-auto px-4 py-12">
        <h2 className="text-3xl font-bold text-center mb-8">Powerful CLI</h2>
        <div className="bg-zinc-900 border border-zinc-700 rounded-xl overflow-hidden">
          <div className="flex items-center gap-2 px-4 py-3 bg-zinc-800 border-b border-zinc-700">
            <div className="w-3 h-3 rounded-full bg-red-500"></div>
            <div className="w-3 h-3 rounded-full bg-yellow-500"></div>
            <div className="w-3 h-3 rounded-full bg-green-500"></div>
            <span className="ml-2 text-zinc-500 text-sm">Terminal</span>
          </div>
          <pre className="p-6 text-sm text-zinc-300 overflow-x-auto">
{`$ npm install -g @solguard/cli

$ solguard audit ./my-program
🛡️ SolGuard - Scanning...
Found 3 critical, 5 high severity issues

$ solguard github coral-xyz/anchor --pr 1234
Cloning... Analyzing 47 files... Done!

$ solguard ci . --fail-on high --sarif results.sarif
✅ CI mode: SARIF generated for GitHub Code Scanning

$ solguard watch ./program
👀 Watching for changes... (Ctrl+C to stop)`}
          </pre>
        </div>
      </section>

      {/* Features */}
      <section id="features" className="max-w-6xl mx-auto px-4 py-16">
        <h2 className="text-3xl font-bold text-center mb-12">What We Detect</h2>
        
        <div className="grid md:grid-cols-3 gap-6">
          {[
            { icon: '🔐', title: 'Missing Signer Checks', desc: 'Authority accounts without cryptographic verification', severity: 'Critical' },
            { icon: '👤', title: 'Owner Validation', desc: 'Accounts without proper ownership constraints', severity: 'Critical' },
            { icon: '🔢', title: 'Integer Overflow', desc: 'Unchecked arithmetic that can wrap around', severity: 'High' },
            { icon: '🔑', title: 'Authority Bypass', desc: 'Sensitive operations without permission checks', severity: 'Critical' },
            { icon: '🏠', title: 'PDA Validation', desc: 'Program Derived Addresses without bump verification', severity: 'High' },
            { icon: '⚡', title: 'Initialization', desc: 'Accounts used without initialization verification', severity: 'Critical' },
            { icon: '🔗', title: 'CPI Vulnerabilities', desc: 'Cross-program invocation without verification', severity: 'High' },
            { icon: '📊', title: 'Rounding Errors', desc: 'Precision loss in financial calculations', severity: 'Medium' },
            { icon: '🔄', title: 'Account Confusion', desc: 'Swappable accounts of the same type', severity: 'High' },
            { icon: '🚪', title: 'Closing Issues', desc: 'Account revival attacks and rent theft', severity: 'Critical' },
            { icon: '♻️', title: 'Reentrancy', desc: 'State changes after cross-program calls', severity: 'High' },
            { icon: '🎯', title: 'Arbitrary CPI', desc: 'Unconstrained program ID in invoke calls', severity: 'Critical' },
            { icon: '👯', title: 'Duplicate Accounts', desc: 'Same account passed as multiple parameters', severity: 'High' },
            { icon: '🏠', title: 'Rent Exemption', desc: 'Accounts that may be garbage collected', severity: 'Medium' },
            { icon: '🎭', title: 'Type Cosplay', desc: 'Missing discriminator validation', severity: 'Critical' },
          ].map((feature, i) => (
            <div key={i} className="p-6 bg-zinc-800/50 border border-zinc-700 rounded-xl hover:border-zinc-600 transition">
              <div className="text-3xl mb-4">{feature.icon}</div>
              <h3 className="text-lg font-semibold mb-2">{feature.title}</h3>
              <p className="text-zinc-400 text-sm mb-3">{feature.desc}</p>
              <span className={`text-xs px-2 py-1 rounded ${
                feature.severity === 'Critical' ? 'bg-red-500/20 text-red-400' : 'bg-orange-500/20 text-orange-400'
              }`}>
                {feature.severity}
              </span>
            </div>
          ))}
        </div>
      </section>

      {/* Audit Form */}
      <section id="audit" className="max-w-4xl mx-auto px-4 py-16">
        <h2 className="text-3xl font-bold text-center mb-4">Try It Now</h2>
        <p className="text-zinc-400 text-center mb-8">Paste your Rust/Anchor code below for instant security analysis</p>
        
        <form onSubmit={handleAudit} className="space-y-4">
          <textarea
            value={code}
            onChange={(e) => setCode(e.target.value)}
            placeholder={`// Paste your Anchor program code here...
use anchor_lang::prelude::*;

#[program]
pub mod my_program {
    // ...
}`}
            className="w-full h-64 p-4 bg-zinc-900 border border-zinc-700 rounded-lg font-mono text-sm focus:outline-none focus:border-emerald-500 resize-none"
          />
          
          <button
            type="submit"
            disabled={isLoading || !code.trim()}
            className="w-full py-3 bg-emerald-500 hover:bg-emerald-600 disabled:bg-zinc-700 disabled:cursor-not-allowed text-black font-semibold rounded-lg transition flex items-center justify-center gap-2"
          >
            {isLoading ? (
              <>
                <svg className="animate-spin h-5 w-5" viewBox="0 0 24 24">
                  <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4" fill="none" />
                  <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z" />
                </svg>
                Analyzing...
              </>
            ) : (
              <>🔍 Run Security Audit</>
            )}
          </button>
        </form>

        {/* Results */}
        {result && (
          <div className="mt-8 p-6 bg-zinc-900 border border-zinc-700 rounded-lg">
            {result.error ? (
              <div className="text-red-400">{result.error}</div>
            ) : (
              <>
                <div className="flex items-center justify-between mb-6">
                  <h3 className="text-xl font-semibold">Audit Results</h3>
                  <span className={`px-3 py-1 rounded-full text-sm font-medium ${
                    result.passed ? 'bg-emerald-500/20 text-emerald-400' : 'bg-red-500/20 text-red-400'
                  }`}>
                    {result.passed ? '✅ Passed' : '❌ Issues Found'}
                  </span>
                </div>
                
                {/* Summary */}
                <div className="grid grid-cols-5 gap-4 mb-6">
                  {[
                    { label: 'Critical', count: result.summary?.critical || 0, color: 'text-red-500' },
                    { label: 'High', count: result.summary?.high || 0, color: 'text-orange-500' },
                    { label: 'Medium', count: result.summary?.medium || 0, color: 'text-yellow-500' },
                    { label: 'Low', count: result.summary?.low || 0, color: 'text-blue-500' },
                    { label: 'Info', count: result.summary?.info || 0, color: 'text-zinc-500' },
                  ].map((s, i) => (
                    <div key={i} className="text-center">
                      <div className={`text-2xl font-bold ${s.color}`}>{s.count}</div>
                      <div className="text-zinc-500 text-xs">{s.label}</div>
                    </div>
                  ))}
                </div>
                
                {/* Findings */}
                {result.findings?.length > 0 && (
                  <div className="space-y-4">
                    {result.findings.map((finding: any, i: number) => (
                      <div key={i} className="p-4 bg-zinc-800 rounded-lg border-l-4 border-red-500">
                        <div className="flex items-start justify-between">
                          <div>
                            <span className={`text-xs px-2 py-0.5 rounded mr-2 ${
                              finding.severity === 'critical' ? 'bg-red-500/20 text-red-400' :
                              finding.severity === 'high' ? 'bg-orange-500/20 text-orange-400' :
                              'bg-yellow-500/20 text-yellow-400'
                            }`}>
                              {finding.severity?.toUpperCase()}
                            </span>
                            <span className="font-mono text-sm text-zinc-500">[{finding.id}]</span>
                          </div>
                          {finding.location?.line && (
                            <span className="text-zinc-500 text-sm">Line {finding.location.line}</span>
                          )}
                        </div>
                        <h4 className="font-semibold mt-2">{finding.title}</h4>
                        <p className="text-zinc-400 text-sm mt-1">{finding.description}</p>
                        {finding.suggestion && (
                          <div className="mt-3 p-3 bg-emerald-500/10 border border-emerald-500/20 rounded text-sm">
                            <span className="text-emerald-400 font-medium">💡 Fix: </span>
                            <span className="text-zinc-300">{finding.suggestion.split('\n')[0]}</span>
                          </div>
                        )}
                      </div>
                    ))}
                  </div>
                )}
              </>
            )}
          </div>
        )}
      </section>

      {/* Footer */}
      <footer className="border-t border-zinc-800 mt-16">
        <div className="max-w-6xl mx-auto px-4 py-8 text-center text-zinc-500 text-sm">
          <p>Built by <span className="text-emerald-400">Midir</span> for the Solana x OpenClaw Agent Hackathon 2026</p>
          <p className="mt-2">Open source • MIT License • Powered by Claude AI</p>
        </div>
      </footer>
    </div>
  );
}
