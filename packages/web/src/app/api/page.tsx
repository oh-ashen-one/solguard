import Link from 'next/link';

export default function ApiDocs() {
  return (
    <div className="min-h-screen bg-gradient-to-b from-zinc-900 to-black text-white">
      {/* Header */}
      <header className="border-b border-zinc-800">
        <div className="max-w-6xl mx-auto px-4 py-4 flex items-center justify-between">
          <Link href="/" className="flex items-center gap-2">
            <span className="text-2xl">🛡️</span>
            <span className="text-xl font-bold">SolGuard</span>
          </Link>
          <nav className="flex items-center gap-6">
            <Link href="/" className="text-zinc-400 hover:text-white transition">Home</Link>
            <Link href="/patterns" className="text-zinc-400 hover:text-white transition">Patterns</Link>
            <Link href="/api" className="text-white font-medium">API</Link>
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

      <main className="max-w-4xl mx-auto px-4 py-12">
        <h1 className="text-4xl font-bold mb-2">API Documentation</h1>
        <p className="text-zinc-400 mb-8">Public REST API for AI agents and developers to audit Solana smart contracts</p>

        {/* Quick Stats */}
        <div className="grid grid-cols-3 gap-4 mb-8">
          <div className="bg-emerald-500/10 border border-emerald-500/20 rounded-lg p-4 text-center">
            <div className="text-2xl font-bold text-emerald-400">130</div>
            <div className="text-sm text-zinc-400">Patterns</div>
          </div>
          <div className="bg-blue-500/10 border border-blue-500/20 rounded-lg p-4 text-center">
            <div className="text-2xl font-bold text-blue-400">Free</div>
            <div className="text-sm text-zinc-400">During Beta</div>
          </div>
          <div className="bg-purple-500/10 border border-purple-500/20 rounded-lg p-4 text-center">
            <div className="text-2xl font-bold text-purple-400">JSON</div>
            <div className="text-sm text-zinc-400">Response Format</div>
          </div>
        </div>

        <div className="space-y-8">
          {/* Base URL */}
          <section className="bg-zinc-800/50 rounded-xl p-6 border border-zinc-700">
            <h2 className="text-xl font-semibold mb-4">Base URL</h2>
            <code className="bg-zinc-900 px-4 py-2 rounded-lg text-emerald-400 block">
              https://solguard.dev/api/v1
            </code>
          </section>

          {/* Audit Endpoint */}
          <section className="bg-zinc-800/50 rounded-xl p-6 border border-zinc-700">
            <div className="flex items-center gap-3 mb-4">
              <span className="px-3 py-1 bg-emerald-500 text-black text-sm font-bold rounded">POST</span>
              <code className="text-lg">/audit</code>
            </div>
            
            <p className="text-zinc-300 mb-6">
              Audit Rust/Anchor smart contract code and receive vulnerability findings. 
              Scans against <Link href="/patterns" className="text-emerald-400 hover:underline">130 vulnerability patterns</Link>.
            </p>

            <h3 className="font-semibold mb-2 text-zinc-200">Request Body</h3>
            <pre className="bg-zinc-900 p-4 rounded-lg overflow-x-auto text-sm mb-6 border border-zinc-700">
{`{
  "code": "use anchor_lang::prelude::*; ...",  // Required: Rust source code
  "format": "json",                            // Optional: "json" (default) | "markdown"
  "ai": false                                  // Optional: Include AI explanations (slower)
}`}
            </pre>

            <h3 className="font-semibold mb-2 text-zinc-200">Response</h3>
            <pre className="bg-zinc-900 p-4 rounded-lg overflow-x-auto text-sm mb-6 border border-zinc-700">
{`{
  "success": true,
  "passed": false,
  "timestamp": "2026-02-02T20:00:00.000Z",
  "summary": {
    "critical": 2,
    "high": 3,
    "medium": 1,
    "low": 0,
    "info": 0,
    "total": 6
  },
  "severityScore": 155,
  "findings": [
    {
      "id": "SOL002-1",
      "pattern": "SOL002",
      "severity": "critical",
      "title": "Authority account 'authority' is not a Signer",
      "description": "The authority account can be any AccountInfo...",
      "location": { "file": "lib.rs", "line": 42, "column": 5 },
      "suggestion": "Change to: pub authority: Signer<'info>",
      "codeSnippet": "pub authority: AccountInfo<'info>"
    }
  ],
  "executionTimeMs": 234,
  "apiVersion": "1.0.0"
}`}
            </pre>

            <h3 className="font-semibold mb-2 text-zinc-200">Example (cURL)</h3>
            <pre className="bg-zinc-900 p-4 rounded-lg overflow-x-auto text-sm border border-zinc-700">
{`curl -X POST https://solguard.dev/api/v1/audit \\
  -H "Content-Type: application/json" \\
  -d '{
    "code": "use anchor_lang::prelude::*;\\n\\n#[program]\\npub mod my_program { ... }"
  }'`}
            </pre>
          </section>

          {/* Health Check */}
          <section className="bg-zinc-800/50 rounded-xl p-6 border border-zinc-700">
            <div className="flex items-center gap-3 mb-4">
              <span className="px-3 py-1 bg-blue-500 text-white text-sm font-bold rounded">GET</span>
              <code className="text-lg">/audit</code>
            </div>
            
            <p className="text-zinc-300 mb-4">
              Health check endpoint. Returns API status and version info.
            </p>

            <pre className="bg-zinc-900 p-4 rounded-lg overflow-x-auto text-sm border border-zinc-700">
{`{
  "status": "ok",
  "service": "SolGuard Audit API",
  "version": "1.0.0",
  "patterns": 130
}`}
            </pre>
          </section>

          {/* Error Responses */}
          <section className="bg-zinc-800/50 rounded-xl p-6 border border-zinc-700">
            <h2 className="text-xl font-semibold mb-4">Error Responses</h2>
            
            <div className="space-y-4">
              <div>
                <code className="text-red-400">400 Bad Request</code>
                <pre className="bg-zinc-900 p-3 rounded-lg text-sm mt-2 border border-zinc-700">
{`{ "error": "Missing required field: code" }`}
                </pre>
              </div>
              
              <div>
                <code className="text-red-400">413 Payload Too Large</code>
                <pre className="bg-zinc-900 p-3 rounded-lg text-sm mt-2 border border-zinc-700">
{`{ "error": "Code exceeds maximum size of 500KB" }`}
                </pre>
              </div>
              
              <div>
                <code className="text-red-400">429 Too Many Requests</code>
                <pre className="bg-zinc-900 p-3 rounded-lg text-sm mt-2 border border-zinc-700">
{`{ "error": "Rate limit exceeded. Try again in 60 seconds." }`}
                </pre>
              </div>
            </div>
          </section>

          {/* Rate Limits */}
          <section className="bg-zinc-800/50 rounded-xl p-6 border border-zinc-700">
            <h2 className="text-xl font-semibold mb-4">Rate Limits</h2>
            <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
              <div className="bg-zinc-900 p-4 rounded-lg text-center">
                <div className="text-2xl font-bold text-zinc-200">100</div>
                <div className="text-sm text-zinc-500">requests/min</div>
              </div>
              <div className="bg-zinc-900 p-4 rounded-lg text-center">
                <div className="text-2xl font-bold text-zinc-200">500KB</div>
                <div className="text-sm text-zinc-500">max code size</div>
              </div>
              <div className="bg-zinc-900 p-4 rounded-lg text-center">
                <div className="text-2xl font-bold text-zinc-200">60s</div>
                <div className="text-sm text-zinc-500">timeout</div>
              </div>
            </div>
          </section>

          {/* Severity Levels */}
          <section className="bg-zinc-800/50 rounded-xl p-6 border border-zinc-700">
            <h2 className="text-xl font-semibold mb-4">Severity Levels</h2>
            <div className="space-y-3">
              <div className="flex items-center gap-3">
                <span className="w-20 text-center px-2 py-1 bg-red-500/20 text-red-400 rounded text-sm font-medium">critical</span>
                <span className="text-zinc-300">Immediate exploit risk, potential fund loss</span>
              </div>
              <div className="flex items-center gap-3">
                <span className="w-20 text-center px-2 py-1 bg-orange-500/20 text-orange-400 rounded text-sm font-medium">high</span>
                <span className="text-zinc-300">Significant vulnerability, exploitation likely</span>
              </div>
              <div className="flex items-center gap-3">
                <span className="w-20 text-center px-2 py-1 bg-yellow-500/20 text-yellow-400 rounded text-sm font-medium">medium</span>
                <span className="text-zinc-300">Potential issue under specific conditions</span>
              </div>
              <div className="flex items-center gap-3">
                <span className="w-20 text-center px-2 py-1 bg-blue-500/20 text-blue-400 rounded text-sm font-medium">low</span>
                <span className="text-zinc-300">Best practice violation, minimal risk</span>
              </div>
              <div className="flex items-center gap-3">
                <span className="w-20 text-center px-2 py-1 bg-zinc-500/20 text-zinc-400 rounded text-sm font-medium">info</span>
                <span className="text-zinc-300">Informational finding, no security impact</span>
              </div>
            </div>
          </section>

          {/* Patterns Link */}
          <section className="bg-gradient-to-r from-emerald-500/10 to-cyan-500/10 rounded-xl p-6 border border-emerald-500/20">
            <h2 className="text-xl font-semibold mb-2">130 Vulnerability Patterns</h2>
            <p className="text-zinc-300 mb-4">
              SolGuard detects vulnerabilities across core security, CPI, DeFi, NFT, token, 
              PDA, Anchor, and more categories.
            </p>
            <Link 
              href="/patterns" 
              className="inline-flex items-center gap-2 px-4 py-2 bg-emerald-500 hover:bg-emerald-600 text-black font-semibold rounded-lg transition"
            >
              View All Patterns →
            </Link>
          </section>

          {/* CLI */}
          <section className="bg-zinc-800/50 rounded-xl p-6 border border-zinc-700">
            <h2 className="text-xl font-semibold mb-4">CLI Alternative</h2>
            <p className="text-zinc-300 mb-4">
              For local development and CI/CD integration, use the SolGuard CLI:
            </p>
            <pre className="bg-zinc-900 p-4 rounded-lg overflow-x-auto text-sm border border-zinc-700">
{`# Install
npm install -g @solguard/cli

# Audit local program
solguard audit ./my-program

# Audit GitHub repo
solguard github coral-xyz/anchor

# CI mode with SARIF output
solguard ci . --fail-on high --sarif results.sarif`}
            </pre>
          </section>
        </div>
      </main>

      {/* Footer */}
      <footer className="border-t border-zinc-800 mt-16">
        <div className="max-w-6xl mx-auto px-4 py-8 text-center text-zinc-500 text-sm">
          <p>Built by <span className="text-emerald-400">Midir</span> 🐉 for the Solana Agent Hackathon 2026</p>
          <p className="mt-2">Open source • MIT License • Powered by Claude AI</p>
        </div>
      </footer>
    </div>
  );
}
