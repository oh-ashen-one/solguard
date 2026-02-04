'use client';

import { useState, useCallback } from 'react';
import Link from 'next/link';

type InputMode = 'github' | 'upload' | 'paste';

export default function Home() {
  const [inputMode, setInputMode] = useState<InputMode>('github');
  const [code, setCode] = useState('');
  const [githubUrl, setGithubUrl] = useState('');
  const [files, setFiles] = useState<File[]>([]);
  const [isLoading, setIsLoading] = useState(false);
  const [loadingStatus, setLoadingStatus] = useState('');
  const [result, setResult] = useState<any>(null);
  const [isDragging, setIsDragging] = useState(false);

  // Parse GitHub URL and fetch files
  const parseGitHubUrl = (url: string) => {
    const patterns = [
      /github\.com\/([^\/]+)\/([^\/]+)(?:\/tree\/([^\/]+))?(?:\/(.*))?/,
      /github\.com\/([^\/]+)\/([^\/]+)/
    ];
    
    for (const pattern of patterns) {
      const match = url.match(pattern);
      if (match) {
        return {
          owner: match[1],
          repo: match[2],
          branch: match[3] || 'main',
          path: match[4] || ''
        };
      }
    }
    return null;
  };

  const fetchGitHubFiles = async (url: string): Promise<string> => {
    const parsed = parseGitHubUrl(url);
    if (!parsed) throw new Error('Invalid GitHub URL');

    setLoadingStatus(`Fetching from ${parsed.owner}/${parsed.repo}...`);
    
    // Use GitHub API to get repo contents
    const apiUrl = `https://api.github.com/repos/${parsed.owner}/${parsed.repo}/git/trees/${parsed.branch}?recursive=1`;
    const response = await fetch(apiUrl);
    
    if (!response.ok) {
      throw new Error(`GitHub API error: ${response.status}`);
    }
    
    const data = await response.json();
    const rustFiles = data.tree?.filter((f: any) => 
      f.path.endsWith('.rs') && f.type === 'blob'
    ) || [];

    if (rustFiles.length === 0) {
      throw new Error('No Rust files found in repository');
    }

    setLoadingStatus(`Found ${rustFiles.length} Rust files. Downloading...`);
    
    // Fetch first 10 files (to avoid rate limits)
    const filesToFetch = rustFiles.slice(0, 10);
    const fileContents: string[] = [];
    
    for (const file of filesToFetch) {
      setLoadingStatus(`Downloading ${file.path}...`);
      const rawUrl = `https://raw.githubusercontent.com/${parsed.owner}/${parsed.repo}/${parsed.branch}/${file.path}`;
      const fileRes = await fetch(rawUrl);
      if (fileRes.ok) {
        const content = await fileRes.text();
        fileContents.push(`// ===== ${file.path} =====\n${content}`);
      }
    }

    return fileContents.join('\n\n');
  };

  // Handle file drop
  const handleDrop = useCallback((e: React.DragEvent) => {
    e.preventDefault();
    setIsDragging(false);
    
    const droppedFiles = Array.from(e.dataTransfer.files).filter(
      f => f.name.endsWith('.rs') || f.name.endsWith('.toml')
    );
    
    if (droppedFiles.length > 0) {
      setFiles(droppedFiles);
      readFiles(droppedFiles);
    }
  }, []);

  const readFiles = async (fileList: File[]) => {
    const contents: string[] = [];
    for (const file of fileList) {
      const text = await file.text();
      contents.push(`// ===== ${file.name} =====\n${text}`);
    }
    setCode(contents.join('\n\n'));
  };

  const handleFileSelect = (e: React.ChangeEvent<HTMLInputElement>) => {
    const selectedFiles = Array.from(e.target.files || []).filter(
      f => f.name.endsWith('.rs') || f.name.endsWith('.toml')
    );
    if (selectedFiles.length > 0) {
      setFiles(selectedFiles);
      readFiles(selectedFiles);
    }
  };

  const handleAudit = async (e: React.FormEvent) => {
    e.preventDefault();
    setIsLoading(true);
    setResult(null);
    setLoadingStatus('');

    try {
      let codeToAudit = code;

      // If GitHub mode, fetch files first
      if (inputMode === 'github' && githubUrl) {
        codeToAudit = await fetchGitHubFiles(githubUrl);
        setCode(codeToAudit);
      }

      if (!codeToAudit.trim()) {
        throw new Error('No code to audit');
      }

      setLoadingStatus('Running security analysis...');
      
      const res = await fetch('/api/audit', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ code: codeToAudit }),
      });
      const data = await res.json();
      setResult(data);
    } catch (err: any) {
      setResult({ error: err.message || 'Failed to run audit' });
    } finally {
      setIsLoading(false);
      setLoadingStatus('');
    }
  };

  const loadExample = (type: 'vulnerable' | 'secure') => {
    setInputMode('paste');
    if (type === 'vulnerable') {
      setCode(`use anchor_lang::prelude::*;

declare_id!("Vuln111111111111111111111111111111111111111");

#[program]
pub mod vulnerable_vault {
    use super::*;

    pub fn withdraw(ctx: Context<Withdraw>, amount: u64) -> Result<()> {
        let vault = &mut ctx.accounts.vault;
        
        // Missing authority verification
        // Integer overflow possible
        vault.balance = vault.balance - amount;
        
        **ctx.accounts.vault_account.try_borrow_mut_lamports()? -= amount;
        **ctx.accounts.recipient.try_borrow_mut_lamports()? += amount;
        
        Ok(())
    }
}

#[derive(Accounts)]
pub struct Withdraw<'info> {
    #[account(mut)]
    pub vault: Account<'info, Vault>,
    
    /// CHECK: No signer constraint
    pub authority: AccountInfo<'info>,
    
    /// CHECK: Recipient
    #[account(mut)]
    pub recipient: AccountInfo<'info>,
    
    /// CHECK: Vault token account
    #[account(mut)]
    pub vault_account: AccountInfo<'info>,
}

#[account]
pub struct Vault {
    pub authority: Pubkey,
    pub balance: u64,
}`);
    } else {
      setCode(`use anchor_lang::prelude::*;

declare_id!("Safe1111111111111111111111111111111111111111");

#[program]
pub mod secure_vault {
    use super::*;

    pub fn withdraw(ctx: Context<Withdraw>, amount: u64) -> Result<()> {
        let vault = &mut ctx.accounts.vault;
        
        require!(
            ctx.accounts.authority.key() == vault.authority,
            VaultError::Unauthorized
        );
        
        vault.balance = vault.balance
            .checked_sub(amount)
            .ok_or(VaultError::InsufficientFunds)?;
        
        **ctx.accounts.vault_account.try_borrow_mut_lamports()? -= amount;
        **ctx.accounts.recipient.try_borrow_mut_lamports()? += amount;
        
        Ok(())
    }
}

#[derive(Accounts)]
pub struct Withdraw<'info> {
    #[account(mut)]
    pub vault: Account<'info, Vault>,
    
    pub authority: Signer<'info>,
    
    /// CHECK: Recipient
    #[account(mut)]
    pub recipient: AccountInfo<'info>,
    
    /// CHECK: Vault token account
    #[account(mut)]
    pub vault_account: AccountInfo<'info>,
}

#[account]
pub struct Vault {
    pub authority: Pubkey,
    pub balance: u64,
}

#[error_code]
pub enum VaultError {
    #[msg("Unauthorized")]
    Unauthorized,
    #[msg("Insufficient funds")]
    InsufficientFunds,
}`);
    }
  };

  return (
    <div className="min-h-screen bg-[#0a0a0f] text-zinc-100">
      {/* Header */}
      <header className="border-b border-zinc-800/50 backdrop-blur-sm bg-[#0a0a0f]/80 sticky top-0 z-50">
        <div className="max-w-6xl mx-auto px-6 py-4 flex items-center justify-between">
          <Link href="/" className="flex items-center gap-3 group">
            <div className="w-8 h-8 rounded-lg bg-gradient-to-br from-blue-500 to-cyan-400 flex items-center justify-center">
              <svg className="w-5 h-5 text-white" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
                <path strokeLinecap="round" strokeLinejoin="round" d="M9 12.75L11.25 15 15 9.75m-3-7.036A11.959 11.959 0 013.598 6 11.99 11.99 0 003 9.749c0 5.592 3.824 10.29 9 11.623 5.176-1.332 9-6.03 9-11.622 0-1.31-.21-2.571-.598-3.751h-.152c-3.196 0-6.1-1.248-8.25-3.285z" />
              </svg>
            </div>
            <span className="text-xl font-semibold tracking-tight">SolShield</span>
          </Link>
          
          <nav className="hidden md:flex items-center gap-8">
            <Link href="#features" className="text-sm text-zinc-400 hover:text-white transition-colors">Features</Link>
            <Link href="/patterns" className="text-sm text-zinc-400 hover:text-white transition-colors">Patterns</Link>
            <Link href="/api" className="text-sm text-zinc-400 hover:text-white transition-colors">API</Link>
            <a 
              href="https://github.com/oh-ashen-one/solshield" 
              target="_blank" 
              rel="noopener noreferrer"
              className="text-sm text-zinc-400 hover:text-white transition-colors flex items-center gap-2"
            >
              <svg className="w-4 h-4" fill="currentColor" viewBox="0 0 24 24">
                <path d="M12 0c-6.626 0-12 5.373-12 12 0 5.302 3.438 9.8 8.207 11.387.599.111.793-.261.793-.577v-2.234c-3.338.726-4.033-1.416-4.033-1.416-.546-1.387-1.333-1.756-1.333-1.756-1.089-.745.083-.729.083-.729 1.205.084 1.839 1.237 1.839 1.237 1.07 1.834 2.807 1.304 3.492.997.107-.775.418-1.305.762-1.604-2.665-.305-5.467-1.334-5.467-5.931 0-1.311.469-2.381 1.236-3.221-.124-.303-.535-1.524.117-3.176 0 0 1.008-.322 3.301 1.23.957-.266 1.983-.399 3.003-.404 1.02.005 2.047.138 3.006.404 2.291-1.552 3.297-1.23 3.297-1.23.653 1.653.242 2.874.118 3.176.77.84 1.235 1.911 1.235 3.221 0 4.609-2.807 5.624-5.479 5.921.43.372.823 1.102.823 2.222v3.293c0 .319.192.694.801.576 4.765-1.589 8.199-6.086 8.199-11.386 0-6.627-5.373-12-12-12z"/>
              </svg>
              GitHub
            </a>
          </nav>

          <a 
            href="#audit"
            className="hidden md:flex px-4 py-2 bg-blue-600 hover:bg-blue-500 text-white text-sm font-medium rounded-lg transition-colors"
          >
            Start Audit
          </a>
        </div>
      </header>

      {/* Hero */}
      <section className="relative overflow-hidden">
        {/* Background gradient */}
        <div className="absolute inset-0 bg-gradient-to-b from-blue-500/5 via-transparent to-transparent" />
        <div className="absolute top-0 left-1/2 -translate-x-1/2 w-[800px] h-[400px] bg-blue-500/10 blur-[120px] rounded-full" />
        
        <div className="relative max-w-6xl mx-auto px-6 pt-24 pb-16">
          <div className="flex items-center justify-center gap-2 mb-8">
            <span className="px-3 py-1 bg-blue-500/10 border border-blue-500/20 rounded-full text-blue-400 text-sm font-medium">
              Solana Agent Hackathon 2026
            </span>
          </div>
          
          <h1 className="text-5xl md:text-6xl lg:text-7xl font-bold text-center tracking-tight mb-6">
            Security Audits for
            <br />
            <span className="text-transparent bg-clip-text bg-gradient-to-r from-blue-400 via-cyan-400 to-blue-400">
              Solana Programs
            </span>
          </h1>
          
          <p className="text-xl text-zinc-400 text-center max-w-2xl mx-auto mb-12">
            AI-powered vulnerability detection for Anchor programs. 
            150 patterns. Instant analysis. Ship secure code.
          </p>
          
          <div className="flex flex-col sm:flex-row items-center justify-center gap-4">
            <a 
              href="#audit"
              className="w-full sm:w-auto px-8 py-3.5 bg-blue-600 hover:bg-blue-500 text-white font-semibold rounded-xl transition-all hover:shadow-lg hover:shadow-blue-500/25"
            >
              Audit Your Code
            </a>
            <a 
              href="https://github.com/oh-ashen-one/solshield" 
              target="_blank"
              rel="noopener noreferrer"
              className="w-full sm:w-auto px-8 py-3.5 border border-zinc-700 hover:border-zinc-500 hover:bg-zinc-800/50 rounded-xl transition-all flex items-center justify-center gap-2"
            >
              <svg className="w-5 h-5" fill="currentColor" viewBox="0 0 24 24">
                <path d="M12 0c-6.626 0-12 5.373-12 12 0 5.302 3.438 9.8 8.207 11.387.599.111.793-.261.793-.577v-2.234c-3.338.726-4.033-1.416-4.033-1.416-.546-1.387-1.333-1.756-1.333-1.756-1.089-.745.083-.729.083-.729 1.205.084 1.839 1.237 1.839 1.237 1.07 1.834 2.807 1.304 3.492.997.107-.775.418-1.305.762-1.604-2.665-.305-5.467-1.334-5.467-5.931 0-1.311.469-2.381 1.236-3.221-.124-.303-.535-1.524.117-3.176 0 0 1.008-.322 3.301 1.23.957-.266 1.983-.399 3.003-.404 1.02.005 2.047.138 3.006.404 2.291-1.552 3.297-1.23 3.297-1.23.653 1.653.242 2.874.118 3.176.77.84 1.235 1.911 1.235 3.221 0 4.609-2.807 5.624-5.479 5.921.43.372.823 1.102.823 2.222v3.293c0 .319.192.694.801.576 4.765-1.589 8.199-6.086 8.199-11.386 0-6.627-5.373-12-12-12z"/>
              </svg>
              View Source
            </a>
          </div>
        </div>
      </section>

      {/* Stats */}
      <section className="border-y border-zinc-800/50 bg-zinc-900/30">
        <div className="max-w-6xl mx-auto px-6 py-12">
          <div className="grid grid-cols-2 md:grid-cols-4 gap-8">
            {[
              { value: '150', label: 'Vulnerability Patterns', sublabel: 'Based on real exploits' },
              { value: '$557M+', label: 'Exploits Covered', sublabel: 'Wormhole, Mango, more' },
              { value: '17', label: 'CLI Commands', sublabel: 'Full audit toolkit' },
              { value: '<1s', label: 'Analysis Time', sublabel: 'Instant results' },
            ].map((stat, i) => (
              <div key={i} className="text-center">
                <div className="text-3xl md:text-4xl font-bold text-white mb-1">{stat.value}</div>
                <div className="text-sm font-medium text-zinc-300">{stat.label}</div>
                <div className="text-xs text-zinc-500 mt-0.5">{stat.sublabel}</div>
              </div>
            ))}
          </div>
        </div>
      </section>

      {/* Audit Section */}
      <section id="audit" className="max-w-4xl mx-auto px-6 py-20">
        <div className="text-center mb-10">
          <h2 className="text-3xl font-bold mb-3">Run Security Audit</h2>
          <p className="text-zinc-400">Analyze your Solana program for vulnerabilities</p>
        </div>

        {/* Input Mode Tabs */}
        <div className="flex items-center justify-center gap-1 p-1 bg-zinc-800/50 rounded-xl mb-6 max-w-md mx-auto">
          {[
            { id: 'github', label: 'GitHub URL', icon: (
              <svg className="w-4 h-4" fill="currentColor" viewBox="0 0 24 24">
                <path d="M12 0c-6.626 0-12 5.373-12 12 0 5.302 3.438 9.8 8.207 11.387.599.111.793-.261.793-.577v-2.234c-3.338.726-4.033-1.416-4.033-1.416-.546-1.387-1.333-1.756-1.333-1.756-1.089-.745.083-.729.083-.729 1.205.084 1.839 1.237 1.839 1.237 1.07 1.834 2.807 1.304 3.492.997.107-.775.418-1.305.762-1.604-2.665-.305-5.467-1.334-5.467-5.931 0-1.311.469-2.381 1.236-3.221-.124-.303-.535-1.524.117-3.176 0 0 1.008-.322 3.301 1.23.957-.266 1.983-.399 3.003-.404 1.02.005 2.047.138 3.006.404 2.291-1.552 3.297-1.23 3.297-1.23.653 1.653.242 2.874.118 3.176.77.84 1.235 1.911 1.235 3.221 0 4.609-2.807 5.624-5.479 5.921.43.372.823 1.102.823 2.222v3.293c0 .319.192.694.801.576 4.765-1.589 8.199-6.086 8.199-11.386 0-6.627-5.373-12-12-12z"/>
              </svg>
            )},
            { id: 'upload', label: 'Upload Files', icon: (
              <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
                <path strokeLinecap="round" strokeLinejoin="round" d="M7 16a4 4 0 01-.88-7.903A5 5 0 1115.9 6L16 6a5 5 0 011 9.9M15 13l-3-3m0 0l-3 3m3-3v12" />
              </svg>
            )},
            { id: 'paste', label: 'Paste Code', icon: (
              <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
                <path strokeLinecap="round" strokeLinejoin="round" d="M10 20l4-16m4 4l4 4-4 4M6 16l-4-4 4-4" />
              </svg>
            )},
          ].map((tab) => (
            <button
              key={tab.id}
              onClick={() => setInputMode(tab.id as InputMode)}
              className={`flex-1 flex items-center justify-center gap-2 px-4 py-2.5 rounded-lg text-sm font-medium transition-all ${
                inputMode === tab.id
                  ? 'bg-zinc-700 text-white shadow-sm'
                  : 'text-zinc-400 hover:text-white'
              }`}
            >
              {tab.icon}
              <span className="hidden sm:inline">{tab.label}</span>
            </button>
          ))}
        </div>

        <form onSubmit={handleAudit} className="space-y-4">
          {/* GitHub URL Input */}
          {inputMode === 'github' && (
            <div className="space-y-3">
              <div className="relative">
                <input
                  type="url"
                  value={githubUrl}
                  onChange={(e) => setGithubUrl(e.target.value)}
                  placeholder="https://github.com/username/repo"
                  className="w-full px-4 py-4 bg-zinc-900 border border-zinc-700 rounded-xl text-white placeholder-zinc-500 focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-transparent transition-all"
                />
                <div className="absolute right-4 top-1/2 -translate-y-1/2 text-zinc-500">
                  <svg className="w-5 h-5" fill="currentColor" viewBox="0 0 24 24">
                    <path d="M12 0c-6.626 0-12 5.373-12 12 0 5.302 3.438 9.8 8.207 11.387.599.111.793-.261.793-.577v-2.234c-3.338.726-4.033-1.416-4.033-1.416-.546-1.387-1.333-1.756-1.333-1.756-1.089-.745.083-.729.083-.729 1.205.084 1.839 1.237 1.839 1.237 1.07 1.834 2.807 1.304 3.492.997.107-.775.418-1.305.762-1.604-2.665-.305-5.467-1.334-5.467-5.931 0-1.311.469-2.381 1.236-3.221-.124-.303-.535-1.524.117-3.176 0 0 1.008-.322 3.301 1.23.957-.266 1.983-.399 3.003-.404 1.02.005 2.047.138 3.006.404 2.291-1.552 3.297-1.23 3.297-1.23.653 1.653.242 2.874.118 3.176.77.84 1.235 1.911 1.235 3.221 0 4.609-2.807 5.624-5.479 5.921.43.372.823 1.102.823 2.222v3.293c0 .319.192.694.801.576 4.765-1.589 8.199-6.086 8.199-11.386 0-6.627-5.373-12-12-12z"/>
                  </svg>
                </div>
              </div>
              <p className="text-xs text-zinc-500 px-1">
                Public repositories only. We'll scan all .rs files automatically.
              </p>
            </div>
          )}

          {/* File Upload */}
          {inputMode === 'upload' && (
            <div
              onDragOver={(e) => { e.preventDefault(); setIsDragging(true); }}
              onDragLeave={() => setIsDragging(false)}
              onDrop={handleDrop}
              className={`relative border-2 border-dashed rounded-xl p-12 text-center transition-all ${
                isDragging 
                  ? 'border-blue-500 bg-blue-500/5' 
                  : 'border-zinc-700 hover:border-zinc-600'
              }`}
            >
              <input
                type="file"
                accept=".rs,.toml"
                multiple
                onChange={handleFileSelect}
                className="absolute inset-0 w-full h-full opacity-0 cursor-pointer"
              />
              <div className="flex flex-col items-center gap-3">
                <div className="w-12 h-12 rounded-full bg-zinc-800 flex items-center justify-center">
                  <svg className="w-6 h-6 text-zinc-400" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={1.5}>
                    <path strokeLinecap="round" strokeLinejoin="round" d="M3 16.5v2.25A2.25 2.25 0 005.25 21h13.5A2.25 2.25 0 0021 18.75V16.5m-13.5-9L12 3m0 0l4.5 4.5M12 3v13.5" />
                  </svg>
                </div>
                <div>
                  <p className="text-zinc-300 font-medium">Drop files here or click to browse</p>
                  <p className="text-zinc-500 text-sm mt-1">Accepts .rs and .toml files</p>
                </div>
              </div>
              {files.length > 0 && (
                <div className="mt-6 flex flex-wrap gap-2 justify-center">
                  {files.map((f, i) => (
                    <span key={i} className="px-3 py-1.5 bg-zinc-800 rounded-lg text-sm text-zinc-300">
                      {f.name}
                    </span>
                  ))}
                </div>
              )}
            </div>
          )}

          {/* Code Paste */}
          {inputMode === 'paste' && (
            <div className="space-y-3">
              <div className="flex items-center gap-2">
                <span className="text-sm text-zinc-500">Load example:</span>
                <button
                  type="button"
                  onClick={() => loadExample('vulnerable')}
                  className="px-3 py-1.5 text-sm bg-red-500/10 text-red-400 hover:bg-red-500/20 rounded-lg transition-colors border border-red-500/20"
                >
                  Vulnerable Code
                </button>
                <button
                  type="button"
                  onClick={() => loadExample('secure')}
                  className="px-3 py-1.5 text-sm bg-emerald-500/10 text-emerald-400 hover:bg-emerald-500/20 rounded-lg transition-colors border border-emerald-500/20"
                >
                  Secure Code
                </button>
              </div>
              <textarea
                value={code}
                onChange={(e) => setCode(e.target.value)}
                placeholder="// Paste your Anchor program code here..."
                className="w-full h-80 px-4 py-4 bg-zinc-900 border border-zinc-700 rounded-xl font-mono text-sm text-white placeholder-zinc-500 focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-transparent transition-all resize-none"
              />
            </div>
          )}

          {/* Submit Button */}
          <button
            type="submit"
            disabled={isLoading || (inputMode === 'github' ? !githubUrl.trim() : !code.trim())}
            className="w-full py-4 bg-blue-600 hover:bg-blue-500 disabled:bg-zinc-800 disabled:text-zinc-500 disabled:cursor-not-allowed text-white font-semibold rounded-xl transition-all flex items-center justify-center gap-3"
          >
            {isLoading ? (
              <>
                <svg className="animate-spin h-5 w-5" viewBox="0 0 24 24">
                  <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4" fill="none" />
                  <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z" />
                </svg>
                {loadingStatus || 'Analyzing...'}
              </>
            ) : (
              <>
                <svg className="w-5 h-5" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
                  <path strokeLinecap="round" strokeLinejoin="round" d="M9 12.75L11.25 15 15 9.75m-3-7.036A11.959 11.959 0 013.598 6 11.99 11.99 0 003 9.749c0 5.592 3.824 10.29 9 11.623 5.176-1.332 9-6.03 9-11.622 0-1.31-.21-2.571-.598-3.751h-.152c-3.196 0-6.1-1.248-8.25-3.285z" />
                </svg>
                Run Security Audit
              </>
            )}
          </button>
        </form>

        {/* Results */}
        {result && (
          <div className="mt-10 p-6 bg-zinc-900/50 border border-zinc-800 rounded-2xl">
            {result.error ? (
              <div className="flex items-center gap-3 text-red-400">
                <svg className="w-5 h-5 flex-shrink-0" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
                  <path strokeLinecap="round" strokeLinejoin="round" d="M12 9v3.75m9-.75a9 9 0 11-18 0 9 9 0 0118 0zm-9 3.75h.008v.008H12v-.008z" />
                </svg>
                {result.error}
              </div>
            ) : (
              <>
                <div className="flex items-center justify-between mb-8">
                  <h3 className="text-xl font-semibold">Audit Results</h3>
                  <span className={`px-4 py-1.5 rounded-full text-sm font-medium ${
                    result.passed 
                      ? 'bg-emerald-500/10 text-emerald-400 border border-emerald-500/20' 
                      : 'bg-red-500/10 text-red-400 border border-red-500/20'
                  }`}>
                    {result.passed ? 'No Issues Found' : 'Issues Detected'}
                  </span>
                </div>
                
                {/* Summary */}
                <div className="grid grid-cols-5 gap-4 mb-8 p-4 bg-zinc-800/50 rounded-xl">
                  {[
                    { label: 'Critical', count: result.summary?.critical || 0, color: 'text-red-400', bg: 'bg-red-500/10' },
                    { label: 'High', count: result.summary?.high || 0, color: 'text-orange-400', bg: 'bg-orange-500/10' },
                    { label: 'Medium', count: result.summary?.medium || 0, color: 'text-yellow-400', bg: 'bg-yellow-500/10' },
                    { label: 'Low', count: result.summary?.low || 0, color: 'text-blue-400', bg: 'bg-blue-500/10' },
                    { label: 'Info', count: result.summary?.info || 0, color: 'text-zinc-400', bg: 'bg-zinc-500/10' },
                  ].map((s, i) => (
                    <div key={i} className={`text-center p-3 rounded-lg ${s.bg}`}>
                      <div className={`text-2xl font-bold ${s.color}`}>{s.count}</div>
                      <div className="text-zinc-400 text-xs mt-1">{s.label}</div>
                    </div>
                  ))}
                </div>
                
                {/* Findings */}
                {result.findings?.length > 0 && (
                  <div className="space-y-4">
                    {result.findings.map((finding: any, i: number) => (
                      <div key={i} className={`p-5 bg-zinc-800/30 rounded-xl border-l-4 ${
                        finding.severity === 'critical' ? 'border-red-500' :
                        finding.severity === 'high' ? 'border-orange-500' :
                        finding.severity === 'medium' ? 'border-yellow-500' :
                        'border-blue-500'
                      }`}>
                        <div className="flex items-start justify-between gap-4">
                          <div className="flex items-center gap-3">
                            <span className={`px-2.5 py-1 rounded text-xs font-medium ${
                              finding.severity === 'critical' ? 'bg-red-500/10 text-red-400' :
                              finding.severity === 'high' ? 'bg-orange-500/10 text-orange-400' :
                              finding.severity === 'medium' ? 'bg-yellow-500/10 text-yellow-400' :
                              'bg-blue-500/10 text-blue-400'
                            }`}>
                              {finding.severity?.toUpperCase()}
                            </span>
                            <code className="text-xs text-zinc-500 bg-zinc-800 px-2 py-0.5 rounded">{finding.id}</code>
                          </div>
                          {finding.location?.line && (
                            <span className="text-zinc-500 text-sm">Line {finding.location.line}</span>
                          )}
                        </div>
                        <h4 className="font-semibold mt-3 text-white">{finding.title}</h4>
                        <p className="text-zinc-400 text-sm mt-2 leading-relaxed">{finding.description}</p>
                        {finding.suggestion && (
                          <div className="mt-4 p-4 bg-emerald-500/5 border border-emerald-500/10 rounded-lg">
                            <div className="flex items-start gap-2">
                              <svg className="w-4 h-4 text-emerald-400 mt-0.5 flex-shrink-0" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
                                <path strokeLinecap="round" strokeLinejoin="round" d="M9.663 17h4.673M12 3v1m6.364 1.636l-.707.707M21 12h-1M4 12H3m3.343-5.657l-.707-.707m2.828 9.9a5 5 0 117.072 0l-.548.547A3.374 3.374 0 0014 18.469V19a2 2 0 11-4 0v-.531c0-.895-.356-1.754-.988-2.386l-.548-.547z" />
                              </svg>
                              <div>
                                <span className="text-emerald-400 text-sm font-medium">Suggested Fix</span>
                                <p className="text-zinc-300 text-sm mt-1">{finding.suggestion.split('\n')[0]}</p>
                              </div>
                            </div>
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

      {/* Features */}
      <section id="features" className="border-t border-zinc-800/50 bg-zinc-900/20">
        <div className="max-w-6xl mx-auto px-6 py-20">
          <div className="text-center mb-16">
            <h2 className="text-3xl font-bold mb-4">What We Detect</h2>
            <p className="text-zinc-400 max-w-2xl mx-auto">
              Comprehensive coverage of Solana-specific vulnerabilities based on real exploits
            </p>
          </div>
          
          <div className="grid md:grid-cols-3 gap-4">
            {[
              { title: 'Missing Signer Checks', desc: 'Authority accounts without cryptographic verification', severity: 'Critical' },
              { title: 'Owner Validation', desc: 'Accounts without proper ownership constraints', severity: 'Critical' },
              { title: 'Integer Overflow', desc: 'Unchecked arithmetic that can wrap around', severity: 'High' },
              { title: 'PDA Validation', desc: 'Program Derived Addresses without bump verification', severity: 'High' },
              { title: 'CPI Vulnerabilities', desc: 'Cross-program invocation without verification', severity: 'High' },
              { title: 'Account Confusion', desc: 'Swappable accounts of the same type', severity: 'High' },
              { title: 'Reentrancy', desc: 'State changes after cross-program calls', severity: 'High' },
              { title: 'Type Cosplay', desc: 'Missing discriminator validation', severity: 'Critical' },
              { title: 'Closing Issues', desc: 'Account revival attacks and rent theft', severity: 'Critical' },
            ].map((feature, i) => (
              <div key={i} className="group p-5 bg-zinc-800/30 border border-zinc-800 rounded-xl hover:border-zinc-700 hover:bg-zinc-800/50 transition-all">
                <div className="flex items-start justify-between mb-3">
                  <h3 className="font-semibold text-white">{feature.title}</h3>
                  <span className={`text-xs px-2 py-0.5 rounded ${
                    feature.severity === 'Critical' 
                      ? 'bg-red-500/10 text-red-400' 
                      : 'bg-orange-500/10 text-orange-400'
                  }`}>
                    {feature.severity}
                  </span>
                </div>
                <p className="text-sm text-zinc-400">{feature.desc}</p>
              </div>
            ))}
          </div>
          
          <div className="text-center mt-8">
            <Link 
              href="/patterns"
              className="inline-flex items-center gap-2 text-blue-400 hover:text-blue-300 transition-colors"
            >
              View all 150 patterns
              <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
                <path strokeLinecap="round" strokeLinejoin="round" d="M13.5 4.5L21 12m0 0l-7.5 7.5M21 12H3" />
              </svg>
            </Link>
          </div>
        </div>
      </section>

      {/* CLI Section */}
      <section className="max-w-6xl mx-auto px-6 py-20">
        <div className="grid lg:grid-cols-2 gap-12 items-center">
          <div>
            <h2 className="text-3xl font-bold mb-4">Powerful CLI</h2>
            <p className="text-zinc-400 mb-6">
              Full-featured command-line tool for integrating security audits into your workflow. 
              Supports CI/CD, GitHub integration, and watch mode for development.
            </p>
            <div className="space-y-3">
              {[
                'Audit local programs or GitHub repos',
                'CI/CD integration with SARIF output',
                'Watch mode for real-time scanning',
                'GitHub PR security checks',
              ].map((item, i) => (
                <div key={i} className="flex items-center gap-3 text-zinc-300">
                  <svg className="w-5 h-5 text-emerald-400 flex-shrink-0" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
                    <path strokeLinecap="round" strokeLinejoin="round" d="M9 12.75L11.25 15 15 9.75M21 12a9 9 0 11-18 0 9 9 0 0118 0z" />
                  </svg>
                  {item}
                </div>
              ))}
            </div>
          </div>
          
          <div className="bg-zinc-900 border border-zinc-800 rounded-2xl overflow-hidden">
            <div className="flex items-center gap-2 px-4 py-3 bg-zinc-800/50 border-b border-zinc-800">
              <div className="flex gap-1.5">
                <div className="w-3 h-3 rounded-full bg-red-500/80"></div>
                <div className="w-3 h-3 rounded-full bg-yellow-500/80"></div>
                <div className="w-3 h-3 rounded-full bg-green-500/80"></div>
              </div>
              <span className="ml-2 text-zinc-500 text-sm">Terminal</span>
            </div>
            <pre className="p-6 text-sm text-zinc-300 overflow-x-auto">
<code>{`$ npx solshield audit ./my-program

  Scanning 12 files...

  ✗ Critical: Missing signer check (SOL002)
    └─ src/lib.rs:47

  ✗ High: Integer overflow possible (SOL003)
    └─ src/lib.rs:52

  Found 2 issues (1 critical, 1 high)

$ npx solshield github coral-xyz/anchor
  Cloning... Analyzing... Done!

$ npx solshield ci . --fail-on high
  SARIF output: results.sarif`}</code>
            </pre>
          </div>
        </div>
      </section>

      {/* Footer */}
      <footer className="border-t border-zinc-800/50">
        <div className="max-w-6xl mx-auto px-6 py-12">
          <div className="flex flex-col md:flex-row items-center justify-between gap-6">
            <div className="flex items-center gap-3">
              <div className="w-8 h-8 rounded-lg bg-gradient-to-br from-blue-500 to-cyan-400 flex items-center justify-center">
                <svg className="w-5 h-5 text-white" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
                  <path strokeLinecap="round" strokeLinejoin="round" d="M9 12.75L11.25 15 15 9.75m-3-7.036A11.959 11.959 0 013.598 6 11.99 11.99 0 003 9.749c0 5.592 3.824 10.29 9 11.623 5.176-1.332 9-6.03 9-11.622 0-1.31-.21-2.571-.598-3.751h-.152c-3.196 0-6.1-1.248-8.25-3.285z" />
                </svg>
              </div>
              <span className="font-semibold">SolShield</span>
            </div>
            
            <div className="flex items-center gap-6 text-sm text-zinc-500">
              <span>Built by Midir for Solana Agent Hackathon 2026</span>
              <a 
                href="https://github.com/oh-ashen-one/solshield"
                target="_blank"
                rel="noopener noreferrer"
                className="hover:text-white transition-colors"
              >
                GitHub
              </a>
            </div>
          </div>
        </div>
      </footer>
    </div>
  );
}
