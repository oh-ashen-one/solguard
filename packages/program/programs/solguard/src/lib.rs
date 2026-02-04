use anchor_lang::prelude::*;

declare_id!("SolShield AI1111111111111111111111111111111111");

/// SolShield AI - On-Chain Audit Registry for Solana Programs
/// 
/// Features:
/// - Store audit results as PDAs keyed by program_id
/// - Verified auditor registry with reputation scores
/// - CPI verification for other programs to check audit status
/// - Audit history and versioning
/// - Dispute mechanism for challenging findings

#[program]
pub mod SolShield AI {
    use super::*;

    /// Register a new audit for a program
    pub fn create_audit(
        ctx: Context<CreateAudit>,
        program_id: Pubkey,
        findings_hash: [u8; 32],
        severity_score: u8,
        critical_count: u8,
        high_count: u8,
        medium_count: u8,
        low_count: u8,
        passed: bool,
    ) -> Result<()> {
        let audit = &mut ctx.accounts.audit;
        let clock = Clock::get()?;
        
        audit.program_id = program_id;
        audit.auditor = ctx.accounts.auditor.key();
        audit.timestamp = clock.unix_timestamp;
        audit.findings_hash = findings_hash;
        audit.severity_score = severity_score;
        audit.critical_count = critical_count;
        audit.high_count = high_count;
        audit.medium_count = medium_count;
        audit.low_count = low_count;
        audit.passed = passed;
        audit.version = 1;
        audit.bump = ctx.bumps.audit;
        
        emit!(AuditCreated {
            program_id,
            auditor: ctx.accounts.auditor.key(),
            passed,
            severity_score,
            timestamp: clock.unix_timestamp,
        });
        
        Ok(())
    }

    /// Verify if a program has a passing audit
    /// Can be called via CPI by other programs
    pub fn verify_audit(ctx: Context<VerifyAudit>) -> Result<bool> {
        let audit = &ctx.accounts.audit;
        
        emit!(AuditVerified {
            program_id: audit.program_id,
            passed: audit.passed,
            verifier: ctx.accounts.verifier.key(),
        });
        
        Ok(audit.passed)
    }

    /// Update registry stats (admin only)
    pub fn initialize_registry(ctx: Context<InitializeRegistry>) -> Result<()> {
        let registry = &mut ctx.accounts.registry;
        registry.authority = ctx.accounts.authority.key();
        registry.total_audits = 0;
        registry.programs_audited = 0;
        registry.bump = ctx.bumps.registry;
        Ok(())
    }

    /// Increment registry counters after audit
    pub fn increment_registry(ctx: Context<IncrementRegistry>) -> Result<()> {
        let registry = &mut ctx.accounts.registry;
        registry.total_audits = registry.total_audits.checked_add(1).unwrap();
        // programs_audited only increments for first audit of a program
        // (would need additional tracking for accurate count)
        Ok(())
    }

    /// Update an existing audit (re-audit after code changes)
    pub fn update_audit(
        ctx: Context<UpdateAudit>,
        findings_hash: [u8; 32],
        severity_score: u8,
        critical_count: u8,
        high_count: u8,
        medium_count: u8,
        low_count: u8,
        passed: bool,
    ) -> Result<()> {
        let audit = &mut ctx.accounts.audit;
        let clock = Clock::get()?;
        
        // Store previous version info in history
        let history = &mut ctx.accounts.audit_history;
        history.audit = audit.key();
        history.version = audit.version;
        history.previous_hash = audit.findings_hash;
        history.previous_score = audit.severity_score;
        history.previous_passed = audit.passed;
        history.timestamp = audit.timestamp;
        history.bump = ctx.bumps.audit_history;
        
        // Update current audit
        audit.findings_hash = findings_hash;
        audit.severity_score = severity_score;
        audit.critical_count = critical_count;
        audit.high_count = high_count;
        audit.medium_count = medium_count;
        audit.low_count = low_count;
        audit.passed = passed;
        audit.timestamp = clock.unix_timestamp;
        audit.version = audit.version.checked_add(1).unwrap_or(255);
        
        emit!(AuditUpdated {
            program_id: audit.program_id,
            auditor: ctx.accounts.auditor.key(),
            passed,
            severity_score,
            version: audit.version,
            timestamp: clock.unix_timestamp,
        });
        
        Ok(())
    }

    /// Register a verified auditor
    pub fn register_auditor(
        ctx: Context<RegisterAuditor>,
        name: String,
        website: String,
    ) -> Result<()> {
        require!(name.len() <= 32, SolShield AIError::NameTooLong);
        require!(website.len() <= 64, SolShield AIError::WebsiteTooLong);
        
        let auditor = &mut ctx.accounts.auditor_profile;
        auditor.authority = ctx.accounts.authority.key();
        auditor.audits_performed = 0;
        auditor.reputation_score = 100; // Start at 100, can go up or down
        auditor.is_verified = false; // Needs admin verification
        auditor.registered_at = Clock::get()?.unix_timestamp;
        auditor.bump = ctx.bumps.auditor_profile;
        
        // Copy name and website
        let name_bytes = name.as_bytes();
        auditor.name[..name_bytes.len()].copy_from_slice(name_bytes);
        auditor.name_len = name_bytes.len() as u8;
        
        let website_bytes = website.as_bytes();
        auditor.website[..website_bytes.len()].copy_from_slice(website_bytes);
        auditor.website_len = website_bytes.len() as u8;
        
        emit!(AuditorRegistered {
            authority: ctx.accounts.authority.key(),
            name,
        });
        
        Ok(())
    }

    /// Admin verifies an auditor
    pub fn verify_auditor(ctx: Context<VerifyAuditor>) -> Result<()> {
        let auditor = &mut ctx.accounts.auditor_profile;
        auditor.is_verified = true;
        
        emit!(AuditorVerified {
            auditor: auditor.authority,
        });
        
        Ok(())
    }

    /// File a dispute against an audit
    pub fn create_dispute(
        ctx: Context<CreateDispute>,
        reason: String,
        evidence_hash: [u8; 32],
    ) -> Result<()> {
        require!(reason.len() <= 256, SolShield AIError::ReasonTooLong);
        
        let dispute = &mut ctx.accounts.dispute;
        let clock = Clock::get()?;
        
        dispute.audit = ctx.accounts.audit.key();
        dispute.disputer = ctx.accounts.disputer.key();
        dispute.timestamp = clock.unix_timestamp;
        dispute.evidence_hash = evidence_hash;
        dispute.status = DisputeStatus::Pending;
        dispute.bump = ctx.bumps.dispute;
        
        // Copy reason
        let reason_bytes = reason.as_bytes();
        dispute.reason[..reason_bytes.len()].copy_from_slice(reason_bytes);
        dispute.reason_len = reason_bytes.len() as u16;
        
        emit!(DisputeCreated {
            audit: ctx.accounts.audit.key(),
            disputer: ctx.accounts.disputer.key(),
            timestamp: clock.unix_timestamp,
        });
        
        Ok(())
    }

    /// Resolve a dispute (admin only)
    pub fn resolve_dispute(
        ctx: Context<ResolveDispute>,
        upheld: bool,
        resolution_notes_hash: [u8; 32],
    ) -> Result<()> {
        let dispute = &mut ctx.accounts.dispute;
        
        dispute.status = if upheld {
            DisputeStatus::Upheld
        } else {
            DisputeStatus::Rejected
        };
        dispute.resolution_hash = resolution_notes_hash;
        dispute.resolved_at = Clock::get()?.unix_timestamp;
        
        // If dispute upheld, invalidate the audit
        if upheld {
            let audit = &mut ctx.accounts.audit;
            audit.passed = false;
            audit.severity_score = 100; // Max severity = invalidated
        }
        
        emit!(DisputeResolved {
            audit: ctx.accounts.audit.key(),
            upheld,
            resolver: ctx.accounts.resolver.key(),
        });
        
        Ok(())
    }
}

#[derive(Accounts)]
#[instruction(program_id: Pubkey)]
pub struct CreateAudit<'info> {
    #[account(
        init,
        payer = auditor,
        space = 8 + AuditReport::INIT_SPACE,
        seeds = [b"audit", program_id.as_ref()],
        bump
    )]
    pub audit: Account<'info, AuditReport>,
    
    #[account(mut)]
    pub auditor: Signer<'info>,
    
    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
pub struct VerifyAudit<'info> {
    #[account(
        seeds = [b"audit", audit.program_id.as_ref()],
        bump = audit.bump
    )]
    pub audit: Account<'info, AuditReport>,
    
    /// Anyone can verify
    pub verifier: Signer<'info>,
}

#[derive(Accounts)]
pub struct InitializeRegistry<'info> {
    #[account(
        init,
        payer = authority,
        space = 8 + AuditRegistry::INIT_SPACE,
        seeds = [b"registry"],
        bump
    )]
    pub registry: Account<'info, AuditRegistry>,
    
    #[account(mut)]
    pub authority: Signer<'info>,
    
    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
pub struct IncrementRegistry<'info> {
    #[account(
        mut,
        seeds = [b"registry"],
        bump = registry.bump,
        has_one = authority
    )]
    pub registry: Account<'info, AuditRegistry>,
    
    pub authority: Signer<'info>,
}

#[derive(Accounts)]
pub struct UpdateAudit<'info> {
    #[account(
        mut,
        seeds = [b"audit", audit.program_id.as_ref()],
        bump = audit.bump,
        has_one = auditor
    )]
    pub audit: Account<'info, AuditReport>,
    
    #[account(
        init,
        payer = auditor,
        space = 8 + AuditHistory::INIT_SPACE,
        seeds = [b"history", audit.key().as_ref(), &[audit.version]],
        bump
    )]
    pub audit_history: Account<'info, AuditHistory>,
    
    #[account(mut)]
    pub auditor: Signer<'info>,
    
    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
pub struct RegisterAuditor<'info> {
    #[account(
        init,
        payer = authority,
        space = 8 + AuditorProfile::INIT_SPACE,
        seeds = [b"auditor", authority.key().as_ref()],
        bump
    )]
    pub auditor_profile: Account<'info, AuditorProfile>,
    
    #[account(mut)]
    pub authority: Signer<'info>,
    
    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
pub struct VerifyAuditor<'info> {
    #[account(
        mut,
        seeds = [b"auditor", auditor_profile.authority.as_ref()],
        bump = auditor_profile.bump
    )]
    pub auditor_profile: Account<'info, AuditorProfile>,
    
    #[account(
        seeds = [b"registry"],
        bump = registry.bump,
        has_one = authority
    )]
    pub registry: Account<'info, AuditRegistry>,
    
    pub authority: Signer<'info>,
}

#[derive(Accounts)]
#[instruction(reason: String, evidence_hash: [u8; 32])]
pub struct CreateDispute<'info> {
    #[account(
        seeds = [b"audit", audit.program_id.as_ref()],
        bump = audit.bump
    )]
    pub audit: Account<'info, AuditReport>,
    
    #[account(
        init,
        payer = disputer,
        space = 8 + Dispute::INIT_SPACE,
        seeds = [b"dispute", audit.key().as_ref(), disputer.key().as_ref()],
        bump
    )]
    pub dispute: Account<'info, Dispute>,
    
    #[account(mut)]
    pub disputer: Signer<'info>,
    
    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
pub struct ResolveDispute<'info> {
    #[account(
        mut,
        seeds = [b"audit", audit.program_id.as_ref()],
        bump = audit.bump
    )]
    pub audit: Account<'info, AuditReport>,
    
    #[account(
        mut,
        seeds = [b"dispute", audit.key().as_ref(), dispute.disputer.as_ref()],
        bump = dispute.bump
    )]
    pub dispute: Account<'info, Dispute>,
    
    #[account(
        seeds = [b"registry"],
        bump = registry.bump,
        has_one = authority
    )]
    pub registry: Account<'info, AuditRegistry>,
    
    #[account(constraint = resolver.key() == registry.authority)]
    pub resolver: Signer<'info>,
    
    pub authority: Signer<'info>,
}

#[account]
#[derive(InitSpace)]
pub struct AuditReport {
    /// The program that was audited
    pub program_id: Pubkey,
    /// The agent/account that performed the audit
    pub auditor: Pubkey,
    /// Unix timestamp of the audit
    pub timestamp: i64,
    /// SHA256 hash of the full findings JSON
    pub findings_hash: [u8; 32],
    /// Overall severity score (0-100, lower is better)
    pub severity_score: u8,
    /// Count of critical findings
    pub critical_count: u8,
    /// Count of high severity findings
    pub high_count: u8,
    /// Count of medium severity findings
    pub medium_count: u8,
    /// Count of low severity findings
    pub low_count: u8,
    /// Whether the audit passed (no critical/high issues)
    pub passed: bool,
    /// Audit version (for future upgrades)
    pub version: u8,
    /// PDA bump
    pub bump: u8,
}

#[account]
#[derive(InitSpace)]
pub struct AuditRegistry {
    /// Registry admin
    pub authority: Pubkey,
    /// Total audits performed
    pub total_audits: u64,
    /// Unique programs audited
    pub programs_audited: u64,
    /// PDA bump
    pub bump: u8,
}

#[account]
#[derive(InitSpace)]
pub struct AuditHistory {
    /// The audit this history belongs to
    pub audit: Pubkey,
    /// Version number at time of snapshot
    pub version: u8,
    /// Previous findings hash
    pub previous_hash: [u8; 32],
    /// Previous severity score
    pub previous_score: u8,
    /// Previous passed status
    pub previous_passed: bool,
    /// Timestamp of the previous audit
    pub timestamp: i64,
    /// PDA bump
    pub bump: u8,
}

#[account]
#[derive(InitSpace)]
pub struct AuditorProfile {
    /// The auditor's authority (wallet)
    pub authority: Pubkey,
    /// Total audits performed by this auditor
    pub audits_performed: u64,
    /// Reputation score (0-1000, higher is better)
    pub reputation_score: u16,
    /// Whether admin has verified this auditor
    pub is_verified: bool,
    /// When the auditor registered
    pub registered_at: i64,
    /// Auditor name (max 32 bytes)
    #[max_len(32)]
    pub name: [u8; 32],
    pub name_len: u8,
    /// Website URL (max 64 bytes)
    #[max_len(64)]
    pub website: [u8; 64],
    pub website_len: u8,
    /// PDA bump
    pub bump: u8,
}

#[account]
#[derive(InitSpace)]
pub struct Dispute {
    /// The audit being disputed
    pub audit: Pubkey,
    /// Who filed the dispute
    pub disputer: Pubkey,
    /// When dispute was filed
    pub timestamp: i64,
    /// Hash of evidence/proof
    pub evidence_hash: [u8; 32],
    /// Dispute status
    pub status: DisputeStatus,
    /// Reason for dispute (max 256 bytes)
    #[max_len(256)]
    pub reason: [u8; 256],
    pub reason_len: u16,
    /// Resolution notes hash (set when resolved)
    pub resolution_hash: [u8; 32],
    /// When dispute was resolved
    pub resolved_at: i64,
    /// PDA bump
    pub bump: u8,
}

#[derive(AnchorSerialize, AnchorDeserialize, Clone, Copy, PartialEq, Eq, InitSpace)]
pub enum DisputeStatus {
    Pending,
    Upheld,
    Rejected,
}

#[error_code]
pub enum SolShield AIError {
    #[msg("Auditor name exceeds 32 characters")]
    NameTooLong,
    #[msg("Website URL exceeds 64 characters")]
    WebsiteTooLong,
    #[msg("Dispute reason exceeds 256 characters")]
    ReasonTooLong,
}

#[event]
pub struct AuditCreated {
    pub program_id: Pubkey,
    pub auditor: Pubkey,
    pub passed: bool,
    pub severity_score: u8,
    pub timestamp: i64,
}

#[event]
pub struct AuditUpdated {
    pub program_id: Pubkey,
    pub auditor: Pubkey,
    pub passed: bool,
    pub severity_score: u8,
    pub version: u8,
    pub timestamp: i64,
}

#[event]
pub struct AuditVerified {
    pub program_id: Pubkey,
    pub passed: bool,
    pub verifier: Pubkey,
}

#[event]
pub struct AuditorRegistered {
    pub authority: Pubkey,
    pub name: String,
}

#[event]
pub struct AuditorVerified {
    pub auditor: Pubkey,
}

#[event]
pub struct DisputeCreated {
    pub audit: Pubkey,
    pub disputer: Pubkey,
    pub timestamp: i64,
}

#[event]
pub struct DisputeResolved {
    pub audit: Pubkey,
    pub upheld: bool,
    pub resolver: Pubkey,
}
