//! Safe Token Vault - Secure Reference Implementation
//! 
//! This program demonstrates SECURE patterns that SolShield AI validates.
//! Use this as a reference for writing secure Solana programs.
//! 
//! Security measures:
//! - All authorities are Signers
//! - Checked arithmetic throughout
//! - Proper initialization guards
//! - Account constraints validated
//! - Safe account closing

use anchor_lang::prelude::*;
use anchor_spl::token::{self, Token, TokenAccount, Transfer};

declare_id!("SaFe1111111111111111111111111111111111111");

#[program]
pub mod safe_vault {
    use super::*;

    /// Initialize vault - SECURE: proper init guard
    pub fn initialize(ctx: Context<Initialize>) -> Result<()> {
        let vault = &mut ctx.accounts.vault;
        
        // Already guaranteed by Anchor's init constraint
        // But we add explicit state tracking for defense-in-depth
        require!(!vault.is_initialized, VaultError::AlreadyInitialized);
        
        vault.authority = ctx.accounts.authority.key();
        vault.token_account = ctx.accounts.token_account.key();
        vault.total_deposited = 0;
        vault.is_initialized = true;
        vault.bump = ctx.bumps.vault;
        
        emit!(VaultInitialized {
            vault: vault.key(),
            authority: ctx.accounts.authority.key(),
        });
        
        Ok(())
    }

    /// Deposit tokens - SECURE: checked arithmetic + validation
    pub fn deposit(ctx: Context<Deposit>, amount: u64) -> Result<()> {
        require!(amount > 0, VaultError::InvalidAmount);
        
        let vault = &mut ctx.accounts.vault;
        
        // SECURE: Use checked_add to prevent overflow
        vault.total_deposited = vault.total_deposited
            .checked_add(amount)
            .ok_or(VaultError::Overflow)?;
        
        // Transfer tokens
        let cpi_accounts = Transfer {
            from: ctx.accounts.user_token.to_account_info(),
            to: ctx.accounts.vault_token.to_account_info(),
            authority: ctx.accounts.user.to_account_info(),
        };
        let cpi_ctx = CpiContext::new(
            ctx.accounts.token_program.to_account_info(),
            cpi_accounts,
        );
        token::transfer(cpi_ctx, amount)?;
        
        emit!(Deposited {
            vault: vault.key(),
            user: ctx.accounts.user.key(),
            amount,
        });
        
        Ok(())
    }

    /// Withdraw tokens - SECURE: proper signer check
    pub fn withdraw(ctx: Context<Withdraw>, amount: u64) -> Result<()> {
        require!(amount > 0, VaultError::InvalidAmount);
        
        let vault = &mut ctx.accounts.vault;
        
        // SECURE: Authority is a Signer (enforced by Anchor)
        // SECURE: has_one = authority constraint validates
        
        // SECURE: Use checked_sub to prevent underflow
        vault.total_deposited = vault.total_deposited
            .checked_sub(amount)
            .ok_or(VaultError::InsufficientFunds)?;
        
        // Transfer out using vault PDA authority
        let authority_key = vault.authority;
        let seeds = &[
            b"vault",
            authority_key.as_ref(),
            &[vault.bump],
        ];
        let signer = &[&seeds[..]];
        
        let cpi_accounts = Transfer {
            from: ctx.accounts.vault_token.to_account_info(),
            to: ctx.accounts.user_token.to_account_info(),
            authority: ctx.accounts.vault.to_account_info(),
        };
        let cpi_ctx = CpiContext::new_with_signer(
            ctx.accounts.token_program.to_account_info(),
            cpi_accounts,
            signer,
        );
        token::transfer(cpi_ctx, amount)?;
        
        emit!(Withdrawn {
            vault: vault.key(),
            user: ctx.accounts.authority.key(),
            amount,
        });
        
        Ok(())
    }

    /// Close vault - SECURE: proper account closing
    pub fn close_vault(ctx: Context<CloseVault>) -> Result<()> {
        // SECURE: Anchor's close constraint handles:
        // 1. Zero out account data
        // 2. Transfer lamports to destination
        // 3. Set owner to system program
        
        // Additional check: ensure vault is empty
        require!(
            ctx.accounts.vault_token.amount == 0,
            VaultError::VaultNotEmpty
        );
        
        emit!(VaultClosed {
            vault: ctx.accounts.vault.key(),
            authority: ctx.accounts.authority.key(),
        });
        
        Ok(())
    }

    /// Transfer between accounts - SECURE: duplicate check
    pub fn internal_transfer(
        ctx: Context<InternalTransfer>,
        amount: u64,
    ) -> Result<()> {
        require!(amount > 0, VaultError::InvalidAmount);
        
        // SECURE: Constraint ensures from != to
        // (enforced by Anchor constraint below)
        
        let from = &mut ctx.accounts.from_account;
        let to = &mut ctx.accounts.to_account;
        
        // SECURE: Checked arithmetic
        from.balance = from.balance
            .checked_sub(amount)
            .ok_or(VaultError::InsufficientFunds)?;
        
        to.balance = to.balance
            .checked_add(amount)
            .ok_or(VaultError::Overflow)?;
        
        Ok(())
    }
}

#[derive(Accounts)]
pub struct Initialize<'info> {
    #[account(
        init,
        payer = authority,
        space = 8 + Vault::INIT_SPACE,
        seeds = [b"vault", authority.key().as_ref()],
        bump
    )]
    pub vault: Account<'info, Vault>,
    
    #[account(
        constraint = token_account.owner == vault.key() @ VaultError::InvalidTokenOwner
    )]
    pub token_account: Account<'info, TokenAccount>,
    
    #[account(mut)]
    pub authority: Signer<'info>,
    
    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
pub struct Deposit<'info> {
    #[account(
        mut,
        seeds = [b"vault", vault.authority.as_ref()],
        bump = vault.bump,
        constraint = vault.is_initialized @ VaultError::NotInitialized
    )]
    pub vault: Account<'info, Vault>,
    
    #[account(
        mut,
        constraint = user_token.owner == user.key() @ VaultError::InvalidTokenOwner
    )]
    pub user_token: Account<'info, TokenAccount>,
    
    #[account(
        mut,
        constraint = vault_token.key() == vault.token_account @ VaultError::InvalidVaultToken
    )]
    pub vault_token: Account<'info, TokenAccount>,
    
    pub user: Signer<'info>,
    
    pub token_program: Program<'info, Token>,
}

#[derive(Accounts)]
pub struct Withdraw<'info> {
    #[account(
        mut,
        seeds = [b"vault", vault.authority.as_ref()],
        bump = vault.bump,
        has_one = authority @ VaultError::InvalidAuthority,
        constraint = vault.is_initialized @ VaultError::NotInitialized
    )]
    pub vault: Account<'info, Vault>,
    
    #[account(
        mut,
        constraint = vault_token.key() == vault.token_account @ VaultError::InvalidVaultToken
    )]
    pub vault_token: Account<'info, TokenAccount>,
    
    #[account(mut)]
    pub user_token: Account<'info, TokenAccount>,
    
    // SECURE: Authority must be a Signer!
    pub authority: Signer<'info>,
    
    pub token_program: Program<'info, Token>,
}

#[derive(Accounts)]
pub struct CloseVault<'info> {
    #[account(
        mut,
        seeds = [b"vault", vault.authority.as_ref()],
        bump = vault.bump,
        has_one = authority @ VaultError::InvalidAuthority,
        close = authority  // SECURE: Proper close with data zeroing
    )]
    pub vault: Account<'info, Vault>,
    
    #[account(
        constraint = vault_token.key() == vault.token_account @ VaultError::InvalidVaultToken
    )]
    pub vault_token: Account<'info, TokenAccount>,
    
    #[account(mut)]
    pub authority: Signer<'info>,
}

#[derive(Accounts)]
pub struct InternalTransfer<'info> {
    // SECURE: Constraint ensures accounts are different!
    #[account(
        mut,
        constraint = from_account.key() != to_account.key() @ VaultError::SameAccount
    )]
    pub from_account: Account<'info, UserBalance>,
    
    #[account(mut)]
    pub to_account: Account<'info, UserBalance>,
    
    #[account(
        constraint = authority.key() == from_account.owner @ VaultError::InvalidAuthority
    )]
    pub authority: Signer<'info>,
}

#[account]
#[derive(InitSpace)]
pub struct Vault {
    pub authority: Pubkey,
    pub token_account: Pubkey,
    pub total_deposited: u64,
    pub is_initialized: bool,
    pub bump: u8,
}

#[account]
#[derive(InitSpace)]
pub struct UserBalance {
    pub owner: Pubkey,
    pub balance: u64,
}

#[error_code]
pub enum VaultError {
    #[msg("Vault is already initialized")]
    AlreadyInitialized,
    #[msg("Vault is not initialized")]
    NotInitialized,
    #[msg("Invalid amount")]
    InvalidAmount,
    #[msg("Arithmetic overflow")]
    Overflow,
    #[msg("Insufficient funds")]
    InsufficientFunds,
    #[msg("Invalid authority")]
    InvalidAuthority,
    #[msg("Invalid token account owner")]
    InvalidTokenOwner,
    #[msg("Invalid vault token account")]
    InvalidVaultToken,
    #[msg("Vault must be empty before closing")]
    VaultNotEmpty,
    #[msg("From and To accounts must be different")]
    SameAccount,
}

#[event]
pub struct VaultInitialized {
    pub vault: Pubkey,
    pub authority: Pubkey,
}

#[event]
pub struct Deposited {
    pub vault: Pubkey,
    pub user: Pubkey,
    pub amount: u64,
}

#[event]
pub struct Withdrawn {
    pub vault: Pubkey,
    pub user: Pubkey,
    pub amount: u64,
}

#[event]
pub struct VaultClosed {
    pub vault: Pubkey,
    pub authority: Pubkey,
}
