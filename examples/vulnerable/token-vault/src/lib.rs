//! Vulnerable Token Vault - Example for SolShield AI Testing
//! 
//! This program contains INTENTIONAL vulnerabilities for testing.
//! DO NOT use in production!
//! 
//! Vulnerabilities present:
//! - SOL001: Missing owner check
//! - SOL002: Missing signer check  
//! - SOL003: Integer overflow
//! - SOL005: Authority bypass
//! - SOL006: Missing init check
//! - SOL010: Account closing vulnerability
//! - SOL013: Duplicate mutable accounts
//! - SOL015: Type cosplay

use anchor_lang::prelude::*;
use anchor_spl::token::{self, Token, TokenAccount, Transfer};

declare_id!("VuLn1111111111111111111111111111111111111");

#[program]
pub mod vulnerable_vault {
    use super::*;

    /// Initialize vault - VULNERABLE: no init check
    pub fn initialize(ctx: Context<Initialize>) -> Result<()> {
        // SOL006: Missing is_initialized check - can be re-initialized!
        let vault = &mut ctx.accounts.vault;
        vault.authority = ctx.accounts.authority.key();
        vault.token_account = ctx.accounts.token_account.key();
        vault.total_deposited = 0;
        Ok(())
    }

    /// Deposit tokens - VULNERABLE: overflow + missing checks
    pub fn deposit(ctx: Context<Deposit>, amount: u64) -> Result<()> {
        let vault = &mut ctx.accounts.vault;
        
        // SOL003: Integer overflow - no checked_add!
        vault.total_deposited = vault.total_deposited + amount;
        
        // Transfer tokens
        let cpi_accounts = Transfer {
            from: ctx.accounts.user_token.to_account_info(),
            to: ctx.accounts.vault_token.to_account_info(),
            authority: ctx.accounts.user.to_account_info(),
        };
        let cpi_program = ctx.accounts.token_program.to_account_info();
        let cpi_ctx = CpiContext::new(cpi_program, cpi_accounts);
        token::transfer(cpi_ctx, amount)?;
        
        Ok(())
    }

    /// Withdraw tokens - VULNERABLE: missing signer check
    pub fn withdraw(ctx: Context<Withdraw>, amount: u64) -> Result<()> {
        let vault = &mut ctx.accounts.vault;
        
        // SOL002: Missing signer check on authority!
        // Anyone can call this if they know the authority pubkey
        
        // SOL003: Integer overflow on subtraction
        vault.total_deposited = vault.total_deposited - amount;
        
        // Transfer out
        let seeds = &[
            b"vault",
            vault.authority.as_ref(),
            &[ctx.bumps.vault],
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
        
        Ok(())
    }

    /// Emergency withdraw - VULNERABLE: authority bypass
    pub fn emergency_withdraw(ctx: Context<EmergencyWithdraw>) -> Result<()> {
        // SOL005: No authority check at all!
        // Anyone can drain the vault
        
        let vault = &ctx.accounts.vault;
        let amount = ctx.accounts.vault_token.amount;
        
        let seeds = &[
            b"vault", 
            vault.authority.as_ref(),
            &[ctx.bumps.vault],
        ];
        let signer = &[&seeds[..]];
        
        let cpi_accounts = Transfer {
            from: ctx.accounts.vault_token.to_account_info(),
            to: ctx.accounts.destination.to_account_info(),
            authority: ctx.accounts.vault.to_account_info(),
        };
        let cpi_ctx = CpiContext::new_with_signer(
            ctx.accounts.token_program.to_account_info(),
            cpi_accounts,
            signer,
        );
        token::transfer(cpi_ctx, amount)?;
        
        Ok(())
    }

    /// Close vault - VULNERABLE: account revival
    pub fn close_vault(ctx: Context<CloseVault>) -> Result<()> {
        // SOL010: Vulnerable to account revival attack
        // Data not zeroed before closing, lamports returned before data cleared
        
        let vault = &ctx.accounts.vault;
        let dest = &ctx.accounts.destination;
        
        // Transfer lamports
        **ctx.accounts.vault.to_account_info().try_borrow_mut_lamports()? = 0;
        **dest.to_account_info().try_borrow_mut_lamports()? += 
            ctx.accounts.vault.to_account_info().lamports();
        
        // Data NOT zeroed - can be revived!
        
        Ok(())
    }

    /// Transfer between accounts - VULNERABLE: duplicate mutable
    pub fn internal_transfer(
        ctx: Context<InternalTransfer>,
        amount: u64,
    ) -> Result<()> {
        // SOL013: from and to could be the same account!
        // No constraint ensuring they're different
        
        let from = &mut ctx.accounts.from_account;
        let to = &mut ctx.accounts.to_account;
        
        from.balance = from.balance - amount;
        to.balance = to.balance + amount;
        
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
    
    pub token_account: Account<'info, TokenAccount>,
    
    #[account(mut)]
    pub authority: Signer<'info>,
    
    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
pub struct Deposit<'info> {
    #[account(mut)]
    pub vault: Account<'info, Vault>,
    
    #[account(mut)]
    pub user_token: Account<'info, TokenAccount>,
    
    #[account(mut)]
    pub vault_token: Account<'info, TokenAccount>,
    
    pub user: Signer<'info>,
    
    pub token_program: Program<'info, Token>,
}

#[derive(Accounts)]
pub struct Withdraw<'info> {
    #[account(
        mut,
        seeds = [b"vault", vault.authority.as_ref()],
        bump
    )]
    pub vault: Account<'info, Vault>,
    
    #[account(mut)]
    pub vault_token: Account<'info, TokenAccount>,
    
    #[account(mut)]
    pub user_token: Account<'info, TokenAccount>,
    
    // SOL002: Should be Signer<'info>!
    /// CHECK: Intentionally vulnerable - not a signer
    pub authority: AccountInfo<'info>,
    
    pub token_program: Program<'info, Token>,
}

#[derive(Accounts)]
pub struct EmergencyWithdraw<'info> {
    #[account(
        seeds = [b"vault", vault.authority.as_ref()],
        bump
    )]
    pub vault: Account<'info, Vault>,
    
    #[account(mut)]
    pub vault_token: Account<'info, TokenAccount>,
    
    #[account(mut)]
    pub destination: Account<'info, TokenAccount>,
    
    // SOL005: No authority check!
    /// CHECK: Anyone can call this
    pub caller: AccountInfo<'info>,
    
    pub token_program: Program<'info, Token>,
}

#[derive(Accounts)]
pub struct CloseVault<'info> {
    #[account(mut)]
    pub vault: Account<'info, Vault>,
    
    /// CHECK: Destination for rent
    #[account(mut)]
    pub destination: AccountInfo<'info>,
    
    pub authority: Signer<'info>,
}

#[derive(Accounts)]
pub struct InternalTransfer<'info> {
    // SOL013: No constraint that from != to!
    #[account(mut)]
    pub from_account: Account<'info, UserBalance>,
    
    #[account(mut)]
    pub to_account: Account<'info, UserBalance>,
    
    pub authority: Signer<'info>,
}

#[account]
#[derive(InitSpace)]
pub struct Vault {
    pub authority: Pubkey,
    pub token_account: Pubkey,
    pub total_deposited: u64,
}

#[account]
#[derive(InitSpace)]
pub struct UserBalance {
    pub owner: Pubkey,
    pub balance: u64,
}
