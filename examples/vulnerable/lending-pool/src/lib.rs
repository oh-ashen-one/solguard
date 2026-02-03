use anchor_lang::prelude::*;
use anchor_spl::token::{self, Token, TokenAccount, Transfer};

declare_id!("LendXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX");

/// VULNERABLE LENDING POOL
/// This program contains multiple intentional vulnerabilities for testing SolGuard.
/// DO NOT use in production!

#[program]
pub mod lending_pool {
    use super::*;

    /// Initialize the lending pool
    /// VULNERABILITY: SOL065 - Initialization Frontrun
    /// Anyone can call this and become the admin
    pub fn initialize(ctx: Context<Initialize>) -> Result<()> {
        let pool = &mut ctx.accounts.pool;
        pool.admin = ctx.accounts.admin.key();
        pool.total_deposits = 0;
        pool.total_borrows = 0;
        Ok(())
    }

    /// Deposit tokens into the pool
    /// VULNERABILITY: SOL003 - Integer Overflow
    pub fn deposit(ctx: Context<Deposit>, amount: u64) -> Result<()> {
        let pool = &mut ctx.accounts.pool;
        
        // BUG: Unchecked addition can overflow
        pool.total_deposits = pool.total_deposits + amount;
        
        token::transfer(
            CpiContext::new(
                ctx.accounts.token_program.to_account_info(),
                Transfer {
                    from: ctx.accounts.user_token.to_account_info(),
                    to: ctx.accounts.pool_token.to_account_info(),
                    authority: ctx.accounts.user.to_account_info(),
                },
            ),
            amount,
        )?;
        
        Ok(())
    }

    /// Borrow tokens from the pool
    /// VULNERABILITY: SOL005 - Authority Bypass
    /// VULNERABILITY: SOL018 - Oracle Manipulation (no price check)
    pub fn borrow(ctx: Context<Borrow>, amount: u64) -> Result<()> {
        let pool = &mut ctx.accounts.pool;
        
        // BUG: No collateral check!
        // BUG: No price oracle validation!
        
        pool.total_borrows = pool.total_borrows + amount;
        
        // BUG: Using pool seeds without proper validation
        let seeds = &[b"pool".as_ref(), &[ctx.accounts.pool.bump]];
        let signer = &[&seeds[..]];
        
        token::transfer(
            CpiContext::new_with_signer(
                ctx.accounts.token_program.to_account_info(),
                Transfer {
                    from: ctx.accounts.pool_token.to_account_info(),
                    to: ctx.accounts.user_token.to_account_info(),
                    authority: ctx.accounts.pool.to_account_info(),
                },
                signer,
            ),
            amount,
        )?;
        
        Ok(())
    }

    /// Liquidate an underwater position
    /// VULNERABILITY: SOL019 - Flash Loan Vulnerability
    /// VULNERABILITY: SOL062 - Sandwich Attack possible
    pub fn liquidate(ctx: Context<Liquidate>) -> Result<()> {
        // BUG: Price can be manipulated in same transaction
        let price = ctx.accounts.oracle.price;
        
        // BUG: No staleness check on oracle
        let collateral_value = ctx.accounts.position.collateral * price;
        let debt_value = ctx.accounts.position.debt * price;
        
        // BUG: Using spot price for liquidation threshold
        if collateral_value < debt_value * 150 / 100 {
            // Liquidate...
        }
        
        Ok(())
    }

    /// Withdraw tokens
    /// VULNERABILITY: SOL002 - Missing Signer Check
    /// VULNERABILITY: SOL011 - Reentrancy Risk
    pub fn withdraw(ctx: Context<Withdraw>, amount: u64) -> Result<()> {
        let pool = &mut ctx.accounts.pool;
        
        // BUG: State change AFTER external call (reentrancy)
        token::transfer(
            CpiContext::new_with_signer(
                ctx.accounts.token_program.to_account_info(),
                Transfer {
                    from: ctx.accounts.pool_token.to_account_info(),
                    to: ctx.accounts.user_token.to_account_info(),
                    authority: ctx.accounts.pool.to_account_info(),
                },
                &[&[b"pool".as_ref(), &[pool.bump]]],
            ),
            amount,
        )?;
        
        // BUG: This should happen BEFORE the transfer
        pool.total_deposits = pool.total_deposits - amount;
        
        Ok(())
    }

    /// Update admin
    /// VULNERABILITY: SOL032 - Missing Time Lock
    pub fn update_admin(ctx: Context<UpdateAdmin>, new_admin: Pubkey) -> Result<()> {
        // BUG: No timelock, immediate effect
        ctx.accounts.pool.admin = new_admin;
        Ok(())
    }
}

#[derive(Accounts)]
pub struct Initialize<'info> {
    #[account(init, payer = admin, space = 8 + Pool::INIT_SPACE)]
    pub pool: Account<'info, Pool>,
    
    // VULNERABILITY: SOL002 - Should be Signer
    pub admin: AccountInfo<'info>,
    
    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
pub struct Deposit<'info> {
    #[account(mut)]
    pub pool: Account<'info, Pool>,
    
    #[account(mut)]
    pub user_token: Account<'info, TokenAccount>,
    
    #[account(mut)]
    pub pool_token: Account<'info, TokenAccount>,
    
    pub user: Signer<'info>,
    pub token_program: Program<'info, Token>,
}

#[derive(Accounts)]
pub struct Borrow<'info> {
    #[account(mut)]
    pub pool: Account<'info, Pool>,
    
    #[account(mut)]
    pub user_token: Account<'info, TokenAccount>,
    
    #[account(mut)]
    pub pool_token: Account<'info, TokenAccount>,
    
    // VULNERABILITY: SOL001 - Missing owner check on oracle
    pub oracle: AccountInfo<'info>,
    
    pub user: Signer<'info>,
    pub token_program: Program<'info, Token>,
}

#[derive(Accounts)]
pub struct Liquidate<'info> {
    #[account(mut)]
    pub pool: Account<'info, Pool>,
    
    #[account(mut)]
    pub position: Account<'info, Position>,
    
    // VULNERABILITY: No staleness check
    pub oracle: Account<'info, Oracle>,
    
    pub liquidator: Signer<'info>,
}

#[derive(Accounts)]
pub struct Withdraw<'info> {
    #[account(mut)]
    pub pool: Account<'info, Pool>,
    
    #[account(mut)]
    pub user_token: Account<'info, TokenAccount>,
    
    #[account(mut)]
    pub pool_token: Account<'info, TokenAccount>,
    
    // VULNERABILITY: SOL002 - Should verify this is the depositor
    pub authority: AccountInfo<'info>,
    
    pub token_program: Program<'info, Token>,
}

#[derive(Accounts)]
pub struct UpdateAdmin<'info> {
    #[account(mut, has_one = admin)]
    pub pool: Account<'info, Pool>,
    
    pub admin: Signer<'info>,
}

#[account]
#[derive(InitSpace)]
pub struct Pool {
    pub admin: Pubkey,
    pub total_deposits: u64,
    pub total_borrows: u64,
    pub bump: u8,
}

#[account]
#[derive(InitSpace)]
pub struct Position {
    pub owner: Pubkey,
    pub collateral: u64,
    pub debt: u64,
}

#[account]
#[derive(InitSpace)]
pub struct Oracle {
    pub price: u64,
    pub timestamp: i64,
}
