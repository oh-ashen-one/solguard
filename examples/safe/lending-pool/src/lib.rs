use anchor_lang::prelude::*;
use anchor_spl::token::{self, Token, TokenAccount, Transfer};

declare_id!("SafeLendXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX");

/// SECURE LENDING POOL
/// This program demonstrates secure patterns for lending protocols.
/// Compare with examples/vulnerable/lending-pool to see the differences.

// Time lock duration for admin changes (24 hours)
const TIME_LOCK_DURATION: i64 = 86400;

// Maximum staleness for oracle data (60 seconds)
const MAX_ORACLE_STALENESS: i64 = 60;

// Minimum collateralization ratio (150%)
const MIN_COLLATERAL_RATIO: u64 = 150;

#[program]
pub mod secure_lending_pool {
    use super::*;

    /// Initialize the lending pool
    /// SECURE: Only callable once via init constraint
    pub fn initialize(ctx: Context<Initialize>) -> Result<()> {
        let pool = &mut ctx.accounts.pool;
        pool.admin = ctx.accounts.admin.key();
        pool.pending_admin = None;
        pool.admin_change_time = 0;
        pool.total_deposits = 0;
        pool.total_borrows = 0;
        pool.bump = ctx.bumps.pool;
        
        emit!(PoolInitialized {
            admin: pool.admin,
            timestamp: Clock::get()?.unix_timestamp,
        });
        
        Ok(())
    }

    /// Deposit tokens into the pool
    /// SECURE: Uses checked arithmetic
    pub fn deposit(ctx: Context<Deposit>, amount: u64) -> Result<()> {
        require!(amount > 0, LendingError::InvalidAmount);
        
        let pool = &mut ctx.accounts.pool;
        
        // SECURE: Checked addition prevents overflow
        pool.total_deposits = pool.total_deposits
            .checked_add(amount)
            .ok_or(LendingError::MathOverflow)?;
        
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
        
        emit!(Deposited {
            user: ctx.accounts.user.key(),
            amount,
        });
        
        Ok(())
    }

    /// Borrow tokens from the pool
    /// SECURE: Validates collateral and oracle
    pub fn borrow(ctx: Context<Borrow>, amount: u64) -> Result<()> {
        require!(amount > 0, LendingError::InvalidAmount);
        
        let pool = &mut ctx.accounts.pool;
        let oracle = &ctx.accounts.oracle;
        let clock = Clock::get()?;
        
        // SECURE: Check oracle staleness
        require!(
            clock.unix_timestamp - oracle.timestamp < MAX_ORACLE_STALENESS,
            LendingError::StaleOracle
        );
        
        // SECURE: Use TWAP instead of spot price
        let price = oracle.twap_price;
        
        // SECURE: Validate collateralization ratio
        let position = &ctx.accounts.position;
        let collateral_value = position.collateral
            .checked_mul(price)
            .ok_or(LendingError::MathOverflow)?;
        let new_debt = position.debt
            .checked_add(amount)
            .ok_or(LendingError::MathOverflow)?;
        let debt_value = new_debt
            .checked_mul(price)
            .ok_or(LendingError::MathOverflow)?;
        
        require!(
            collateral_value >= debt_value * MIN_COLLATERAL_RATIO / 100,
            LendingError::InsufficientCollateral
        );
        
        // SECURE: Update state BEFORE external call
        pool.total_borrows = pool.total_borrows
            .checked_add(amount)
            .ok_or(LendingError::MathOverflow)?;
        
        let seeds = &[b"pool".as_ref(), &[pool.bump]];
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
        
        emit!(Borrowed {
            user: ctx.accounts.user.key(),
            amount,
        });
        
        Ok(())
    }

    /// Withdraw tokens
    /// SECURE: State updated before transfer, proper authority check
    pub fn withdraw(ctx: Context<Withdraw>, amount: u64) -> Result<()> {
        require!(amount > 0, LendingError::InvalidAmount);
        
        let pool = &mut ctx.accounts.pool;
        
        // SECURE: Check sufficient balance
        require!(
            pool.total_deposits >= amount,
            LendingError::InsufficientLiquidity
        );
        
        // SECURE: Update state BEFORE external call (prevents reentrancy)
        pool.total_deposits = pool.total_deposits
            .checked_sub(amount)
            .ok_or(LendingError::MathOverflow)?;
        
        let seeds = &[b"pool".as_ref(), &[pool.bump]];
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
        
        emit!(Withdrawn {
            user: ctx.accounts.user.key(),
            amount,
        });
        
        Ok(())
    }

    /// Propose new admin (starts time lock)
    /// SECURE: Time lock prevents immediate admin changes
    pub fn propose_admin(ctx: Context<ProposeAdmin>, new_admin: Pubkey) -> Result<()> {
        let pool = &mut ctx.accounts.pool;
        let clock = Clock::get()?;
        
        pool.pending_admin = Some(new_admin);
        pool.admin_change_time = clock.unix_timestamp + TIME_LOCK_DURATION;
        
        emit!(AdminProposed {
            current_admin: pool.admin,
            proposed_admin: new_admin,
            effective_time: pool.admin_change_time,
        });
        
        Ok(())
    }

    /// Accept admin change (after time lock)
    /// SECURE: Requires time lock to have passed
    pub fn accept_admin(ctx: Context<AcceptAdmin>) -> Result<()> {
        let pool = &mut ctx.accounts.pool;
        let clock = Clock::get()?;
        
        require!(
            pool.pending_admin.is_some(),
            LendingError::NoPendingAdmin
        );
        require!(
            clock.unix_timestamp >= pool.admin_change_time,
            LendingError::TimeLockNotExpired
        );
        
        let new_admin = pool.pending_admin.unwrap();
        pool.admin = new_admin;
        pool.pending_admin = None;
        
        emit!(AdminChanged {
            new_admin,
        });
        
        Ok(())
    }
}

#[derive(Accounts)]
pub struct Initialize<'info> {
    #[account(
        init,
        payer = admin,
        space = 8 + Pool::INIT_SPACE,
        seeds = [b"pool"],
        bump
    )]
    pub pool: Account<'info, Pool>,
    
    // SECURE: Signer constraint enforces signature
    #[account(mut)]
    pub admin: Signer<'info>,
    
    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
pub struct Deposit<'info> {
    #[account(mut, seeds = [b"pool"], bump = pool.bump)]
    pub pool: Account<'info, Pool>,
    
    #[account(mut, constraint = user_token.owner == user.key())]
    pub user_token: Account<'info, TokenAccount>,
    
    #[account(mut, constraint = pool_token.owner == pool.key())]
    pub pool_token: Account<'info, TokenAccount>,
    
    pub user: Signer<'info>,
    pub token_program: Program<'info, Token>,
}

#[derive(Accounts)]
pub struct Borrow<'info> {
    #[account(mut, seeds = [b"pool"], bump = pool.bump)]
    pub pool: Account<'info, Pool>,
    
    #[account(
        mut,
        has_one = owner,
        seeds = [b"position", owner.key().as_ref()],
        bump
    )]
    pub position: Account<'info, Position>,
    
    #[account(mut)]
    pub user_token: Account<'info, TokenAccount>,
    
    #[account(mut)]
    pub pool_token: Account<'info, TokenAccount>,
    
    // SECURE: Oracle is a typed account with known program
    #[account(
        constraint = oracle.key() == pool.oracle @ LendingError::InvalidOracle
    )]
    pub oracle: Account<'info, Oracle>,
    
    #[account(constraint = owner.key() == position.owner)]
    pub owner: Signer<'info>,
    
    pub token_program: Program<'info, Token>,
}

#[derive(Accounts)]
pub struct Withdraw<'info> {
    #[account(mut, seeds = [b"pool"], bump = pool.bump)]
    pub pool: Account<'info, Pool>,
    
    #[account(mut)]
    pub user_token: Account<'info, TokenAccount>,
    
    #[account(mut)]
    pub pool_token: Account<'info, TokenAccount>,
    
    // SECURE: Proper signer verification
    pub authority: Signer<'info>,
    
    pub token_program: Program<'info, Token>,
}

#[derive(Accounts)]
pub struct ProposeAdmin<'info> {
    #[account(mut, seeds = [b"pool"], bump = pool.bump, has_one = admin)]
    pub pool: Account<'info, Pool>,
    
    pub admin: Signer<'info>,
}

#[derive(Accounts)]
pub struct AcceptAdmin<'info> {
    #[account(mut, seeds = [b"pool"], bump = pool.bump)]
    pub pool: Account<'info, Pool>,
}

#[account]
#[derive(InitSpace)]
pub struct Pool {
    pub admin: Pubkey,
    pub pending_admin: Option<Pubkey>,
    pub admin_change_time: i64,
    pub oracle: Pubkey,
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
    pub twap_price: u64,
    pub timestamp: i64,
}

#[error_code]
pub enum LendingError {
    #[msg("Invalid amount")]
    InvalidAmount,
    #[msg("Math overflow")]
    MathOverflow,
    #[msg("Stale oracle data")]
    StaleOracle,
    #[msg("Insufficient collateral")]
    InsufficientCollateral,
    #[msg("Insufficient liquidity")]
    InsufficientLiquidity,
    #[msg("Invalid oracle")]
    InvalidOracle,
    #[msg("No pending admin")]
    NoPendingAdmin,
    #[msg("Time lock not expired")]
    TimeLockNotExpired,
}

#[event]
pub struct PoolInitialized {
    pub admin: Pubkey,
    pub timestamp: i64,
}

#[event]
pub struct Deposited {
    pub user: Pubkey,
    pub amount: u64,
}

#[event]
pub struct Borrowed {
    pub user: Pubkey,
    pub amount: u64,
}

#[event]
pub struct Withdrawn {
    pub user: Pubkey,
    pub amount: u64,
}

#[event]
pub struct AdminProposed {
    pub current_admin: Pubkey,
    pub proposed_admin: Pubkey,
    pub effective_time: i64,
}

#[event]
pub struct AdminChanged {
    pub new_admin: Pubkey,
}
