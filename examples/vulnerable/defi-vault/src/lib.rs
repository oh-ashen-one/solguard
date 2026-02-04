use anchor_lang::prelude::*;
use anchor_lang::solana_program::program::invoke;

declare_id!("VuLnDeF1111111111111111111111111111111111");

/// A vulnerable DeFi vault with multiple security issues
/// Used for testing SolShield AI pattern detection
#[program]
pub mod vulnerable_defi_vault {
    use super::*;

    /// Initialize a new vault - no issues here
    pub fn initialize(ctx: Context<Initialize>) -> Result<()> {
        let vault = &mut ctx.accounts.vault;
        vault.authority = ctx.accounts.authority.key();
        vault.total_shares = 0;
        vault.total_assets = 0;
        Ok(())
    }

    /// Deposit assets and receive shares
    /// VULNERABILITY: Rounding error - division before multiplication
    pub fn deposit(ctx: Context<Deposit>, amount: u64) -> Result<()> {
        let vault = &mut ctx.accounts.vault;
        
        // BAD: Division before multiplication causes precision loss
        let shares = if vault.total_shares == 0 {
            amount
        } else {
            (amount / vault.total_assets) * vault.total_shares  // SOL008: Rounding
        };
        
        vault.total_assets = vault.total_assets + amount;  // SOL003: Overflow
        vault.total_shares = vault.total_shares + shares;
        
        Ok(())
    }

    /// Withdraw assets by burning shares
    /// VULNERABILITY: No authority check, anyone can withdraw
    pub fn withdraw(ctx: Context<Withdraw>, shares: u64) -> Result<()> {
        let vault = &mut ctx.accounts.vault;
        
        // BAD: No check that caller is authorized
        let assets = (shares / vault.total_shares) * vault.total_assets;  // SOL008
        
        vault.total_shares = vault.total_shares - shares;  // SOL003
        vault.total_assets = vault.total_assets - assets;
        
        // BAD: CPI without program verification
        let ix = anchor_lang::solana_program::system_instruction::transfer(
            &ctx.accounts.vault_token.key(),
            &ctx.accounts.recipient.key(),
            assets,
        );
        invoke(&ix, &[  // SOL007: CPI without verification
            ctx.accounts.vault_token.to_account_info(),
            ctx.accounts.recipient.to_account_info(),
        ])?;
        
        Ok(())
    }

    /// Transfer between two user accounts
    /// VULNERABILITY: Accounts could be the same (confusion)
    pub fn transfer_shares(
        ctx: Context<TransferShares>,
        amount: u64,
    ) -> Result<()> {
        let from = &mut ctx.accounts.from_account;
        let to = &mut ctx.accounts.to_account;
        
        // BAD: No check that from != to (SOL009: Account confusion)
        from.shares = from.shares - amount;
        to.shares = to.shares + amount;
        
        Ok(())
    }

    /// Close a user account
    /// VULNERABILITY: Doesn't zero data before closing
    pub fn close_account(ctx: Context<CloseAccount>) -> Result<()> {
        let account = &ctx.accounts.user_account;
        let recipient = &ctx.accounts.recipient;
        
        // BAD: Transfer lamports without zeroing data (SOL010)
        let lamports = account.to_account_info().lamports();
        **account.to_account_info().try_borrow_mut_lamports()? = 0;
        **recipient.to_account_info().try_borrow_mut_lamports()? += lamports;
        
        // Data is NOT zeroed - account can be revived!
        
        Ok(())
    }

    /// Calculate fees
    /// VULNERABILITY: Fee can round to zero
    pub fn calculate_fee(ctx: Context<CalculateFee>, amount: u64) -> Result<u64> {
        // BAD: Fee calculation can round to zero (SOL008)
        let fee = amount * 3 / 1000;  // 0.3% fee, but small amounts = 0 fee
        Ok(fee)
    }
}

#[derive(Accounts)]
pub struct Initialize<'info> {
    #[account(init, payer = authority, space = 8 + Vault::INIT_SPACE)]
    pub vault: Account<'info, Vault>,
    #[account(mut)]
    pub authority: Signer<'info>,
    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
pub struct Deposit<'info> {
    #[account(mut)]
    pub vault: Account<'info, Vault>,
    pub depositor: Signer<'info>,
}

#[derive(Accounts)]
pub struct Withdraw<'info> {
    #[account(mut)]
    pub vault: Account<'info, Vault>,
    /// CHECK: Token account for vault
    pub vault_token: AccountInfo<'info>,  // SOL001: Unchecked
    /// CHECK: Recipient
    pub recipient: AccountInfo<'info>,  // SOL001: Unchecked
    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
pub struct TransferShares<'info> {
    // Both accounts are same type - could be confused (SOL009)
    #[account(mut)]
    pub from_account: Account<'info, UserAccount>,
    #[account(mut)]
    pub to_account: Account<'info, UserAccount>,
    pub authority: AccountInfo<'info>,  // SOL002: Not a Signer
}

#[derive(Accounts)]
pub struct CloseAccount<'info> {
    #[account(mut)]
    pub user_account: Account<'info, UserAccount>,
    /// CHECK: Recipient for rent - not validated (SOL010)
    #[account(mut)]
    pub recipient: AccountInfo<'info>,
}

#[derive(Accounts)]
pub struct CalculateFee<'info> {
    pub vault: Account<'info, Vault>,
}

#[account]
#[derive(InitSpace)]
pub struct Vault {
    pub authority: Pubkey,
    pub total_shares: u64,
    pub total_assets: u64,
}

#[account]
#[derive(InitSpace)]
pub struct UserAccount {
    pub owner: Pubkey,
    pub shares: u64,
}
