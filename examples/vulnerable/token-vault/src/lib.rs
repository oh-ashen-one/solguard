use anchor_lang::prelude::*;

declare_id!("VuLnErAbLe111111111111111111111111111111111");

#[program]
pub mod vulnerable_vault {
    use super::*;

    // VULNERABILITY: No signer check - anyone can initialize
    pub fn initialize(ctx: Context<Initialize>, vault_bump: u8) -> Result<()> {
        let vault = &mut ctx.accounts.vault;
        vault.authority = ctx.accounts.authority.key();
        vault.bump = vault_bump;
        vault.balance = 0;
        Ok(())
    }

    // VULNERABILITY: Authority is AccountInfo, not Signer
    pub fn deposit(ctx: Context<Deposit>, amount: u64) -> Result<()> {
        let vault = &mut ctx.accounts.vault;
        
        // VULNERABILITY: Unchecked arithmetic - could overflow
        vault.balance = vault.balance + amount;
        
        Ok(())
    }

    // VULNERABILITY: Missing owner check on vault account
    pub fn withdraw(ctx: Context<Withdraw>, amount: u64) -> Result<()> {
        let vault = &mut ctx.accounts.vault;
        
        // No check that authority.key() == vault.authority!
        
        // VULNERABILITY: Unchecked arithmetic - could underflow
        vault.balance = vault.balance - amount;
        
        Ok(())
    }

    // VULNERABILITY: PDA without bump verification
    pub fn transfer_between_vaults(ctx: Context<Transfer>, amount: u64) -> Result<()> {
        let from_vault = &mut ctx.accounts.from_vault;
        let to_vault = &mut ctx.accounts.to_vault;
        
        // Deriving PDA without storing/checking bump
        let (expected_pda, _bump) = Pubkey::find_program_address(
            &[b"vault", ctx.accounts.authority.key().as_ref()],
            ctx.program_id,
        );
        
        from_vault.balance = from_vault.balance - amount;
        to_vault.balance = to_vault.balance + amount;
        
        Ok(())
    }
}

#[derive(Accounts)]
pub struct Initialize<'info> {
    #[account(
        init,
        payer = payer,
        space = 8 + Vault::INIT_SPACE,
        seeds = [b"vault", authority.key().as_ref()],
        bump
    )]
    pub vault: Account<'info, Vault>,
    
    // VULNERABILITY: Should be Signer<'info>
    /// CHECK: This should be a signer
    pub authority: AccountInfo<'info>,
    
    #[account(mut)]
    pub payer: Signer<'info>,
    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
pub struct Deposit<'info> {
    #[account(mut)]
    pub vault: Account<'info, Vault>,
    
    // VULNERABILITY: Authority should be Signer, not AccountInfo
    /// CHECK: Missing signer check
    pub authority: AccountInfo<'info>,
}

#[derive(Accounts)]
pub struct Withdraw<'info> {
    // VULNERABILITY: No owner constraint, no authority check
    #[account(mut)]
    pub vault: Account<'info, Vault>,
    
    // VULNERABILITY: Not a Signer
    /// CHECK: Should verify this matches vault.authority AND is a signer
    pub authority: AccountInfo<'info>,
}

#[derive(Accounts)]
pub struct Transfer<'info> {
    #[account(mut)]
    pub from_vault: Account<'info, Vault>,
    
    #[account(mut)]
    pub to_vault: Account<'info, Vault>,
    
    /// CHECK: No validation
    pub authority: AccountInfo<'info>,
}

#[account]
#[derive(InitSpace)]
pub struct Vault {
    pub authority: Pubkey,
    pub balance: u64,
    pub bump: u8,
}
