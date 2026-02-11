// PoC Template: CPI Reentrancy / Privilege Escalation
// Vulnerability: Unsafe CPI call allowing privilege escalation
// Chain: Solana/Anchor
//
// Demonstrates how an attacker can exploit CPI to escalate privileges
// or re-enter the program with unexpected state.

// ============================================================
// VULNERABLE CODE PATTERN
// ============================================================
// pub fn process_payment(ctx: Context<Payment>, amount: u64) -> Result<()> {
//     let vault = &mut ctx.accounts.vault;
//     vault.balance -= amount;  // State change BEFORE CPI
//
//     // CPI to token program - if target is attacker-controlled, reentrancy possible
//     let cpi_accounts = Transfer {
//         from: ctx.accounts.vault_token.to_account_info(),
//         to: ctx.accounts.recipient_token.to_account_info(),
//         authority: ctx.accounts.vault_authority.to_account_info(),
//     };
//     let cpi_program = ctx.accounts.token_program.to_account_info();
//     // BUG: If token_program is not validated, attacker can pass malicious program
//     token::transfer(CpiContext::new(cpi_program, cpi_accounts), amount)?;
//
//     Ok(())
// }

// ============================================================
// EXPLOIT SCENARIO
// ============================================================
// 1. Attacker deploys malicious program that mimics Token program interface
// 2. Attacker calls process_payment with malicious_program as token_program
// 3. Malicious program re-enters process_payment before state is finalized
// 4. Vault balance is drained through repeated withdrawals

// ============================================================
// FIX: Validate CPI target program
// ============================================================
// #[derive(Accounts)]
// pub struct Payment<'info> {
//     #[account(mut)]
//     pub vault: Account<'info, Vault>,
//     pub token_program: Program<'info, Token>,  // <-- Anchor validates this is SPL Token
//     // ... other accounts
// }
