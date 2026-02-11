// PoC Template: Missing Signer Check
// Vulnerability: Instruction handler does not verify the signer
// Chain: Solana/Anchor
//
// This template demonstrates how a missing signer check allows
// an attacker to execute privileged operations.

use anchor_lang::prelude::*;

// ============================================================
// VULNERABLE INSTRUCTION (example)
// ============================================================
// pub fn vulnerable_withdraw(ctx: Context<Withdraw>, amount: u64) -> Result<()> {
//     // BUG: No check that ctx.accounts.authority is the signer
//     let vault = &mut ctx.accounts.vault;
//     vault.balance -= amount;
//     // ... transfer lamports ...
//     Ok(())
// }

// ============================================================
// EXPLOIT TEST (Anchor test framework)
// ============================================================
// #[cfg(test)]
// mod tests {
//     use super::*;
//     use anchor_lang::solana_program::system_instruction;
//
//     #[test]
//     fn test_missing_signer_exploit() {
//         // 1. Set up program and accounts
//         // let program = {{PROGRAM_ID}};
//         // let vault = {{VAULT_ACCOUNT}};
//         // let attacker = Keypair::new();
//
//         // 2. Call withdraw with attacker as authority (not the real owner)
//         // let ix = instruction::Withdraw {
//         //     amount: vault_balance,
//         // };
//         // let accounts = accounts::Withdraw {
//         //     vault: vault.pubkey(),
//         //     authority: attacker.pubkey(),  // Attacker, not real owner!
//         //     system_program: system_program::ID,
//         // };
//
//         // 3. Should succeed if signer check is missing
//         // assert!(tx.is_ok(), "Exploit: unauthorized withdrawal succeeded");
//     }
// }

// ============================================================
// FIX: Add signer validation
// ============================================================
// #[derive(Accounts)]
// pub struct Withdraw<'info> {
//     #[account(mut, has_one = authority)]
//     pub vault: Account<'info, Vault>,
//     pub authority: Signer<'info>,  // <-- This enforces signer check
//     pub system_program: Program<'info, System>,
// }
