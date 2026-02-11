// PoC Template: PDA Seed Collision
// Vulnerability: Different account types sharing PDA seeds
// Chain: Solana/Anchor
//
// If two different account types use the same seed structure,
// an attacker can create a collision to confuse the program.

// ============================================================
// VULNERABLE CODE PATTERN
// ============================================================
// // Both UserProfile and UserConfig derive PDAs from just the user's pubkey
// #[account]
// pub struct UserProfile {
//     pub user: Pubkey,
//     pub balance: u64,
// }
//
// #[account]
// pub struct UserConfig {
//     pub user: Pubkey,
//     pub is_admin: bool,
// }
//
// // seeds = [b"user", user.key().as_ref()] for BOTH types!
// // An attacker could initialize UserConfig where UserProfile is expected

// ============================================================
// EXPLOIT SCENARIO
// ============================================================
// 1. Attacker initializes a UserConfig with is_admin = true
// 2. The PDA is: seeds = [b"user", attacker.key().as_ref()]
// 3. When program expects UserProfile at this PDA, it deserializes
//    UserConfig data as UserProfile (if discriminator isn't checked)
// 4. balance field overlaps with is_admin/user fields -> corruption

// ============================================================
// FIX: Use type-specific seed prefixes
// ============================================================
// // For UserProfile: seeds = [b"profile", user.key().as_ref()]
// // For UserConfig:  seeds = [b"config", user.key().as_ref()]
// // This ensures PDAs are unique per type
