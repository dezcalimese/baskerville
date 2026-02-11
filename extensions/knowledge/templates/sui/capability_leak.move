// PoC Template: Capability Leakage
// Vulnerability: Admin capability stored in accessible location
// Chain: Sui/Move
//
// Capabilities in Sui control access to privileged operations.
// If leaked to shared objects, anyone can use them.

// ============================================================
// VULNERABLE CODE PATTERN
// ============================================================
// module example::admin {
//     use sui::object::{Self, UID};
//     use sui::transfer;
//     use sui::tx_context::TxContext;
//
//     struct AdminCap has key, store {
//         id: UID,
//     }
//
//     struct Config has key {
//         id: UID,
//         admin_cap: AdminCap,  // BUG: Capability stored in shared object!
//     }
//
//     fun init(ctx: &mut TxContext) {
//         let cap = AdminCap { id: object::new(ctx) };
//         let config = Config { id: object::new(ctx), admin_cap: cap };
//         transfer::share_object(config);  // Now anyone can access AdminCap
//     }
// }

// ============================================================
// EXPLOIT SCENARIO
// ============================================================
// 1. Config is a shared object containing AdminCap
// 2. Attacker borrows Config mutably in a transaction
// 3. Attacker extracts AdminCap and uses it for privileged operations
// 4. All admin protections are bypassed

// ============================================================
// FIX: Transfer capabilities to specific addresses
// ============================================================
// fun init(ctx: &mut TxContext) {
//     let cap = AdminCap { id: object::new(ctx) };
//     transfer::transfer(cap, tx_context::sender(ctx));  // Owned by deployer
//     let config = Config { id: object::new(ctx) };
//     transfer::share_object(config);  // Config shared, but cap is safe
// }
