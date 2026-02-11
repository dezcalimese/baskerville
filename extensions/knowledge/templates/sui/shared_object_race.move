// PoC Template: Shared Object Race Condition
// Vulnerability: Concurrent access to shared objects causing unexpected state
// Chain: Sui/Move
//
// Shared objects in Sui can be accessed by multiple transactions concurrently.
// Without proper ordering or locking, this can lead to race conditions.

// ============================================================
// VULNERABLE CODE PATTERN
// ============================================================
// module example::pool {
//     use sui::object::{Self, UID};
//     use sui::tx_context::TxContext;
//     use sui::transfer;
//
//     struct Pool has key {
//         id: UID,
//         balance: u64,
//         total_shares: u64,
//     }
//
//     // BUG: Two users calling deposit simultaneously on a shared Pool
//     // can both read the same total_shares, causing incorrect share calculation
//     public entry fun deposit(pool: &mut Pool, amount: u64, ctx: &mut TxContext) {
//         let shares = if (pool.total_shares == 0) {
//             amount
//         } else {
//             amount * pool.total_shares / pool.balance  // Race: stale balance
//         };
//         pool.balance = pool.balance + amount;
//         pool.total_shares = pool.total_shares + shares;
//     }
// }

// ============================================================
// EXPLOIT SCENARIO
// ============================================================
// 1. Pool has balance=1000, total_shares=1000
// 2. TX-A (deposit 500) reads pool: balance=1000, total_shares=1000
// 3. TX-B (deposit 500) reads pool: balance=1000, total_shares=1000
// 4. TX-A completes: balance=1500, shares_minted=500, total=1500
// 5. TX-B executes with stale values: also mints 500 shares
// 6. Result: 2000 shares for 2000 balance (should be ~1833 shares for TX-B)

// ============================================================
// FIX: Use versioning or ensure atomicity
// ============================================================
// - Add a version counter to the Pool, check it in each operation
// - Or use Sui's ordered transaction mechanism for critical operations
// - Consider making the Pool an owned object with a wrapper for access
