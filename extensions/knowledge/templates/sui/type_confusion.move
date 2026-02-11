// PoC Template: Type Confusion via Generics
// Vulnerability: Unconstrained generic type parameters
// Chain: Sui/Move
//
// Move generics allow any type to be used unless constrained.
// This can enable type confusion attacks.

// ============================================================
// VULNERABLE CODE PATTERN
// ============================================================
// module example::pool {
//     use sui::object::{Self, UID};
//     use sui::coin::{Self, Coin};
//
//     struct Pool<phantom T> has key {
//         id: UID,
//         balance: u64,
//     }
//
//     // BUG: No validation that T matches the actual coin in the pool
//     public entry fun withdraw<T>(pool: &mut Pool<T>, amount: u64, ctx: &mut TxContext) {
//         assert!(pool.balance >= amount, 0);
//         pool.balance = pool.balance - amount;
//         // Mints new coins of type T... but what if T is a fake coin?
//     }
// }

// ============================================================
// EXPLOIT SCENARIO
// ============================================================
// 1. Pool<USDC> is created with real USDC deposits
// 2. Attacker calls withdraw<FakeCoin>(pool, amount)
// 3. If the pool doesn't validate T matches its actual coin type,
//    the attacker drains the pool's accounting while getting FakeCoins
// 4. Pool shows reduced balance but real assets weren't moved

// ============================================================
// FIX: Store and validate the coin type
// ============================================================
// struct Pool<phantom T> has key {
//     id: UID,
//     coin: Coin<T>,  // Store actual coins, not just balance
// }
// // Now withdraw must return Coin<T> which is type-checked by the runtime
