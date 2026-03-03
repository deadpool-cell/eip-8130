// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.30;

import {Script, console} from "forge-std/Script.sol";

import {AccountConfiguration} from "../src/AccountConfiguration.sol";
import {DefaultAccount} from "../src/accounts/DefaultAccount.sol";
import {K1Verifier} from "../src/verifiers/K1Verifier.sol";
import {P256Verifier} from "../src/verifiers/P256Verifier.sol";
import {WebAuthnVerifier} from "../src/verifiers/WebAuthnVerifier.sol";
import {DelegateVerifier} from "../src/verifiers/DelegateVerifier.sol";
import {BLSVerifier} from "../src/verifiers/BLSVerifier.sol";
import {Ed25519Verifier} from "../src/verifiers/Ed25519Verifier.sol";
import {SandboxLib} from "../src/SandboxLib.sol";

/// @notice Deploys the full EIP-8130 system with sandbox-wrapped verifiers.
///
///         Each native verifier is deployed in two forms:
///           1. Regular contract   — used for direct calls and as the STATICCALL target
///           2. Sandbox wrapper    — 55-byte contract with the 8130 sandbox header that
///                                   forwards calls to (1) via STATICCALL
///
///         The sandbox wrappers carry the EIP-8130 header metadata (magic, gas limit,
///         version) so the protocol on 8130 chains can recognise them. On non-8130
///         chains the wrapper transparently forwards to the real verifier.
contract Deploy is Script {
    // Sandbox gas limits (units of 1k gas).
    // Based on benchmarked verification costs minus external-call overhead.
    // K1:       ecrecover (3k) + calldata decode (~500) + compare (~200) ≈ 4k
    // P256:     RIP-7212 precompile (3.5k) + decode + keccak ≈ 5k
    // WebAuthn: P256 verify + authenticatorData/challenge parsing ≈ 8k
    // Delegate: getKeyData SLOAD (2.1k) + nested verifier call ≈ 8k (excl. nested)
    // BLS:      EIP-2537 hashToG2 (~30k) + pairing 2-pair (~103k) ≈ 135k
    // Ed25519:  precompile (~3.5k) + decode ≈ 4k
    uint24 constant K1_GAS_LIMIT = 4;
    uint24 constant P256_GAS_LIMIT = 5;
    uint24 constant WEBAUTHN_GAS_LIMIT = 8;
    uint24 constant DELEGATE_GAS_LIMIT = 8;
    uint24 constant BLS_GAS_LIMIT = 135;
    uint24 constant ED25519_GAS_LIMIT = 4;

    uint8 constant SANDBOX_VERSION = 0;

    // Placeholder Ed25519 precompile address — override per chain
    address constant ED25519_PRECOMPILE = address(0x0ed);


    function run() public {
        vm.startBroadcast();

        // ── Core contracts ──

        AccountConfiguration accountConfig = new AccountConfiguration{salt: 0}();
        console.log("AccountConfiguration:", address(accountConfig));

        address defaultAccount = address(new DefaultAccount{salt: 0}(address(accountConfig)));
        console.log("DefaultAccount:      ", defaultAccount);

        // ── Native verifiers (regular contracts) ──

        address k1 = address(new K1Verifier{salt: 0}());
        address p256 = address(new P256Verifier{salt: 0}());
        address webAuthn = address(new WebAuthnVerifier{salt: 0}());
        address delegate = address(new DelegateVerifier{salt: 0}(address(accountConfig)));
        address bls = address(new BLSVerifier{salt: 0}());
        address ed25519 = address(new Ed25519Verifier{salt: 0}(ED25519_PRECOMPILE));

        // ── Sandbox wrappers (forward to native verifiers via STATICCALL) ──

        address k1Sandbox = SandboxLib.deploy(k1, K1_GAS_LIMIT, SANDBOX_VERSION, bytes32("K1"));
        address p256Sandbox = SandboxLib.deploy(p256, P256_GAS_LIMIT, SANDBOX_VERSION, bytes32("P256_RAW"));
        address webAuthnSandbox = SandboxLib.deploy(webAuthn, WEBAUTHN_GAS_LIMIT, SANDBOX_VERSION, bytes32("P256_WEBAUTHN"));
        address delegateSandbox = SandboxLib.deploy(delegate, DELEGATE_GAS_LIMIT, SANDBOX_VERSION, bytes32("DELEGATE"));
        address blsSandbox = SandboxLib.deploy(bls, BLS_GAS_LIMIT, SANDBOX_VERSION, bytes32("BLS"));
        address ed25519Sandbox = SandboxLib.deploy(ed25519, ED25519_GAS_LIMIT, SANDBOX_VERSION, bytes32("ED25519"));

        vm.stopBroadcast();

        // ── Log results ──

        _logVerifier("K1Verifier", k1, k1Sandbox);
        _logVerifier("P256Verifier", p256, p256Sandbox);
        _logVerifier("WebAuthnVerifier", webAuthn, webAuthnSandbox);
        _logVerifier("DelegateVerifier", delegate, delegateSandbox);
        _logVerifier("BLSVerifier", bls, blsSandbox);
        _logVerifier("Ed25519Verifier", ed25519, ed25519Sandbox);
    }

    function _logVerifier(string memory name, address impl, address sandbox) internal view {
        console.log(string.concat(name, ":"));
        console.log("  impl:   ", impl);
        console.log("  sandbox:", sandbox);

        (uint24 gasLimitInK, uint8 version, address wrapped, bool valid) = SandboxLib.parseSandboxHeader(sandbox);
        require(valid, string.concat(name, ": invalid sandbox header"));
        require(wrapped == impl, string.concat(name, ": wrapper points to wrong impl"));
        console.log("  header:  magic=8130, gas=%dk, version=%d, wraps=%s", gasLimitInK, version, impl);
    }
}
