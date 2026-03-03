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
import {SandboxLib} from "../src/SandboxLib.sol";

/// @notice Deploys the full EIP-8130 system with sandbox-wrapped verifiers.
///
///         Each native verifier is deployed in two forms:
///           1. Regular contract   — used for direct calls and as the STATICCALL target
///           2. Sandbox wrapper    — 52-byte contract with the 7-byte 8130 sandbox header
///                                   that forwards calls to (1) via STATICCALL
///
///         The sandbox wrappers carry the EIP-8130 header metadata (magic, version)
///         so the protocol on 8130 chains can recognise them. Gas metering is handled
///         by the node (configurable gas cap). On non-8130 chains the wrapper
///         transparently forwards to the real verifier.
contract Deploy is Script {
    uint8 constant SANDBOX_VERSION = 0;

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

        // ── Sandbox wrappers (forward to native verifiers via STATICCALL) ──

        address k1Sandbox = SandboxLib.deploy(k1, SANDBOX_VERSION, bytes32("K1"));
        address p256Sandbox = SandboxLib.deploy(p256, SANDBOX_VERSION, bytes32("P256_RAW"));
        address webAuthnSandbox = SandboxLib.deploy(webAuthn, SANDBOX_VERSION, bytes32("P256_WEBAUTHN"));
        address delegateSandbox = SandboxLib.deploy(delegate, SANDBOX_VERSION, bytes32("DELEGATE"));
        address blsSandbox = SandboxLib.deploy(bls, SANDBOX_VERSION, bytes32("BLS"));

        vm.stopBroadcast();

        // ── Log results ──

        _logVerifier("K1Verifier", k1, k1Sandbox);
        _logVerifier("P256Verifier", p256, p256Sandbox);
        _logVerifier("WebAuthnVerifier", webAuthn, webAuthnSandbox);
        _logVerifier("DelegateVerifier", delegate, delegateSandbox);
        _logVerifier("BLSVerifier", bls, blsSandbox);
    }

    function _logVerifier(string memory name, address impl, address sandbox) internal view {
        console.log(string.concat(name, ":"));
        console.log("  impl:   ", impl);
        console.log("  sandbox:", sandbox);

        (uint8 version, address wrapped, bool valid) = SandboxLib.parseSandboxHeader(sandbox);
        require(valid, string.concat(name, ": invalid sandbox header"));
        require(wrapped == impl, string.concat(name, ": wrapper points to wrong impl"));
        console.log("  header:  magic=8130, version=%d, wraps=%s", version, impl);
    }
}
