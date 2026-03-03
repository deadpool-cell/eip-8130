// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.30;

import {Script, console} from "forge-std/Script.sol";

import {AccountConfiguration} from "../src/AccountConfiguration.sol";
import {InitialKey} from "../src/AccountDeployer.sol";
import {IAuthVerifier} from "../src/verifiers/IAuthVerifier.sol";
import {SandboxLib} from "../src/SandboxLib.sol";

/// @notice End-to-end smoke test against a live deployment.
///
///         Tests:
///           1. Account creation via AccountConfiguration
///           2. Key authorization + data reads
///           3. K1 signature verification (direct verifier call)
///           4. K1 signature verification (through sandbox wrapper)
///           5. ERC-1167 proxy bytecode correctness
///           6. Sandbox header parsing
contract SmokeTest is Script {
    uint256 constant SIGNER_PK = 0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80;

    function run(address acctConfig, address k1Verifier, address k1Sandbox, address defaultImpl) public {
        address signer = vm.addr(SIGNER_PK);
        bytes32 keyId = bytes32(bytes20(signer));
        AccountConfiguration config = AccountConfiguration(acctConfig);

        // 1. Create account
        address account = _createAccount(config, k1Verifier, defaultImpl, keyId);
        console.log("[PASS] Account created:", account);

        // 2. Key authorization + data reads
        _checkKey(config, account, keyId, k1Verifier);
        console.log("[PASS] Key authorized with correct verifier and flags");

        // 3. K1 signature verification (direct)
        _checkSignature(k1Verifier, account, keyId);
        console.log("[PASS] K1 verify (direct)");

        // 4. K1 signature verification (through sandbox wrapper)
        _checkSignature(k1Sandbox, account, keyId);
        console.log("[PASS] K1 verify (sandbox wrapper)");

        // 5. ERC-1167 proxy
        require(account.code.length == 45, "expected 45-byte ERC-1167 proxy");
        console.log("[PASS] Account is 45-byte ERC-1167 proxy");

        // 6. Sandbox header parsing
        _checkSandboxHeader(k1Sandbox, k1Verifier);
        console.log("[PASS] Sandbox header valid, wraps correct verifier");

        console.log("");
        console.log("=== ALL SMOKE TESTS PASSED ===");
    }

    function _createAccount(AccountConfiguration config, address k1Verifier, address defaultImpl, bytes32 keyId)
        internal
        returns (address)
    {
        InitialKey[] memory keys = new InitialKey[](1);
        keys[0] = InitialKey({keyId: keyId, verifier: k1Verifier});

        bytes memory bytecode = config.computeERC1167Bytecode(defaultImpl);

        vm.startBroadcast(SIGNER_PK);
        address account = config.createAccount(bytes32(0), bytecode, keys);
        vm.stopBroadcast();
        return account;
    }

    function _checkKey(AccountConfiguration config, address account, bytes32 keyId, address k1Verifier) internal view {
        require(config.isAuthorized(account, keyId), "key not authorized");
        (address verifier, uint8 flags) = config.getKeyData(account, keyId);
        require(verifier == k1Verifier, "wrong verifier");
        require(flags == 0, "flags should be 0");
    }

    function _checkSignature(address verifier, address account, bytes32 keyId) internal view {
        bytes32 testHash = keccak256("hello EIP-8130");
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(SIGNER_PK, testHash);

        bool valid = IAuthVerifier(verifier).verify(account, keyId, testHash, abi.encodePacked(r, s, v));
        require(valid, "signature verification failed");
    }

    function _checkSandboxHeader(address sandbox, address expectedImpl) internal view {
        (uint8 version, address wrapped, bool valid) = SandboxLib.parseSandboxHeader(sandbox);
        require(valid, "invalid sandbox header");
        require(wrapped == expectedImpl, "wrapper points to wrong impl");
        require(version == 0, "version should be 0");
    }
}
