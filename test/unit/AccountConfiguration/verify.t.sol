// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;

import {KeyOperation} from "../../../src/AccountConfigDigest.sol";
import {AccountConfigurationTest} from "../../lib/AccountConfigurationTest.sol";

contract VerifyTest is AccountConfigurationTest {
    uint256 constant OWNER_PK = 400;

    function test_verify_validK1Signature() public {
        (address account, bytes32 keyId) = _createK1Account(OWNER_PK);

        bytes32 hash = keccak256("verify me");
        bytes memory sig = _signDigest(OWNER_PK, hash);

        assertTrue(accountConfiguration.verify(account, keyId, hash, sig));
    }

    function test_verify_wrongSignature() public {
        (address account, bytes32 keyId) = _createK1Account(OWNER_PK);

        bytes32 hash = keccak256("verify me");
        bytes memory wrongSig = _signDigest(999, hash);

        assertFalse(accountConfiguration.verify(account, keyId, hash, wrongSig));
    }

    function test_verify_unregisteredKey() public {
        (address account,) = _createK1Account(OWNER_PK);

        bytes32 unknownKeyId = bytes32(bytes20(vm.addr(999)));
        bytes32 hash = keccak256("verify me");
        bytes memory sig = _signDigest(999, hash);

        assertFalse(accountConfiguration.verify(account, unknownKeyId, hash, sig));
    }

    function test_verify_revokedKey() public {
        (address account, bytes32 ownerKeyId) = _createK1Account(OWNER_PK);

        // Add a second key
        address newSigner = vm.addr(401);
        bytes32 newKeyId = bytes32(bytes20(newSigner));
        _authorizeKey(account, OWNER_PK, newKeyId, address(k1Verifier), 0);

        // Revoke it
        _revokeKey(account, OWNER_PK, newKeyId);

        // Verify should fail for revoked key
        bytes32 hash = keccak256("after revoke");
        bytes memory sig = _signDigest(401, hash);
        assertFalse(accountConfiguration.verify(account, newKeyId, hash, sig));

        // Owner key should still work
        bytes memory ownerSig = _signDigest(OWNER_PK, hash);
        assertTrue(accountConfiguration.verify(account, ownerKeyId, hash, ownerSig));
    }

    function test_verify_differentAccounts() public {
        (address account1, bytes32 keyId1) = _createK1AccountWithSalt(OWNER_PK, bytes32(uint256(1)));
        (address account2,) = _createK1AccountWithSalt(OWNER_PK, bytes32(uint256(2)));

        bytes32 hash = keccak256("cross-account test");
        bytes memory sig = _signDigest(OWNER_PK, hash);

        // Same key is registered on account1 but not necessarily the same storage for account2
        assertTrue(accountConfiguration.verify(account1, keyId1, hash, sig));
        assertTrue(accountConfiguration.verify(account2, keyId1, hash, sig));
    }

    function test_isAuthorized_returnsCorrectly() public {
        (address account, bytes32 keyId) = _createK1Account(OWNER_PK);

        assertTrue(accountConfiguration.isAuthorized(account, keyId));

        bytes32 unknownKeyId = bytes32(bytes20(vm.addr(999)));
        assertFalse(accountConfiguration.isAuthorized(account, unknownKeyId));
    }

    function test_getKeyData_returnsVerifierAndFlags() public {
        (address account, bytes32 keyId) = _createK1Account(OWNER_PK);

        (address verifier, uint8 flags) = accountConfiguration.getKeyData(account, keyId);
        assertEq(verifier, address(k1Verifier));
        assertEq(flags, 0);
    }

    function test_getKeyData_returnsZeroForUnknownKey() public {
        (address account,) = _createK1Account(OWNER_PK);

        bytes32 unknownKeyId = bytes32(bytes20(vm.addr(999)));
        (address verifier, uint8 flags) = accountConfiguration.getKeyData(account, unknownKeyId);
        assertEq(verifier, address(0));
        assertEq(flags, 0);
    }

    function test_computeERC1167Bytecode() public view {
        bytes memory bytecode = accountConfiguration.computeERC1167Bytecode(defaultAccountImplementation);
        assertEq(bytecode.length, 45);

        // Verify it matches the standard ERC-1167 pattern
        bytes memory expected = _computeERC1167Bytecode(defaultAccountImplementation);
        assertEq(keccak256(bytecode), keccak256(expected));
    }

    // ── Helpers ──

    function _authorizeKey(address account, uint256 pk, bytes32 newKeyId, address verifier, uint8 flags) internal {
        KeyOperation[] memory ops = new KeyOperation[](1);
        ops[0] = KeyOperation({opType: 0x01, verifier: verifier, keyId: newKeyId, flags: flags});

        uint64 chainId = uint64(block.chainid);
        uint64 seq = accountConfiguration.getChangeSequence(account, chainId);
        bytes32 digest = _computeKeyChangeDigest(account, chainId, seq, ops);
        bytes memory auth = _buildK1Auth(pk, digest);

        accountConfiguration.applyKeyChange(account, chainId, seq, ops, auth);
    }

    function _revokeKey(address account, uint256 pk, bytes32 keyId) internal {
        KeyOperation[] memory ops = new KeyOperation[](1);
        ops[0] = KeyOperation({opType: 0x02, verifier: address(0), keyId: keyId, flags: 0});

        uint64 chainId = uint64(block.chainid);
        uint64 seq = accountConfiguration.getChangeSequence(account, chainId);
        bytes32 digest = _computeKeyChangeDigest(account, chainId, seq, ops);
        bytes memory auth = _buildK1Auth(pk, digest);

        accountConfiguration.applyKeyChange(account, chainId, seq, ops, auth);
    }
}
