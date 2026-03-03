// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;

import {KeyOperation, AccountOperation} from "../../../src/AccountConfigEIP712.sol";
import {AccountConfigurationTest} from "../../lib/AccountConfigurationTest.sol";

contract ApplyKeyChangeTest is AccountConfigurationTest {
    uint256 constant OWNER_PK = 200;
    uint256 constant NEW_KEY_PK = 201;

    function test_authorizeKey() public {
        (address account, bytes32 ownerKeyId) = _createK1Account(OWNER_PK);

        address newKeySigner = vm.addr(NEW_KEY_PK);
        bytes32 newKeyId = bytes32(bytes20(newKeySigner));

        KeyOperation[] memory ops = new KeyOperation[](1);
        ops[0] = KeyOperation({
            opType: 0x01,
            verifier: address(k1Verifier),
            keyId: newKeyId,
            flags: 0
        });

        uint64 chainId = uint64(block.chainid);
        uint64 seq = accountConfiguration.getChangeSequence(account, chainId);
        bytes32 digest = _computeKeyChangeDigest(account, chainId, seq, ops);
        bytes memory auth = _buildK1Auth(OWNER_PK, digest);

        accountConfiguration.applyKeyChange(account, chainId, seq, ops, auth);

        assertTrue(accountConfiguration.isAuthorized(account, newKeyId));
        (address v, uint8 f) = accountConfiguration.getKeyData(account, newKeyId);
        assertEq(v, address(k1Verifier));
        assertEq(f, 0);
    }

    function test_authorizeKeyWithFlags() public {
        (address account,) = _createK1Account(OWNER_PK);

        address newKeySigner = vm.addr(NEW_KEY_PK);
        bytes32 newKeyId = bytes32(bytes20(newKeySigner));

        KeyOperation[] memory ops = new KeyOperation[](1);
        ops[0] = KeyOperation({
            opType: 0x01,
            verifier: address(k1Verifier),
            keyId: newKeyId,
            flags: 0x03 // disableKeyAdmin + disableGasPayment
        });

        uint64 chainId = uint64(block.chainid);
        uint64 seq = accountConfiguration.getChangeSequence(account, chainId);
        bytes32 digest = _computeKeyChangeDigest(account, chainId, seq, ops);
        bytes memory auth = _buildK1Auth(OWNER_PK, digest);

        accountConfiguration.applyKeyChange(account, chainId, seq, ops, auth);

        (, uint8 flags) = accountConfiguration.getKeyData(account, newKeyId);
        assertEq(flags, 0x03);
    }

    function test_revokeKey() public {
        (address account,) = _createK1Account(OWNER_PK);

        // First authorize a new key
        address newKeySigner = vm.addr(NEW_KEY_PK);
        bytes32 newKeyId = bytes32(bytes20(newKeySigner));
        _authorizeKey(account, OWNER_PK, newKeyId, address(k1Verifier), 0);

        assertTrue(accountConfiguration.isAuthorized(account, newKeyId));

        // Now revoke it
        KeyOperation[] memory ops = new KeyOperation[](1);
        ops[0] = KeyOperation({
            opType: 0x02,
            verifier: address(0),
            keyId: newKeyId,
            flags: 0
        });

        uint64 chainId = uint64(block.chainid);
        uint64 seq = accountConfiguration.getChangeSequence(account, chainId);
        bytes32 digest = _computeKeyChangeDigest(account, chainId, seq, ops);
        bytes memory auth = _buildK1Auth(OWNER_PK, digest);

        accountConfiguration.applyKeyChange(account, chainId, seq, ops, auth);

        assertFalse(accountConfiguration.isAuthorized(account, newKeyId));
    }

    function test_multipleOperationsInSingleChange() public {
        (address account,) = _createK1Account(OWNER_PK);

        bytes32 key1 = bytes32(bytes20(vm.addr(300)));
        bytes32 key2 = bytes32(bytes20(vm.addr(301)));

        KeyOperation[] memory ops = new KeyOperation[](2);
        ops[0] = KeyOperation({opType: 0x01, verifier: address(k1Verifier), keyId: key1, flags: 0});
        ops[1] = KeyOperation({opType: 0x01, verifier: address(k1Verifier), keyId: key2, flags: 0});

        uint64 chainId = uint64(block.chainid);
        uint64 seq = accountConfiguration.getChangeSequence(account, chainId);
        bytes32 digest = _computeKeyChangeDigest(account, chainId, seq, ops);
        bytes memory auth = _buildK1Auth(OWNER_PK, digest);

        accountConfiguration.applyKeyChange(account, chainId, seq, ops, auth);

        assertTrue(accountConfiguration.isAuthorized(account, key1));
        assertTrue(accountConfiguration.isAuthorized(account, key2));
    }

    function test_sequenceIncrements() public {
        (address account,) = _createK1Account(OWNER_PK);

        uint64 chainId = uint64(block.chainid);
        assertEq(accountConfiguration.getChangeSequence(account, chainId), 0);

        _authorizeKey(account, OWNER_PK, bytes32(bytes20(vm.addr(300))), address(k1Verifier), 0);
        assertEq(accountConfiguration.getChangeSequence(account, chainId), 1);

        _authorizeKey(account, OWNER_PK, bytes32(bytes20(vm.addr(301))), address(k1Verifier), 0);
        assertEq(accountConfiguration.getChangeSequence(account, chainId), 2);
    }

    function test_revertsOnWrongSequence() public {
        (address account,) = _createK1Account(OWNER_PK);

        KeyOperation[] memory ops = new KeyOperation[](1);
        ops[0] = KeyOperation({
            opType: 0x01,
            verifier: address(k1Verifier),
            keyId: bytes32(bytes20(vm.addr(300))),
            flags: 0
        });

        uint64 chainId = uint64(block.chainid);
        uint64 wrongSeq = 999;
        bytes32 digest = _computeKeyChangeDigest(account, chainId, wrongSeq, ops);
        bytes memory auth = _buildK1Auth(OWNER_PK, digest);

        vm.expectRevert();
        accountConfiguration.applyKeyChange(account, chainId, wrongSeq, ops, auth);
    }

    function test_revertsWhenLocked() public {
        (address account, bytes32 keyId) = _createK1Account(OWNER_PK);

        // Lock the account
        _lockAccount(account, OWNER_PK);

        KeyOperation[] memory ops = new KeyOperation[](1);
        ops[0] = KeyOperation({
            opType: 0x01,
            verifier: address(k1Verifier),
            keyId: bytes32(bytes20(vm.addr(300))),
            flags: 0
        });

        uint64 chainId = uint64(block.chainid);
        uint64 seq = accountConfiguration.getChangeSequence(account, chainId);
        bytes32 digest = _computeKeyChangeDigest(account, chainId, seq, ops);
        bytes memory auth = _buildK1Auth(OWNER_PK, digest);

        vm.expectRevert();
        accountConfiguration.applyKeyChange(account, chainId, seq, ops, auth);
    }

    function test_revertsWhenAuthorizerHasDisableKeyAdmin() public {
        (address account,) = _createK1Account(OWNER_PK);

        // Add a new key with disableKeyAdmin flag
        bytes32 nonAdminKeyId = bytes32(bytes20(vm.addr(NEW_KEY_PK)));
        _authorizeKey(account, OWNER_PK, nonAdminKeyId, address(k1Verifier), 0x01);

        // Try to use the non-admin key to authorize another key
        KeyOperation[] memory ops = new KeyOperation[](1);
        ops[0] = KeyOperation({
            opType: 0x01,
            verifier: address(k1Verifier),
            keyId: bytes32(bytes20(vm.addr(302))),
            flags: 0
        });

        uint64 chainId = uint64(block.chainid);
        uint64 seq = accountConfiguration.getChangeSequence(account, chainId);
        bytes32 digest = _computeKeyChangeDigest(account, chainId, seq, ops);
        bytes memory auth = _buildK1Auth(NEW_KEY_PK, digest);

        vm.expectRevert();
        accountConfiguration.applyKeyChange(account, chainId, seq, ops, auth);
    }

    function test_revertsOnDuplicateKeyAuthorization() public {
        (address account, bytes32 ownerKeyId) = _createK1Account(OWNER_PK);

        // Try to authorize a key that already exists (the owner key)
        KeyOperation[] memory ops = new KeyOperation[](1);
        ops[0] = KeyOperation({
            opType: 0x01,
            verifier: address(k1Verifier),
            keyId: ownerKeyId,
            flags: 0
        });

        uint64 chainId = uint64(block.chainid);
        uint64 seq = accountConfiguration.getChangeSequence(account, chainId);
        bytes32 digest = _computeKeyChangeDigest(account, chainId, seq, ops);
        bytes memory auth = _buildK1Auth(OWNER_PK, digest);

        vm.expectRevert();
        accountConfiguration.applyKeyChange(account, chainId, seq, ops, auth);
    }

    function test_revertsOnRevokingNonExistentKey() public {
        (address account,) = _createK1Account(OWNER_PK);

        bytes32 nonExistentKeyId = bytes32(bytes20(vm.addr(999)));

        KeyOperation[] memory ops = new KeyOperation[](1);
        ops[0] = KeyOperation({
            opType: 0x02,
            verifier: address(0),
            keyId: nonExistentKeyId,
            flags: 0
        });

        uint64 chainId = uint64(block.chainid);
        uint64 seq = accountConfiguration.getChangeSequence(account, chainId);
        bytes32 digest = _computeKeyChangeDigest(account, chainId, seq, ops);
        bytes memory auth = _buildK1Auth(OWNER_PK, digest);

        vm.expectRevert();
        accountConfiguration.applyKeyChange(account, chainId, seq, ops, auth);
    }

    function test_revertsWithInvalidSignature() public {
        (address account,) = _createK1Account(OWNER_PK);

        KeyOperation[] memory ops = new KeyOperation[](1);
        ops[0] = KeyOperation({
            opType: 0x01,
            verifier: address(k1Verifier),
            keyId: bytes32(bytes20(vm.addr(300))),
            flags: 0
        });

        uint64 chainId = uint64(block.chainid);
        uint64 seq = accountConfiguration.getChangeSequence(account, chainId);
        bytes32 digest = _computeKeyChangeDigest(account, chainId, seq, ops);

        // Sign with wrong private key
        bytes memory badAuth = _buildK1Auth(999, digest);

        vm.expectRevert();
        accountConfiguration.applyKeyChange(account, chainId, seq, ops, badAuth);
    }

    function test_multichainSequenceChannelsAreIndependent() public {
        (address account,) = _createK1Account(OWNER_PK);

        uint64 localChainId = uint64(block.chainid);
        uint64 multichainId = 0;

        assertEq(accountConfiguration.getChangeSequence(account, localChainId), 0);
        assertEq(accountConfiguration.getChangeSequence(account, multichainId), 0);

        // Apply on local chain
        _authorizeKey(account, OWNER_PK, bytes32(bytes20(vm.addr(300))), address(k1Verifier), 0);

        assertEq(accountConfiguration.getChangeSequence(account, localChainId), 1);
        assertEq(accountConfiguration.getChangeSequence(account, multichainId), 0);
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

    function _lockAccount(address account, uint256 pk) internal {
        AccountOperation[] memory ops = new AccountOperation[](1);
        ops[0] = AccountOperation({opType: 0x03, flags: 0x01, unlockDelay: 1 hours});

        uint64 chainId = uint64(block.chainid);
        uint64 seq = accountConfiguration.getChangeSequence(account, chainId);
        bytes32 digest = _computeAccountChangeDigest(account, chainId, seq, ops);
        bytes memory auth = _buildK1Auth(pk, digest);

        accountConfiguration.applyAccountChange(account, chainId, seq, ops, auth);
    }
}
