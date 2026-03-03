// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;

import {KeyOperation, AccountOperation} from "../../../src/AccountConfigDigest.sol";
import {AccountConfigurationTest} from "../../lib/AccountConfigurationTest.sol";

contract ApplyAccountChangeTest is AccountConfigurationTest {
    uint256 constant OWNER_PK = 300;

    // ── Lock lifecycle ──

    function test_lockAccount() public {
        (address account,) = _createK1Account(OWNER_PK);

        _applyAccountOp(account, OWNER_PK, _lockOp(1 hours));

        (bool locked, uint32 unlockDelay, uint32 unlockRequestedAt) = accountConfiguration.getAccountPolicy(account);
        assertTrue(locked);
        assertEq(unlockDelay, 1 hours);
        assertEq(unlockRequestedAt, 0);
    }

    function test_requestUnlock() public {
        (address account,) = _createK1Account(OWNER_PK);

        _applyAccountOp(account, OWNER_PK, _lockOp(1 hours));

        vm.warp(1000);
        _applyAccountOp(account, OWNER_PK, _requestUnlockOp());

        (bool locked, uint32 unlockDelay, uint32 unlockRequestedAt) = accountConfiguration.getAccountPolicy(account);
        assertTrue(locked);
        assertEq(unlockDelay, 1 hours);
        assertEq(unlockRequestedAt, 1000);
    }

    function test_unlockAfterDelay() public {
        (address account,) = _createK1Account(OWNER_PK);

        _applyAccountOp(account, OWNER_PK, _lockOp(1 hours));

        vm.warp(1000);
        _applyAccountOp(account, OWNER_PK, _requestUnlockOp());

        // Warp past the delay
        vm.warp(1000 + 1 hours);
        _applyAccountOp(account, OWNER_PK, _unlockOp());

        (bool locked,,) = accountConfiguration.getAccountPolicy(account);
        assertFalse(locked);
    }

    function test_unlockRevertsBeforeDelay() public {
        (address account,) = _createK1Account(OWNER_PK);

        _applyAccountOp(account, OWNER_PK, _lockOp(1 hours));

        vm.warp(1000);
        _applyAccountOp(account, OWNER_PK, _requestUnlockOp());

        // Try to unlock too early
        vm.warp(1000 + 30 minutes);
        AccountOperation[] memory ops = new AccountOperation[](1);
        ops[0] = _unlockOp();

        uint64 chainId = uint64(block.chainid);
        uint64 seq = accountConfiguration.getChangeSequence(account, chainId);
        bytes32 digest = _computeAccountChangeDigest(account, chainId, seq, ops);
        bytes memory auth = _buildK1Auth(OWNER_PK, digest);

        vm.expectRevert();
        accountConfiguration.applyAccountChange(account, chainId, seq, ops, auth);
    }

    function test_unlockRevertsWithoutRequest() public {
        (address account,) = _createK1Account(OWNER_PK);

        _applyAccountOp(account, OWNER_PK, _lockOp(1 hours));

        // Try to unlock without requesting first
        AccountOperation[] memory ops = new AccountOperation[](1);
        ops[0] = _unlockOp();

        uint64 chainId = uint64(block.chainid);
        uint64 seq = accountConfiguration.getChangeSequence(account, chainId);
        bytes32 digest = _computeAccountChangeDigest(account, chainId, seq, ops);
        bytes memory auth = _buildK1Auth(OWNER_PK, digest);

        vm.expectRevert();
        accountConfiguration.applyAccountChange(account, chainId, seq, ops, auth);
    }

    function test_requestUnlockRevertsWhenNotLocked() public {
        (address account,) = _createK1Account(OWNER_PK);

        AccountOperation[] memory ops = new AccountOperation[](1);
        ops[0] = _requestUnlockOp();

        uint64 chainId = uint64(block.chainid);
        uint64 seq = accountConfiguration.getChangeSequence(account, chainId);
        bytes32 digest = _computeAccountChangeDigest(account, chainId, seq, ops);
        bytes memory auth = _buildK1Auth(OWNER_PK, digest);

        vm.expectRevert();
        accountConfiguration.applyAccountChange(account, chainId, seq, ops, auth);
    }

    function test_lockedAccountRejectsNonUnlockOps() public {
        (address account,) = _createK1Account(OWNER_PK);

        _applyAccountOp(account, OWNER_PK, _lockOp(1 hours));

        // Try setAccountPolicy while locked — should revert
        AccountOperation[] memory ops = new AccountOperation[](1);
        ops[0] = AccountOperation({opType: 0x03, flags: 0x00, unlockDelay: 0});

        uint64 chainId = uint64(block.chainid);
        uint64 seq = accountConfiguration.getChangeSequence(account, chainId);
        bytes32 digest = _computeAccountChangeDigest(account, chainId, seq, ops);
        bytes memory auth = _buildK1Auth(OWNER_PK, digest);

        vm.expectRevert();
        accountConfiguration.applyAccountChange(account, chainId, seq, ops, auth);
    }

    // ── Chain ID enforcement ──

    function test_requestUnlockRequiresNonZeroChainId() public {
        (address account,) = _createK1Account(OWNER_PK);

        _applyAccountOp(account, OWNER_PK, _lockOp(1 hours));

        AccountOperation[] memory ops = new AccountOperation[](1);
        ops[0] = _requestUnlockOp();

        // Use chain_id 0 (multichain)
        uint64 seq = accountConfiguration.getChangeSequence(account, 0);
        bytes32 digest = _computeAccountChangeDigest(account, 0, seq, ops);
        bytes memory auth = _buildK1Auth(OWNER_PK, digest);

        vm.expectRevert();
        accountConfiguration.applyAccountChange(account, 0, seq, ops, auth);
    }

    // ── Sequence management ──

    function test_sequenceIncrements() public {
        (address account,) = _createK1Account(OWNER_PK);

        uint64 chainId = uint64(block.chainid);
        assertEq(accountConfiguration.getChangeSequence(account, chainId), 0);

        _applyAccountOp(account, OWNER_PK, _lockOp(1 hours));
        assertEq(accountConfiguration.getChangeSequence(account, chainId), 1);
    }

    function test_keyChangeAndAccountChangeShareSequence() public {
        (address account,) = _createK1Account(OWNER_PK);

        uint64 chainId = uint64(block.chainid);
        assertEq(accountConfiguration.getChangeSequence(account, chainId), 0);

        // Apply a key change at sequence 0
        KeyOperation[] memory keyOps = new KeyOperation[](1);
        keyOps[0] = KeyOperation({
            opType: 0x01, verifier: address(k1Verifier), keyId: bytes32(bytes20(vm.addr(400))), flags: 0
        });

        uint64 seq0 = accountConfiguration.getChangeSequence(account, chainId);
        bytes32 keyDigest = _computeKeyChangeDigest(account, chainId, seq0, keyOps);
        bytes memory keyAuth = _buildK1Auth(OWNER_PK, keyDigest);
        accountConfiguration.applyKeyChange(account, chainId, seq0, keyOps, keyAuth);

        assertEq(accountConfiguration.getChangeSequence(account, chainId), 1);

        // Apply an account change at sequence 1
        _applyAccountOp(account, OWNER_PK, _lockOp(1 hours));

        assertEq(accountConfiguration.getChangeSequence(account, chainId), 2);
    }

    function test_fullLockUnlockCycle() public {
        (address account,) = _createK1Account(OWNER_PK);

        // 1. Lock
        _applyAccountOp(account, OWNER_PK, _lockOp(1 hours));
        (bool locked,,) = accountConfiguration.getAccountPolicy(account);
        assertTrue(locked);

        // 2. Request unlock
        vm.warp(1000);
        _applyAccountOp(account, OWNER_PK, _requestUnlockOp());

        // 3. Wait and unlock
        vm.warp(1000 + 1 hours);
        _applyAccountOp(account, OWNER_PK, _unlockOp());

        (locked,,) = accountConfiguration.getAccountPolicy(account);
        assertFalse(locked);

        // 4. Key changes should work again
        KeyOperation[] memory ops = new KeyOperation[](1);
        ops[0] = KeyOperation({
            opType: 0x01, verifier: address(k1Verifier), keyId: bytes32(bytes20(vm.addr(500))), flags: 0
        });

        uint64 chainId = uint64(block.chainid);
        uint64 seq = accountConfiguration.getChangeSequence(account, chainId);
        bytes32 digest = _computeKeyChangeDigest(account, chainId, seq, ops);
        bytes memory auth = _buildK1Auth(OWNER_PK, digest);

        accountConfiguration.applyKeyChange(account, chainId, seq, ops, auth);
        assertTrue(accountConfiguration.isAuthorized(account, bytes32(bytes20(vm.addr(500)))));
    }

    // ── Helpers ──

    function _lockOp(uint32 delay) internal pure returns (AccountOperation memory) {
        return AccountOperation({opType: 0x03, flags: 0x01, unlockDelay: delay});
    }

    function _requestUnlockOp() internal pure returns (AccountOperation memory) {
        return AccountOperation({opType: 0x04, flags: 0, unlockDelay: 0});
    }

    function _unlockOp() internal pure returns (AccountOperation memory) {
        return AccountOperation({opType: 0x05, flags: 0, unlockDelay: 0});
    }

    function _applyAccountOp(address account, uint256 pk, AccountOperation memory op) internal {
        AccountOperation[] memory ops = new AccountOperation[](1);
        ops[0] = op;

        uint64 chainId = uint64(block.chainid);
        uint64 seq = accountConfiguration.getChangeSequence(account, chainId);
        bytes32 digest = _computeAccountChangeDigest(account, chainId, seq, ops);
        bytes memory auth = _buildK1Auth(pk, digest);

        accountConfiguration.applyAccountChange(account, chainId, seq, ops, auth);
    }
}
