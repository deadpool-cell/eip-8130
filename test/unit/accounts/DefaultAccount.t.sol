// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;

import {AccountOperation} from "../../../src/AccountConfigDigest.sol";
import {DefaultAccount} from "../../../src/accounts/DefaultAccount.sol";
import {AccountConfigurationTest} from "../../lib/AccountConfigurationTest.sol";

contract MockTarget {
    uint256 public value;

    function setValue(uint256 v) external payable {
        value = v;
    }

    function reverting() external pure {
        revert("boom");
    }
}

contract DefaultAccountTest is AccountConfigurationTest {
    uint256 constant OWNER_PK = 100;
    MockTarget public target;

    function setUp() public override {
        super.setUp();
        target = new MockTarget();
    }

    // ── executeBatch ──

    function test_executeBatch_success() public {
        (address account,) = _createK1Account(OWNER_PK);
        vm.deal(account, 1 ether);

        DefaultAccount.Call[] memory calls = new DefaultAccount.Call[](1);
        calls[0] =
            DefaultAccount.Call({target: address(target), data: abi.encodeCall(MockTarget.setValue, (42)), value: 0});

        vm.prank(account);
        DefaultAccount(payable(account)).executeBatch(calls);

        assertEq(target.value(), 42);
    }

    function test_executeBatch_multipleCalls() public {
        (address account,) = _createK1Account(OWNER_PK);

        DefaultAccount.Call[] memory calls = new DefaultAccount.Call[](2);
        calls[0] =
            DefaultAccount.Call({target: address(target), data: abi.encodeCall(MockTarget.setValue, (10)), value: 0});
        calls[1] =
            DefaultAccount.Call({target: address(target), data: abi.encodeCall(MockTarget.setValue, (20)), value: 0});

        vm.prank(account);
        DefaultAccount(payable(account)).executeBatch(calls);

        assertEq(target.value(), 20);
    }

    function test_executeBatch_withETHValue() public {
        (address account,) = _createK1Account(OWNER_PK);
        vm.deal(account, 1 ether);

        DefaultAccount.Call[] memory calls = new DefaultAccount.Call[](1);
        calls[0] = DefaultAccount.Call({
            target: address(target), data: abi.encodeCall(MockTarget.setValue, (1)), value: 0.5 ether
        });

        vm.prank(account);
        DefaultAccount(payable(account)).executeBatch(calls);

        assertEq(address(target).balance, 0.5 ether);
    }

    function test_executeBatch_revertsFromNonSelf() public {
        (address account,) = _createK1Account(OWNER_PK);

        DefaultAccount.Call[] memory calls = new DefaultAccount.Call[](1);
        calls[0] =
            DefaultAccount.Call({target: address(target), data: abi.encodeCall(MockTarget.setValue, (1)), value: 0});

        vm.prank(address(0xdead));
        vm.expectRevert();
        DefaultAccount(payable(account)).executeBatch(calls);
    }

    function test_executeBatch_revertsOnFailedCall() public {
        (address account,) = _createK1Account(OWNER_PK);

        DefaultAccount.Call[] memory calls = new DefaultAccount.Call[](1);
        calls[0] =
            DefaultAccount.Call({target: address(target), data: abi.encodeCall(MockTarget.reverting, ()), value: 0});

        vm.prank(account);
        vm.expectRevert();
        DefaultAccount(payable(account)).executeBatch(calls);
    }

    function test_executeBatch_blocksETHWhenLocked() public {
        (address account, bytes32 keyId) = _createK1Account(OWNER_PK);
        vm.deal(account, 1 ether);

        // Lock the account via applyAccountChange
        _lockAccount(account, OWNER_PK, keyId);

        (bool locked,,) = accountConfiguration.getAccountPolicy(account);
        assertTrue(locked);

        // Try to send ETH — should revert
        DefaultAccount.Call[] memory calls = new DefaultAccount.Call[](1);
        calls[0] = DefaultAccount.Call({
            target: address(target), data: abi.encodeCall(MockTarget.setValue, (1)), value: 0.1 ether
        });

        vm.prank(account);
        vm.expectRevert();
        DefaultAccount(payable(account)).executeBatch(calls);
    }

    function test_executeBatch_allowsZeroValueCallsWhenLocked() public {
        (address account, bytes32 keyId) = _createK1Account(OWNER_PK);

        _lockAccount(account, OWNER_PK, keyId);

        DefaultAccount.Call[] memory calls = new DefaultAccount.Call[](1);
        calls[0] =
            DefaultAccount.Call({target: address(target), data: abi.encodeCall(MockTarget.setValue, (99)), value: 0});

        vm.prank(account);
        DefaultAccount(payable(account)).executeBatch(calls);

        assertEq(target.value(), 99);
    }

    // ── isValidSignature ──

    function test_isValidSignature_validK1() public {
        (address account, bytes32 keyId) = _createK1Account(OWNER_PK);

        bytes32 hash = keccak256("validate me");
        bytes memory sig = _signDigest(OWNER_PK, hash);
        bytes memory authData = abi.encode(keyId, sig);

        bytes4 result = DefaultAccount(payable(account)).isValidSignature(hash, authData);
        assertEq(result, bytes4(0x1626ba7e));
    }

    function test_isValidSignature_invalidSignature() public {
        (address account, bytes32 keyId) = _createK1Account(OWNER_PK);

        bytes32 hash = keccak256("validate me");
        bytes memory wrongSig = _signDigest(999, hash);
        bytes memory authData = abi.encode(keyId, wrongSig);

        bytes4 result = DefaultAccount(payable(account)).isValidSignature(hash, authData);
        assertEq(result, bytes4(0xFFFFFFFF));
    }

    function test_isValidSignature_unknownKeyId() public {
        (address account,) = _createK1Account(OWNER_PK);

        bytes32 hash = keccak256("validate me");
        bytes32 unknownKeyId = bytes32(bytes20(vm.addr(999)));
        bytes memory sig = _signDigest(999, hash);
        bytes memory authData = abi.encode(unknownKeyId, sig);

        bytes4 result = DefaultAccount(payable(account)).isValidSignature(hash, authData);
        assertEq(result, bytes4(0xFFFFFFFF));
    }

    // ── Helper: lock account via applyAccountChange ──

    function _lockAccount(address account, uint256 pk, bytes32 keyId) internal {
        AccountOperation[] memory ops = new AccountOperation[](1);
        ops[0] = AccountOperation({
            opType: 0x03, // OP_SET_ACCOUNT_POLICY
            flags: 0x01, // POLICY_LOCKED
            unlockDelay: 1 hours
        });

        uint64 chainId = uint64(block.chainid);
        uint64 sequence = accountConfiguration.getChangeSequence(account, chainId);
        bytes32 digest = _computeAccountChangeDigest(account, chainId, sequence, ops);
        bytes memory auth = _buildK1Auth(pk, digest);

        accountConfiguration.applyAccountChange(account, chainId, sequence, ops, auth);
    }
}
