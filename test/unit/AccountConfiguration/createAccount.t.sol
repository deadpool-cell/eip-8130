// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;

import {InitialKey} from "../../../src/AccountDeployer.sol";
import {AccountConfigurationTest} from "../../lib/AccountConfigurationTest.sol";

contract CreateAccountTest is AccountConfigurationTest {
    function test_createAccount_singleK1Key(uint256 pk) public {
        pk = bound(pk, 1, 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364140);
        address owner = vm.addr(pk);
        bytes32 keyId = bytes32(bytes20(owner));

        InitialKey[] memory keys = new InitialKey[](1);
        keys[0] = InitialKey({verifier: address(k1Verifier), keyId: keyId});

        bytes memory bytecode = _computeERC1167Bytecode(defaultAccountImplementation);
        address account = accountConfiguration.createAccount(bytes32(0), bytecode, keys);

        assertTrue(account != address(0));
        assertTrue(account.code.length > 0);
        assertTrue(accountConfiguration.isAuthorized(account, keyId));
    }

    function test_createAccount_multipleKeys() public {
        address owner1 = vm.addr(1);
        address owner2 = vm.addr(2);

        bytes32 keyId1 = bytes32(bytes20(owner1));
        bytes32 keyId2 = bytes32(bytes20(owner2));

        // Ensure keys are sorted
        InitialKey[] memory keys = new InitialKey[](2);
        if (keyId1 < keyId2) {
            keys[0] = InitialKey({verifier: address(k1Verifier), keyId: keyId1});
            keys[1] = InitialKey({verifier: address(k1Verifier), keyId: keyId2});
        } else {
            keys[0] = InitialKey({verifier: address(k1Verifier), keyId: keyId2});
            keys[1] = InitialKey({verifier: address(k1Verifier), keyId: keyId1});
        }

        bytes memory bytecode = _computeERC1167Bytecode(defaultAccountImplementation);
        address account = accountConfiguration.createAccount(bytes32(0), bytecode, keys);

        assertTrue(account != address(0));
        assertTrue(accountConfiguration.isAuthorized(account, keyId1));
        assertTrue(accountConfiguration.isAuthorized(account, keyId2));
    }

    function test_createAccount_deterministicAddress() public {
        address owner = vm.addr(1);
        bytes32 keyId = bytes32(bytes20(owner));

        InitialKey[] memory keys = new InitialKey[](1);
        keys[0] = InitialKey({verifier: address(k1Verifier), keyId: keyId});

        bytes memory bytecode = _computeERC1167Bytecode(defaultAccountImplementation);
        address predicted = accountConfiguration.getAddress(bytes32(0), bytecode, keys);
        address actual = accountConfiguration.createAccount(bytes32(0), bytecode, keys);

        assertEq(predicted, actual);
    }

    function test_createAccount_idempotent() public {
        address owner = vm.addr(1);
        bytes32 keyId = bytes32(bytes20(owner));

        InitialKey[] memory keys = new InitialKey[](1);
        keys[0] = InitialKey({verifier: address(k1Verifier), keyId: keyId});

        bytes memory bytecode = _computeERC1167Bytecode(defaultAccountImplementation);
        address first = accountConfiguration.createAccount(bytes32(0), bytecode, keys);
        address second = accountConfiguration.createAccount(bytes32(0), bytecode, keys);

        assertEq(first, second);
    }

    function test_createAccount_revertsWithUnsortedKeys() public {
        address owner1 = vm.addr(1);
        address owner2 = vm.addr(2);

        bytes32 keyId1 = bytes32(bytes20(owner1));
        bytes32 keyId2 = bytes32(bytes20(owner2));

        // Force wrong order
        bytes32 smaller = keyId1 < keyId2 ? keyId1 : keyId2;
        bytes32 larger = keyId1 < keyId2 ? keyId2 : keyId1;

        InitialKey[] memory keys = new InitialKey[](2);
        keys[0] = InitialKey({verifier: address(k1Verifier), keyId: larger});
        keys[1] = InitialKey({verifier: address(k1Verifier), keyId: smaller});

        bytes memory bytecode = _computeERC1167Bytecode(defaultAccountImplementation);
        vm.expectRevert();
        accountConfiguration.createAccount(bytes32(0), bytecode, keys);
    }

    function test_createAccount_revertsWithNoKeys() public {
        InitialKey[] memory keys = new InitialKey[](0);
        bytes memory bytecode = _computeERC1167Bytecode(defaultAccountImplementation);

        vm.expectRevert();
        accountConfiguration.createAccount(bytes32(0), bytecode, keys);
    }

    function test_createAccount_revertsWithZeroVerifier() public {
        bytes32 keyId = bytes32(uint256(1));

        InitialKey[] memory keys = new InitialKey[](1);
        keys[0] = InitialKey({verifier: address(0), keyId: keyId});

        bytes memory bytecode = _computeERC1167Bytecode(defaultAccountImplementation);
        vm.expectRevert();
        accountConfiguration.createAccount(bytes32(0), bytecode, keys);
    }

    function test_createAccount_initialKeysHaveSafeDefaults() public {
        address owner = vm.addr(1);
        bytes32 keyId = bytes32(bytes20(owner));

        InitialKey[] memory keys = new InitialKey[](1);
        keys[0] = InitialKey({verifier: address(k1Verifier), keyId: keyId});

        bytes memory bytecode = _computeERC1167Bytecode(defaultAccountImplementation);
        address account = accountConfiguration.createAccount(bytes32(0), bytecode, keys);

        (address verifier, uint8 flags) = accountConfiguration.getKeyData(account, keyId);
        assertEq(verifier, address(k1Verifier));
        assertEq(flags, 0);

        (bool locked, uint32 unlockDelay, uint32 unlockRequestedAt) = accountConfiguration.getAccountPolicy(account);
        assertFalse(locked);
        assertEq(unlockDelay, 0);
        assertEq(unlockRequestedAt, 0);
    }

    function test_createAccount_differentSaltsProduceDifferentAddresses() public {
        address owner = vm.addr(1);
        bytes32 keyId = bytes32(bytes20(owner));

        InitialKey[] memory keys = new InitialKey[](1);
        keys[0] = InitialKey({verifier: address(k1Verifier), keyId: keyId});

        bytes memory bytecode = _computeERC1167Bytecode(defaultAccountImplementation);
        address addr1 = accountConfiguration.getAddress(bytes32(uint256(1)), bytecode, keys);
        address addr2 = accountConfiguration.getAddress(bytes32(uint256(2)), bytecode, keys);

        assertTrue(addr1 != addr2);
    }
}
