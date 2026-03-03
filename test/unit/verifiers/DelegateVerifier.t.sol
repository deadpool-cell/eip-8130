// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;

import {InitialKey} from "../../../src/AccountDeployer.sol";
import {AccountConfigurationTest} from "../../lib/AccountConfigurationTest.sol";

contract DelegateVerifierTest is AccountConfigurationTest {
    uint256 constant DELEGATE_PK = 42;
    uint256 constant DELEGATOR_PK = 43;

    function test_verify_validDelegation() public {
        // Create delegate account (Account A) with a K1 key
        (address delegateAccount, bytes32 delegateKeyId) = _createK1Account(DELEGATE_PK);

        // Create delegator account (Account B) with a delegate key pointing to A
        address delegateSigner = vm.addr(DELEGATOR_PK);
        bytes32 delegatorKeyId = bytes32(bytes20(delegateSigner));
        bytes32 delegateRefKeyId = bytes32(bytes20(delegateAccount));

        InitialKey[] memory keys = new InitialKey[](2);
        // Sort keys by keyId
        if (delegatorKeyId < delegateRefKeyId) {
            keys[0] = InitialKey({verifier: address(k1Verifier), keyId: delegatorKeyId});
            keys[1] = InitialKey({verifier: address(delegateVerifier), keyId: delegateRefKeyId});
        } else {
            keys[0] = InitialKey({verifier: address(delegateVerifier), keyId: delegateRefKeyId});
            keys[1] = InitialKey({verifier: address(k1Verifier), keyId: delegatorKeyId});
        }

        bytes memory bytecode = _computeERC1167Bytecode(defaultAccountImplementation);
        address delegatorAccount = accountConfiguration.createAccount(bytes32(uint256(1)), bytecode, keys);

        // Sign a hash with the delegate's K1 key (Account A's key)
        bytes32 hash = keccak256("delegate test");
        bytes memory delegateSig = _signDigest(DELEGATE_PK, hash);

        // Build nested data: (nestedKeyId, nestedVerifierData)
        bytes memory nestedData = abi.encode(delegateKeyId, delegateSig);

        // Verify through delegate verifier
        assertTrue(delegateVerifier.verify(delegatorAccount, delegateRefKeyId, hash, nestedData));
    }

    function test_verify_revertsOnInvalidKeyId() public {
        bytes32 hash = keccak256("test");
        // keyId with non-zero low bytes (not a valid address-padded keyId)
        bytes32 badKeyId = bytes32(uint256(1));

        vm.expectRevert();
        delegateVerifier.verify(address(0), badKeyId, hash, hex"");
    }

    function test_verify_revertsOnUnauthorizedNestedKey() public {
        (address delegateAccount,) = _createK1Account(DELEGATE_PK);
        bytes32 delegateRefKeyId = bytes32(bytes20(delegateAccount));

        bytes32 hash = keccak256("test");

        // Use a keyId that doesn't exist on the delegate account
        bytes32 fakeNestedKeyId = bytes32(bytes20(vm.addr(999)));
        bytes memory fakeSig = _signDigest(999, hash);
        bytes memory nestedData = abi.encode(fakeNestedKeyId, fakeSig);

        vm.expectRevert();
        delegateVerifier.verify(address(0), delegateRefKeyId, hash, nestedData);
    }

    function test_verify_revertsOnDoubleDelegate() public {
        // Account A with K1 key
        (address accountA,) = _createK1Account(DELEGATE_PK);
        bytes32 aK1KeyId = bytes32(bytes20(vm.addr(DELEGATE_PK)));

        // Account B with a delegate key pointing to A
        bytes32 delegateRefA = bytes32(bytes20(accountA));
        InitialKey[] memory keysB = new InitialKey[](1);
        keysB[0] = InitialKey({verifier: address(delegateVerifier), keyId: delegateRefA});
        bytes memory bytecodeB = _computeERC1167Bytecode(defaultAccountImplementation);
        address accountB = accountConfiguration.createAccount(bytes32(uint256(10)), bytecodeB, keysB);

        // Account C with a delegate key pointing to B
        bytes32 delegateRefB = bytes32(bytes20(accountB));
        InitialKey[] memory keysC = new InitialKey[](1);
        keysC[0] = InitialKey({verifier: address(delegateVerifier), keyId: delegateRefB});
        bytes memory bytecodeC = _computeERC1167Bytecode(defaultAccountImplementation);
        accountConfiguration.createAccount(bytes32(uint256(20)), bytecodeC, keysC);

        bytes32 hash = keccak256("double delegate test");
        bytes memory k1Sig = _signDigest(DELEGATE_PK, hash);

        // Single-hop B → A data: (nestedKeyId = A's K1 key, nestedData = K1 sig)
        bytes memory singleHopData = abi.encode(aK1KeyId, k1Sig);

        // Verify B → A: should work (1 hop)
        assertTrue(delegateVerifier.verify(accountB, delegateRefA, hash, singleHopData));

        // Double-hop C → B data: (nestedKeyId = B's delegate key, nestedData = singleHopData)
        // B's delegate key has verifier = DelegateVerifier → triggers 1-hop limit
        bytes memory doubleHopData = abi.encode(delegateRefA, singleHopData);
        vm.expectRevert();
        delegateVerifier.verify(address(0), delegateRefB, hash, doubleHopData);
    }
}
