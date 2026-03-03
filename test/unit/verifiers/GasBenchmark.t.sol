// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;

import {Test} from "forge-std/Test.sol";

import {AccountConfiguration} from "../../../src/AccountConfiguration.sol";
import {InitialKey} from "../../../src/AccountDeployer.sol";
import {DefaultAccount} from "../../../src/accounts/DefaultAccount.sol";
import {IAuthVerifier} from "../../../src/verifiers/IAuthVerifier.sol";
import {K1Verifier} from "../../../src/verifiers/K1Verifier.sol";
import {P256Verifier} from "../../../src/verifiers/P256Verifier.sol";
import {WebAuthnVerifier} from "../../../src/verifiers/WebAuthnVerifier.sol";
import {DelegateVerifier} from "../../../src/verifiers/DelegateVerifier.sol";

contract GasBenchmarkTest is Test {
    K1Verifier k1;
    P256Verifier p256;
    WebAuthnVerifier webAuthn;
    DelegateVerifier delegate;
    AccountConfiguration config;
    address defaultImpl;

    function setUp() public {
        config = new AccountConfiguration();
        k1 = new K1Verifier();
        p256 = new P256Verifier();
        webAuthn = new WebAuthnVerifier();
        delegate = new DelegateVerifier(address(config));
        defaultImpl = address(new DefaultAccount(address(config)));
    }

    function test_gasK1Verifier() public {
        uint256 pk = 0xBEEF;
        address signer = vm.addr(pk);
        bytes32 keyId = bytes32(bytes20(signer));
        bytes32 hash = keccak256("benchmark");
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(pk, hash);
        bytes memory sig = abi.encodePacked(r, s, v);

        uint256 gasBefore = gasleft();
        k1.verify(address(0), keyId, hash, sig);
        uint256 gasUsed = gasBefore - gasleft();

        emit log_named_uint("K1Verifier.verify gas", gasUsed);
    }

    function test_gasP256Verifier() public {
        uint256 pk = 0xBEEF;
        (uint256 pubXu, uint256 pubYu) = vm.publicKeyP256(pk);
        bytes32 pubX = bytes32(pubXu);
        bytes32 pubY = bytes32(pubYu);
        bytes32 keyId = keccak256(abi.encodePacked(pubX, pubY));
        bytes32 hash = keccak256("benchmark");
        (bytes32 r, bytes32 s) = vm.signP256(pk, hash);
        bytes memory data = abi.encodePacked(r, s, pubX, pubY, uint8(0));

        uint256 gasBefore = gasleft();
        p256.verify(address(0), keyId, hash, data);
        uint256 gasUsed = gasBefore - gasleft();

        emit log_named_uint("P256Verifier.verify gas", gasUsed);
    }

    function test_gasDelegateVerifier() public {
        uint256 pkA = 0xA001;
        address signerA = vm.addr(pkA);
        bytes32 keyIdA = bytes32(bytes20(signerA));

        // Create the delegate account (where we look up the nested key)
        InitialKey[] memory keysA = new InitialKey[](1);
        keysA[0] = InitialKey({verifier: address(k1), keyId: keyIdA});
        bytes memory bytecode =
            abi.encodePacked(hex"363d3d373d3d3d363d73", defaultImpl, hex"5af43d82803e903d91602b57fd5bf3");
        address accountA = config.createAccount(bytes32("benchA"), bytecode, keysA);

        // delegateKeyId encodes the delegate account address (left-aligned)
        bytes32 delegateKeyId = bytes32(bytes20(accountA));

        bytes32 hash = keccak256("benchmark");
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(pkA, hash);
        bytes memory innerSig = abi.encodePacked(r, s, v);
        bytes memory data = abi.encode(keyIdA, innerSig);

        uint256 gasBefore = gasleft();
        delegate.verify(address(0), delegateKeyId, hash, data);
        uint256 gasUsed = gasBefore - gasleft();

        emit log_named_uint("DelegateVerifier.verify gas", gasUsed);
    }
}
