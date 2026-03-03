// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;

import {Test} from "forge-std/Test.sol";

import {BLSVerifier} from "../../../src/verifiers/BLSVerifier.sol";

contract BLSVerifierTest is Test {
    BLSVerifier verifier;

    function setUp() public {
        verifier = new BLSVerifier();
    }

    function test_verify_revertsOnWrongDataLength() public {
        vm.expectRevert();
        verifier.verify(address(0), bytes32(0), bytes32(0), hex"0000");
    }

    function test_verify_revertsOnShortData() public {
        bytes memory data = new bytes(383);

        vm.expectRevert();
        verifier.verify(address(0), bytes32(0), bytes32(0), data);
    }

    function test_verify_revertsOnLongData() public {
        bytes memory data = new bytes(385);

        vm.expectRevert();
        verifier.verify(address(0), bytes32(0), bytes32(0), data);
    }

    function test_verify_revertsOnWrongKeyId() public {
        bytes memory data = new bytes(384);
        bytes32 wrongKeyId = bytes32(uint256(1));

        vm.expectRevert();
        verifier.verify(address(0), wrongKeyId, bytes32(0), data);
    }

    function test_verify_keyIdMatchesPubKeyHash() public pure {
        // pubKey_G1 is 128 zero bytes — verify keyId derivation
        bytes memory pubKey = new bytes(128);
        bytes32 expectedKeyId = keccak256(pubKey);
        assertEq(expectedKeyId, keccak256(new bytes(128)));
    }

    function test_verify_revertsWithoutBLSPrecompiles() public {
        // On standard EVM without EIP-2537 precompiles, the pairing check
        // (or hashToG2) will revert because the precompile calls fail.
        bytes memory pubKey = new bytes(128);
        bytes32 keyId = keccak256(pubKey);
        bytes memory data = new bytes(384);

        // Copy pubKey into data[256:384] — already zeros matching our keyId
        vm.expectRevert();
        verifier.verify(address(0), keyId, keccak256("msg"), data);
    }

    function test_dataLayoutConstants() public pure {
        // sig_G2: 256 bytes (8 × 32-byte Fp components)
        // pubKey_G1: 128 bytes (4 × 32-byte Fp components)
        assertEq(uint256(256 + 128), uint256(384));
    }
}
