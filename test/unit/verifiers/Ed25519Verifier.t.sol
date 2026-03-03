// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;

import {Test} from "forge-std/Test.sol";

import {Ed25519Verifier} from "../../../src/verifiers/Ed25519Verifier.sol";

/// @dev Mock Ed25519 precompile that accepts signatures where
///      keccak256(input) has an even last byte (deterministic, testable).
///      Real chains would use a real Ed25519 precompile.
contract MockEd25519 {
    fallback(bytes calldata input) external returns (bytes memory) {
        // Expect 128 bytes: hash (32) || signature (64) || pubKey (32)
        if (input.length != 128) return abi.encode(uint256(0));

        // For testing: "valid" if first byte of pubkey matches first byte of hash
        bytes32 hash = bytes32(input[0:32]);
        bytes32 pubKey = bytes32(input[96:128]);
        if (uint8(hash[0]) == uint8(pubKey[0])) {
            return abi.encode(uint256(1));
        }
        return abi.encode(uint256(0));
    }
}

contract Ed25519VerifierTest is Test {
    Ed25519Verifier verifier;
    MockEd25519 mock;

    function setUp() public {
        mock = new MockEd25519();
        verifier = new Ed25519Verifier(address(mock));
    }

    function test_verify_validSignature() public view {
        // Construct a pubKey whose first byte matches the hash's first byte
        bytes32 hash = keccak256("test message");
        bytes32 pubKey = bytes32(abi.encodePacked(hash[0], bytes31(0)));
        bytes32 keyId = keccak256(abi.encodePacked(pubKey));

        bytes memory sig = new bytes(64);
        bytes memory data = abi.encodePacked(sig, pubKey);

        bool result = verifier.verify(address(0), keyId, hash, data);
        assertTrue(result);
    }

    function test_verify_invalidSignature() public view {
        bytes32 hash = keccak256("test message");
        // Make pubKey's first byte differ from hash's first byte
        uint8 wrongByte = uint8(hash[0]) ^ 0xFF;
        bytes32 pubKey = bytes32(abi.encodePacked(wrongByte, bytes31(0)));
        bytes32 keyId = keccak256(abi.encodePacked(pubKey));

        bytes memory sig = new bytes(64);
        bytes memory data = abi.encodePacked(sig, pubKey);

        bool result = verifier.verify(address(0), keyId, hash, data);
        assertFalse(result);
    }

    function test_verify_revertsOnWrongDataLength() public {
        bytes32 keyId = bytes32(uint256(1));

        vm.expectRevert();
        verifier.verify(address(0), keyId, bytes32(0), hex"0000");
    }

    function test_verify_revertsOnWrongKeyId() public {
        bytes32 pubKey = bytes32(uint256(0xABCD));
        bytes32 wrongKeyId = bytes32(uint256(1));
        bytes memory sig = new bytes(64);

        vm.expectRevert();
        verifier.verify(address(0), wrongKeyId, bytes32(0), abi.encodePacked(sig, pubKey));
    }

    function test_verify_returnsFalseWhenPrecompileFails() public {
        // Deploy verifier pointing to an address with no code
        Ed25519Verifier noPrecompile = new Ed25519Verifier(address(0xDEAD));
        bytes32 pubKey = bytes32(uint256(0x42));
        bytes32 keyId = keccak256(abi.encodePacked(pubKey));
        bytes memory sig = new bytes(64);

        bool result = noPrecompile.verify(address(0), keyId, bytes32(0), abi.encodePacked(sig, pubKey));
        assertFalse(result);
    }

    function test_immutableAddress() public view {
        assertEq(verifier.ED25519_VERIFIER(), address(mock));
    }
}
