// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;

import {AccountConfigurationTest} from "../../lib/AccountConfigurationTest.sol";

contract K1VerifierTest is AccountConfigurationTest {
    function test_verify_validSignature(uint256 pk) public view {
        pk = bound(pk, 1, 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364140);
        address signer = vm.addr(pk);
        bytes32 keyId = bytes32(bytes20(signer));
        bytes32 hash = keccak256("test message");

        bytes memory sig = _signDigest(pk, hash);
        assertTrue(k1Verifier.verify(address(0), keyId, hash, sig));
    }

    function test_verify_wrongKey(uint256 pk) public view {
        pk = bound(pk, 2, 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364140);
        address wrongSigner = vm.addr(1);
        bytes32 wrongKeyId = bytes32(bytes20(wrongSigner));
        bytes32 hash = keccak256("test message");

        bytes memory sig = _signDigest(pk, hash);
        assertFalse(k1Verifier.verify(address(0), wrongKeyId, hash, sig));
    }

    function test_verify_wrongHash(uint256 pk) public view {
        pk = bound(pk, 1, 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364140);
        address signer = vm.addr(pk);
        bytes32 keyId = bytes32(bytes20(signer));
        bytes32 hash = keccak256("test message");
        bytes32 wrongHash = keccak256("wrong message");

        bytes memory sig = _signDigest(pk, hash);
        assertFalse(k1Verifier.verify(address(0), keyId, wrongHash, sig));
    }

    function test_verify_revertsOnNonAddressKeyId() public {
        bytes32 hash = keccak256("test message");
        // keyId with non-zero bytes in the low 12 bytes
        bytes32 badKeyId = bytes32(uint256(1));
        bytes memory sig = _signDigest(1, hash);

        vm.expectRevert();
        k1Verifier.verify(address(0), badKeyId, hash, sig);
    }

    function test_verify_deterministicForSameInputs() public view {
        uint256 pk = 42;
        address signer = vm.addr(pk);
        bytes32 keyId = bytes32(bytes20(signer));
        bytes32 hash = keccak256("test message");

        bytes memory sig = _signDigest(pk, hash);
        bool result1 = k1Verifier.verify(address(0), keyId, hash, sig);
        bool result2 = k1Verifier.verify(address(0), keyId, hash, sig);

        assertEq(result1, result2);
        assertTrue(result1);
    }
}
