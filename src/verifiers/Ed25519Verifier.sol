// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;

import {IAuthVerifier} from "./IAuthVerifier.sol";

/// @notice Ed25519 (EdDSA on Curve25519) signature verifier.
///
///         keyId  = keccak256(publicKey)  where publicKey is 32 bytes
///         data   = signature (64 bytes) || publicKey (32 bytes)  — 96 bytes total
///
///         Delegates to an Ed25519 verification precompile or deployed contract.
///         The target address is set at construction time:
///           - On chains with a native Ed25519 precompile, use that address
///           - On other chains, deploy an Ed25519 verifier contract and point to it
///
///         Expected precompile/contract interface:
///           Input:  hash (32) || rs (64) || pubKey (32)  — 128 bytes
///           Output: 32 bytes where uint256 == 1 is valid, 0 is invalid
contract Ed25519Verifier is IAuthVerifier {
    address public immutable ED25519_VERIFIER;

    constructor(address ed25519Verifier) {
        ED25519_VERIFIER = ed25519Verifier;
    }

    function verify(address, bytes32 keyId, bytes32 hash, bytes calldata data) external view returns (bool) {
        require(data.length == 96);
        require(keccak256(data[64:96]) == keyId);

        // Encode: hash (32) || signature (64) || publicKey (32) = 128 bytes
        bytes memory input = abi.encodePacked(hash, data);

        (bool success, bytes memory result) = ED25519_VERIFIER.staticcall(input);
        if (!success || result.length < 32) return false;

        return abi.decode(result, (uint256)) == 1;
    }
}
