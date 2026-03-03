// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import {ECDSA} from "openzeppelin/utils/cryptography/ECDSA.sol";

import {IAuthVerifier} from "./IAuthVerifier.sol";

/// @notice secp256k1 ECDSA verifier. keyId = bytes32(bytes20(address)).
contract K1Verifier is IAuthVerifier {
    function verify(address, bytes32 keyId, bytes32 hash, bytes calldata data) external pure returns (bool) {
        address key = address(bytes20(keyId));
        require(bytes32(bytes20(key)) == keyId);
        return key == ECDSA.recover(hash, data);
    }
}
