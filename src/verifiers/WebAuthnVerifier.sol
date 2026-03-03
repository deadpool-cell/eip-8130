// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;

import {WebAuthn} from "openzeppelin/utils/cryptography/WebAuthn.sol";

import {IAuthVerifier} from "./IAuthVerifier.sol";

/// @notice P-256 WebAuthn/Passkey verifier. keyId = keccak256(pub_key_x || pub_key_y).
contract WebAuthnVerifier is IAuthVerifier {
    function verify(address, bytes32 keyId, bytes32 hash, bytes calldata data) external view returns (bool) {
        (WebAuthn.WebAuthnAuth memory auth, bytes32 x, bytes32 y) =
            abi.decode(data, (WebAuthn.WebAuthnAuth, bytes32, bytes32));
        require(keccak256(abi.encodePacked(x, y)) == keyId);
        return WebAuthn.verify({challenge: abi.encode(hash), auth: auth, qx: x, qy: y, requireUV: false});
    }
}
