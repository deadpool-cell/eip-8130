// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import {ECDSA} from "openzeppelin/utils/cryptography/ECDSA.sol";

import {IVerifier} from "./IVerifier.sol";

contract K1Verifier is IVerifier {
    function verifyIntent(address account, bytes32 ownerId, bytes32 hash, bytes calldata data)
        external
        pure
        returns (bool)
    {
        // Commitment must be a valid address
        address owner = address(bytes20(ownerId));
        require(bytes32(bytes20(owner)) == ownerId);

        // Verify recovered address matches owner
        return owner == ECDSA.recover(hash, data);
    }
}
