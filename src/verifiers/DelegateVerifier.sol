// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;

import {IAuthVerifier} from "./IAuthVerifier.sol";
import {AccountConfiguration} from "../AccountConfiguration.sol";

/// @notice Delegates verification to another account's key configuration.
///         keyId = bytes32(bytes20(delegate_address)). Only 1 hop permitted.
contract DelegateVerifier is IAuthVerifier {
    AccountConfiguration public immutable ACCOUNT_CONFIGURATION;

    constructor(address accountConfiguration) {
        ACCOUNT_CONFIGURATION = AccountConfiguration(accountConfiguration);
    }

    function verify(address, bytes32 keyId, bytes32 hash, bytes calldata data) external view returns (bool) {
        address delegate = address(bytes20(keyId));
        require(bytes32(bytes20(delegate)) == keyId);

        (bytes32 nestedKeyId, bytes memory nestedData) = abi.decode(data, (bytes32, bytes));
        (address nestedVerifier,) = ACCOUNT_CONFIGURATION.getKeyData(delegate, nestedKeyId);
        require(nestedVerifier != address(0));
        require(nestedVerifier != address(this));

        return IAuthVerifier(nestedVerifier).verify(delegate, nestedKeyId, hash, nestedData);
    }
}
