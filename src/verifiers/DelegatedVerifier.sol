// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;

import {IVerifier} from "./IVerifier.sol";
import {AccountConfiguration} from "../AccountConfiguration.sol";

contract DelegatedVerifier is IVerifier {
    AccountConfiguration public immutable ACCOUNT_CONFIGURATION;

    constructor(address accountConfiguration) {
        ACCOUNT_CONFIGURATION = AccountConfiguration(accountConfiguration);
    }

    // TODO: Add ERC-7739 rehashing?
    function verifyIntent(address account, bytes32 ownerId, bytes32 hash, bytes calldata data)
        external
        view
        returns (bool)
    {
        // Commitment must be a valid address
        address delegate = address(bytes20(ownerId));
        require(bytes32(bytes20(delegate)) == ownerId);

        // Verify nested verification
        (bytes32 nestedOwnerId, bytes memory nestedData) = abi.decode(data, (bytes32, bytes));
        return ACCOUNT_CONFIGURATION.verifyIntent(delegate, nestedOwnerId, hash, nestedData);
    }
}
