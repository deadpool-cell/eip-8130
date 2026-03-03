// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;

import {Receiver} from "solady/accounts/Receiver.sol";

import {AccountConfiguration} from "../AccountConfiguration.sol";
import {IAuthVerifier} from "../verifiers/IAuthVerifier.sol";

/// @notice Default account implementation for EIP-8130.
///         Deployed behind ERC-1167 minimal proxy (45 bytes, deterministic pattern).
///         Enforces ETH movement restrictions when account is locked.
contract DefaultAccount is Receiver {
    struct Call {
        address target;
        bytes data;
        uint256 value;
    }

    AccountConfiguration public immutable ACCOUNT_CONFIGURATION;

    constructor(address accountConfiguration) {
        ACCOUNT_CONFIGURATION = AccountConfiguration(accountConfiguration);
    }

    /// @notice Execute a batch of calls. Only callable via self-call (protocol delivers calldata this way).
    function executeBatch(Call[] calldata calls) external {
        require(msg.sender == address(this));

        (bool locked,,) = ACCOUNT_CONFIGURATION.getAccountPolicy(address(this));

        for (uint256 i; i < calls.length; i++) {
            if (locked) require(calls[i].value == 0);
            (bool success,) = calls[i].target.call{value: calls[i].value}(calls[i].data);
            require(success);
        }
    }

    /// @notice ERC-1271 signature validation. Used by AccountConfiguration for portable change authorization.
    /// @param hash The digest to verify
    /// @param signature ABI-encoded (bytes32 keyId, bytes verifierData)
    /// @return magicValue 0x1626ba7e if valid, 0xffffffff otherwise
    function isValidSignature(bytes32 hash, bytes calldata signature) external view returns (bytes4) {
        (bytes32 keyId, bytes memory data) = abi.decode(signature, (bytes32, bytes));
        (address verifier,) = ACCOUNT_CONFIGURATION.getKeyData(address(this), keyId);
        if (verifier == address(0)) return bytes4(0xFFFFFFFF);
        if (!IAuthVerifier(verifier).verify(address(this), keyId, hash, data)) return bytes4(0xFFFFFFFF);
        return bytes4(0x1626ba7e);
    }
}
