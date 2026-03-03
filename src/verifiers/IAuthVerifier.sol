// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

/// @notice Verifier interface for EIP-8130 signature verification.
interface IAuthVerifier {
    /// @param account The account to verify the signature for
    /// @param keyId The keyId to verify the signature for
    /// @param hash The hash to verify the signature for
    /// @param data Verifier-specific signature data
    /// @return true if the signature is valid, false otherwise
    function verify(address account, bytes32 keyId, bytes32 hash, bytes calldata data)
        external
        view
        returns (bool);
}
