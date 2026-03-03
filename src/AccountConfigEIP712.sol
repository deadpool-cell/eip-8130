// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;

struct KeyOperation {
    uint8 opType;
    address verifier;
    bytes32 keyId;
    uint8 flags;
}

struct AccountOperation {
    uint8 opType;
    uint8 flags;
    uint32 unlockDelay;
}

/// @notice EIP-712 typed structured data hashing for EIP-8130 account changes.
///         Domain separator is chain-agnostic (chainId intentionally omitted) because
///         operations with chain_id = 0 are designed for cross-chain replay.
abstract contract AccountConfigEIP712 {
    bytes32 constant DOMAIN_TYPEHASH = keccak256("EIP712Domain(string name,string version,address verifyingContract)");

    bytes32 constant ACCOUNT_CHANGE_TYPEHASH = keccak256(
        "AccountChange(address account,uint64 chainId,uint64 sequence,AccountOperation[] operations)"
        "AccountOperation(uint8 opType,uint8 flags,uint32 unlockDelay)"
    );
    bytes32 constant ACCOUNT_OPERATION_TYPEHASH =
        keccak256("AccountOperation(uint8 opType,uint8 flags,uint32 unlockDelay)");

    bytes32 constant KEY_CHANGE_TYPEHASH = keccak256(
        "KeyChange(address account,uint64 chainId,uint64 sequence,KeyOperation[] operations)"
        "KeyOperation(uint8 opType,address verifier,bytes32 keyId,uint8 flags)"
    );
    bytes32 constant KEY_OPERATION_TYPEHASH =
        keccak256("KeyOperation(uint8 opType,address verifier,bytes32 keyId,uint8 flags)");

    bytes32 public immutable DOMAIN_SEPARATOR;

    constructor() {
        DOMAIN_SEPARATOR = keccak256(
            abi.encode(DOMAIN_TYPEHASH, keccak256("AccountConfig"), keccak256("1"), address(this))
        );
    }

    function _computeKeyChangeDigest(
        address account,
        uint64 chainId,
        uint64 sequence,
        KeyOperation[] calldata operations
    ) internal view returns (bytes32) {
        bytes32[] memory opHashes = new bytes32[](operations.length);
        for (uint256 i; i < operations.length; i++) {
            opHashes[i] = keccak256(
                abi.encode(
                    KEY_OPERATION_TYPEHASH,
                    operations[i].opType,
                    operations[i].verifier,
                    operations[i].keyId,
                    operations[i].flags
                )
            );
        }
        bytes32 structHash = keccak256(
            abi.encode(KEY_CHANGE_TYPEHASH, account, chainId, sequence, keccak256(abi.encodePacked(opHashes)))
        );
        return keccak256(abi.encodePacked("\x19\x01", DOMAIN_SEPARATOR, structHash));
    }

    function _computeAccountChangeDigest(
        address account,
        uint64 chainId,
        uint64 sequence,
        AccountOperation[] calldata operations
    ) internal view returns (bytes32) {
        bytes32[] memory opHashes = new bytes32[](operations.length);
        for (uint256 i; i < operations.length; i++) {
            opHashes[i] = keccak256(
                abi.encode(
                    ACCOUNT_OPERATION_TYPEHASH, operations[i].opType, operations[i].flags, operations[i].unlockDelay
                )
            );
        }
        bytes32 structHash = keccak256(
            abi.encode(ACCOUNT_CHANGE_TYPEHASH, account, chainId, sequence, keccak256(abi.encodePacked(opHashes)))
        );
        return keccak256(abi.encodePacked("\x19\x01", DOMAIN_SEPARATOR, structHash));
    }
}
