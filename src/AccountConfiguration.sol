// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;

import {IERC1271} from "openzeppelin/interfaces/IERC1271.sol";
import {IAuthVerifier} from "./verifiers/IAuthVerifier.sol";
import {AccountConfigEIP712, KeyOperation, AccountOperation} from "./AccountConfigEIP712.sol";
import {AccountDeployer, InitialKey} from "./AccountDeployer.sol";

struct KeyConfig {
    address verifier;
    uint8 flags;
}

struct AccountPolicy {
    uint8 flags;
    uint32 unlockDelay;
    uint32 unlockRequestedAt;
}

/// @notice Account Configuration system contract for EIP-8130.
///         Manages key authorization, account creation, change sequencing, and account policy.
contract AccountConfiguration is AccountConfigEIP712, AccountDeployer {
    // ──────────────────────────────────────────────
    //  Constants
    // ──────────────────────────────────────────────

    uint8 constant OP_AUTHORIZE_KEY = 0x01;
    uint8 constant OP_REVOKE_KEY = 0x02;
    uint8 constant OP_SET_ACCOUNT_POLICY = 0x03;
    uint8 constant OP_REQUEST_UNLOCK = 0x04;
    uint8 constant OP_UNLOCK = 0x05;

    uint8 constant FLAG_DISABLE_KEY_ADMIN = 0x01;
    uint8 constant FLAG_DISABLE_GAS_PAYMENT = 0x02;

    uint8 constant POLICY_LOCKED = 0x01;

    // ──────────────────────────────────────────────
    //  Storage
    // ──────────────────────────────────────────────

    mapping(address account => mapping(bytes32 keyId => KeyConfig)) internal _keyConfigs;
    mapping(address account => AccountPolicy) internal _accountPolicies;

    struct ChangeSequences {
        uint64 multichain; // chain_id 0
        uint64 local;      // chain_id == block.chainid
    }

    mapping(address account => ChangeSequences) internal _changeSequences;

    // ──────────────────────────────────────────────
    //  Events
    // ──────────────────────────────────────────────

    event KeyAuthorized(address indexed account, bytes32 indexed keyId, address verifier, uint8 flags);
    event KeyRevoked(address indexed account, bytes32 indexed keyId);
    event AccountCreated(address indexed account, bytes32 userSalt, bytes32 codeHash);
    event ChangeApplied(address indexed account, uint64 sequence);
    event AccountPolicyChanged(address indexed account, uint8 flags, uint32 unlockDelay);
    event AccountLocked(address indexed account, uint32 unlockDelay);
    event UnlockRequested(address indexed account, uint32 effectiveAt);
    event AccountUnlocked(address indexed account);

    // ══════════════════════════════════════════════
    //  ACCOUNT CREATION
    // ══════════════════════════════════════════════

    /// @notice Deploy a new account with initial keys configured using safe defaults.
    function createAccount(bytes32 userSalt, bytes calldata bytecode, InitialKey[] calldata initialKeys)
        external
        returns (address account)
    {
        account = getAddress(userSalt, bytecode, initialKeys);
        if (account.code.length > 0) return account;

        require(initialKeys.length > 0);

        bytes32 previousKeyId;
        for (uint256 i; i < initialKeys.length; i++) {
            require(initialKeys[i].keyId > previousKeyId);
            previousKeyId = initialKeys[i].keyId;
            require(initialKeys[i].verifier != address(0));

            _keyConfigs[account][initialKeys[i].keyId] = KeyConfig(initialKeys[i].verifier, 0);
            emit KeyAuthorized(account, initialKeys[i].keyId, initialKeys[i].verifier, 0);
        }

        _accountPolicies[account] = AccountPolicy(0, 0, 0);

        _deploy(bytecode, initialKeys, userSalt);
        emit AccountCreated(account, userSalt, keccak256(bytecode));
    }

    // ══════════════════════════════════════════════
    //  PORTABLE CHANGES (EVM path — ERC-1271 authorized)
    // ══════════════════════════════════════════════

    /// @notice Apply key operations authorized by the account's isValidSignature.
    function applyKeyChange(
        address account,
        uint64 chainId,
        uint64 sequence,
        KeyOperation[] calldata operations,
        bytes calldata authorizerAuth
    ) external {
        _requireNotLocked(account);

        require(chainId == 0 || chainId == block.chainid);

        require(_getSequence(account, chainId) == sequence);
        _setSequence(account, chainId, sequence + 1);

        bytes32 digest = _computeKeyChangeDigest(account, chainId, sequence, operations);

        bytes32 authorizerKeyId = abi.decode(authorizerAuth, (bytes32));
        require((_keyConfigs[account][authorizerKeyId].flags & FLAG_DISABLE_KEY_ADMIN) == 0);

        _requireValidSignature(account, digest, authorizerAuth);

        for (uint256 i; i < operations.length; i++) {
            _applyKeyOperation(account, operations[i]);
        }
        emit ChangeApplied(account, sequence);
    }

    /// @notice Apply account policy operations authorized by the account's isValidSignature.
    function applyAccountChange(
        address account,
        uint64 chainId,
        uint64 sequence,
        AccountOperation[] calldata operations,
        bytes calldata authorizerAuth
    ) external {
        _requireNotLockedOrUnlockOps(account, operations);

        require(chainId == 0 || chainId == block.chainid);

        for (uint256 i; i < operations.length; i++) {
            if (operations[i].opType == OP_REQUEST_UNLOCK || operations[i].opType == OP_UNLOCK) {
                require(chainId != 0);
            }
        }

        require(_getSequence(account, chainId) == sequence);
        _setSequence(account, chainId, sequence + 1);

        bytes32 digest = _computeAccountChangeDigest(account, chainId, sequence, operations);

        bytes32 authorizerKeyId = abi.decode(authorizerAuth, (bytes32));
        require((_keyConfigs[account][authorizerKeyId].flags & FLAG_DISABLE_KEY_ADMIN) == 0);

        _requireValidSignature(account, digest, authorizerAuth);

        for (uint256 i; i < operations.length; i++) {
            _applyAccountOperation(account, operations[i]);
        }
        emit ChangeApplied(account, sequence);
    }

    // ══════════════════════════════════════════════
    //  READ FUNCTIONS
    // ══════════════════════════════════════════════

    function isAuthorized(address account, bytes32 keyId) external view returns (bool) {
        return _keyConfigs[account][keyId].verifier != address(0);
    }

    function getKeyData(address account, bytes32 keyId) public view returns (address verifier, uint8 flags) {
        KeyConfig storage kc = _keyConfigs[account][keyId];
        return (kc.verifier, kc.flags);
    }

    function getAccountPolicy(address account)
        public
        view
        returns (bool locked, uint32 unlockDelay, uint32 unlockRequestedAt)
    {
        AccountPolicy storage p = _accountPolicies[account];
        locked = (p.flags & POLICY_LOCKED) != 0;
        unlockDelay = p.unlockDelay;
        unlockRequestedAt = p.unlockRequestedAt;
    }

    function getChangeSequence(address account, uint64 chainId) external view returns (uint64) {
        return _getSequence(account, chainId);
    }

    // ══════════════════════════════════════════════
    //  TRANSACTION CONTEXT (EIP-1153 transient storage)
    // ══════════════════════════════════════════════

    /// @notice Returns the current AA transaction's gas payer address.
    ///         Only meaningful during AA transaction execution on 8130 chains.
    function getCurrentPayer() public view returns (address payer) {
        bytes32 slot = keccak256("context.payer");
        assembly {
            payer := tload(slot)
        }
    }

    /// @notice Returns the current AA transaction's signer key info.
    ///         Protocol writes keyId to transient storage; verifier + flags looked up from persistent storage.
    ///         On non-8130 chains, returns zero values (no protocol writes to transient storage).
    function getCurrentSigner() public view returns (bytes32 keyId, address, uint8) {
        bytes32 signerSlot = keccak256("context.signer");
        assembly {
            keyId := tload(signerSlot)
        }
    }

    // ══════════════════════════════════════════════
    //  SIGNATURE VERIFICATION (for EVM-initiated checks)
    // ══════════════════════════════════════════════

    /// @notice Verify a signature against a key on an account by calling the verifier.
    function verify(address account, bytes32 keyId, bytes32 hash, bytes calldata data) public view returns (bool) {
        address verifier = _keyConfigs[account][keyId].verifier;
        if (verifier == address(0)) return false;
        return IAuthVerifier(verifier).verify(account, keyId, hash, data);
    }

    // ══════════════════════════════════════════════
    //  INTERNALS
    // ══════════════════════════════════════════════

    function _requireValidSignature(address account, bytes32 digest, bytes calldata authorizerAuth) internal view {
        require(account.code.length > 0);
        (bool success, bytes memory result) =
            account.staticcall(abi.encodeWithSignature("isValidSignature(bytes32,bytes)", digest, authorizerAuth));
        require(success && result.length >= 32);
        require(abi.decode(result, (bytes4)) == IERC1271.isValidSignature.selector);
    }

    function _getSequence(address account, uint64 chainId) internal view returns (uint64) {
        ChangeSequences storage s = _changeSequences[account];
        return chainId == 0 ? s.multichain : s.local;
    }

    function _setSequence(address account, uint64 chainId, uint64 value) internal {
        ChangeSequences storage s = _changeSequences[account];
        if (chainId == 0) {
            s.multichain = value;
        } else {
            s.local = value;
        }
    }

    function _requireNotLocked(address account) internal view {
        require((_accountPolicies[account].flags & POLICY_LOCKED) == 0);
    }

    function _requireNotLockedOrUnlockOps(address account, AccountOperation[] calldata operations) internal view {
        if ((_accountPolicies[account].flags & POLICY_LOCKED) != 0) {
            for (uint256 i; i < operations.length; i++) {
                require(operations[i].opType == OP_REQUEST_UNLOCK || operations[i].opType == OP_UNLOCK);
            }
        }
    }

    function _applyKeyOperation(address account, KeyOperation calldata op) internal {
        KeyConfig storage kc = _keyConfigs[account][op.keyId];
        if (op.opType == OP_AUTHORIZE_KEY) {
            require(op.verifier != address(0));
            require(kc.verifier == address(0));
            kc.verifier = op.verifier;
            kc.flags = op.flags;
            emit KeyAuthorized(account, op.keyId, op.verifier, op.flags);
        } else if (op.opType == OP_REVOKE_KEY) {
            require(kc.verifier != address(0));
            delete _keyConfigs[account][op.keyId];
            emit KeyRevoked(account, op.keyId);
        } else {
            revert();
        }
    }

    function _applyAccountOperation(address account, AccountOperation calldata op) internal {
        AccountPolicy storage p = _accountPolicies[account];
        if (op.opType == OP_SET_ACCOUNT_POLICY) {
            p.flags = op.flags;
            p.unlockDelay = op.unlockDelay;
            p.unlockRequestedAt = 0;
            emit AccountPolicyChanged(account, op.flags, op.unlockDelay);
            if ((op.flags & POLICY_LOCKED) != 0) {
                emit AccountLocked(account, op.unlockDelay);
            }
        } else if (op.opType == OP_REQUEST_UNLOCK) {
            require((p.flags & POLICY_LOCKED) != 0 && p.unlockRequestedAt == 0);
            p.unlockRequestedAt = uint32(block.timestamp);
            emit UnlockRequested(account, uint32(block.timestamp) + p.unlockDelay);
        } else if (op.opType == OP_UNLOCK) {
            require((p.flags & POLICY_LOCKED) != 0 && p.unlockRequestedAt != 0);
            require(block.timestamp >= p.unlockRequestedAt + p.unlockDelay);
            p.flags = p.flags & ~uint8(POLICY_LOCKED);
            p.unlockDelay = 0;
            p.unlockRequestedAt = 0;
            emit AccountUnlocked(account);
        } else {
            revert();
        }
    }
}
