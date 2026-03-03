// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;

/// @notice Library for deploying EIP-8130 sandbox verifier wrappers.
///
///         The sandbox wrapper is a 55-byte contract consisting of:
///
///           [10-byte sandbox header] [45-byte STATICCALL forwarder]
///
///         The sandbox header follows the EIP-8130 format:
///           Byte 0-1:  PUSH1 9      (jump offset to JUMPDEST)
///           Byte 2:    JUMP
///           Byte 3-4:  0x81 0x30    (magic "8130")
///           Byte 5-7:  gas_limit    (uint24, units of 1k gas)
///           Byte 8:    version      (uint8, interface version)
///           Byte 9:    JUMPDEST
///
///         The STATICCALL forwarder is an ERC-1167-style proxy that forwards all
///         calls to the wrapped verifier via STATICCALL. On success the return data
///         is relayed; on failure the revert data is propagated.
///
///         On 8130 chains the protocol reads the header metadata and may use native
///         implementations for known verifiers. On other chains the forwarder acts
///         as a transparent read-only proxy.
///
///         This approach works with any Solidity-compiled verifier — the wrapper
///         bytecode is hand-crafted with no internal JUMPs that depend on absolute
///         offsets, so the 10-byte header shift is fully accounted for.
///
///         For third-party verifiers that must run inside the 8130 sandbox restricted
///         environment (no external calls allowed), use raw EVM bytecode instead of
///         this wrapper.
library SandboxLib {
    uint256 private constant _WRAPPER_SIZE = 55;
    uint256 private constant _DEPLOYMENT_HEADER_SIZE = 14;

    /// @notice Build the 55-byte sandbox wrapper runtime bytecode.
    /// @param verifier   Address of the real verifier to forward calls to
    /// @param gasLimitInK Gas limit in units of 1k gas (e.g. 10 = 10k gas)
    /// @param version    Sandbox interface version (0 for current)
    function wrapperBytecode(address verifier, uint24 gasLimitInK, uint8 version)
        internal
        pure
        returns (bytes memory)
    {
        return abi.encodePacked(
            // ── Sandbox header (10 bytes) ──
            hex"600956", // PUSH1 9, JUMP
            hex"8130", // magic
            bytes3(gasLimitInK),
            bytes1(version),
            hex"5b", // JUMPDEST
            // ── STATICCALL forwarder (45 bytes) ──
            //     Same structure as ERC-1167 minimal proxy but using STATICCALL (0xFA)
            //     instead of DELEGATECALL (0xF4), and with the JUMPI target adjusted
            //     from 0x2B to 0x35 (+10 for the sandbox header).
            hex"363d3d37" // CALLDATASIZE, RETURNDATASIZE, RETURNDATASIZE, CALLDATACOPY
            hex"3d3d3d36" // RETURNDATASIZE×3, CALLDATASIZE  (STATICCALL args setup)
            hex"3d73", // RETURNDATASIZE, PUSH20
            verifier,
            hex"5afa" // GAS, STATICCALL
            hex"3d8280" // RETURNDATASIZE, DUP3, DUP1
            hex"3e" // RETURNDATACOPY
            hex"903d91" // SWAP1, RETURNDATASIZE, SWAP2
            hex"6035" // PUSH1 0x35  (JUMPDEST offset = 53)
            hex"57" // JUMPI
            hex"fd" // REVERT
            hex"5b" // JUMPDEST @53
            hex"f3" // RETURN
        );
    }

    /// @notice Build deployment code: 14-byte deployment header + 55-byte wrapper.
    function deploymentCode(address verifier, uint24 gasLimitInK, uint8 version)
        internal
        pure
        returns (bytes memory)
    {
        bytes memory runtime = wrapperBytecode(verifier, gasLimitInK, version);
        uint16 n = uint16(runtime.length);

        return abi.encodePacked(
            bytes1(0x61), n, // PUSH2 n
            bytes1(0x60), bytes1(0x0E), // PUSH1 14
            bytes1(0x60), bytes1(0x00), // PUSH1 0
            bytes1(0x39), // CODECOPY
            bytes1(0x61), n, // PUSH2 n
            bytes1(0x60), bytes1(0x00), // PUSH1 0
            bytes1(0xF3), // RETURN
            runtime
        );
    }

    /// @notice Deploy a sandbox wrapper via CREATE2.
    /// @return deployed Address of the deployed sandbox wrapper
    function deploy(address verifier, uint24 gasLimitInK, uint8 version, bytes32 salt)
        internal
        returns (address deployed)
    {
        bytes memory code = deploymentCode(verifier, gasLimitInK, version);
        assembly {
            deployed := create2(0, add(code, 0x20), mload(code), salt)
        }
        require(deployed != address(0), "SandboxLib: CREATE2 failed");
    }

    /// @notice Predict the CREATE2 address for a sandbox wrapper deployment.
    function computeAddress(address deployer, address verifier, uint24 gasLimitInK, uint8 version, bytes32 salt)
        internal
        pure
        returns (address)
    {
        bytes32 initCodeHash = keccak256(deploymentCode(verifier, gasLimitInK, version));
        return address(
            uint160(uint256(keccak256(abi.encodePacked(bytes1(0xFF), deployer, salt, initCodeHash))))
        );
    }

    /// @notice Parse the sandbox header and extract the wrapped verifier address
    ///         from a deployed sandbox wrapper.
    function parseSandboxHeader(address deployed)
        internal
        view
        returns (uint24 gasLimitInK, uint8 version, address wrappedVerifier, bool valid)
    {
        bytes memory code = deployed.code;
        if (code.length < _WRAPPER_SIZE) return (0, 0, address(0), false);

        // Validate sandbox header bytes
        if (code[0] != 0x60 || code[1] != 0x09 || code[2] != 0x56) return (0, 0, address(0), false);
        if (code[3] != 0x81 || code[4] != 0x30) return (0, 0, address(0), false);
        if (code[9] != 0x5B) return (0, 0, address(0), false);

        gasLimitInK = uint24(uint8(code[5])) << 16 | uint24(uint8(code[6])) << 8 | uint24(uint8(code[7]));
        version = uint8(code[8]);

        // Validate PUSH20 opcode at forwarder offset 9 (absolute offset 19)
        if (code[19] != 0x73) return (0, 0, address(0), false);

        // Extract 20-byte address starting at absolute offset 20
        assembly {
            wrappedVerifier := shr(96, mload(add(add(code, 0x20), 20)))
        }
        valid = true;
    }
}
