// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.30;

import {Script, console} from "forge-std/Script.sol";
import {SandboxLib} from "../src/SandboxLib.sol";

/// @notice Deploy a sandbox wrapper around an existing verifier contract.
///
///         This script is a thin CLI wrapper around SandboxLib.deploy().
///         It reads the runtime bytecode from an already-deployed verifier,
///         deploys a 52-byte sandbox wrapper that STATICCALL-forwards to it,
///         and logs the result.
///
///         Usage (forge script):
///           forge script script/DeploySandboxVerifier.s.sol \
///             --sig "run(address,uint8,bytes32)" \
///             <verifier_address> <version> <salt> \
///             --broadcast
contract DeploySandboxVerifier is Script {
    /// @notice Deploy a sandbox wrapper for an already-deployed verifier.
    /// @param verifier Address of the deployed verifier
    /// @param version  Sandbox interface version (0 for current)
    /// @param salt     CREATE2 salt
    function run(address verifier, uint8 version, bytes32 salt) public {
        require(verifier.code.length > 0, "no bytecode at verifier address");

        vm.startBroadcast();
        address sandbox = SandboxLib.deploy(verifier, version, salt);
        vm.stopBroadcast();

        console.log("Verifier:       ", verifier);
        console.log("Sandbox wrapper:", sandbox);

        (uint8 ver, address wrapped, bool valid) = SandboxLib.parseSandboxHeader(sandbox);
        require(valid, "invalid sandbox header");
        console.log("  magic=8130, version=%d, wraps=%s", ver, wrapped);
    }
}
