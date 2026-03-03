// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;

import {Test} from "forge-std/Test.sol";

import {SandboxLib} from "../../src/SandboxLib.sol";
import {IAuthVerifier} from "../../src/verifiers/IAuthVerifier.sol";
import {K1Verifier} from "../../src/verifiers/K1Verifier.sol";
import {ECDSA} from "openzeppelin/utils/cryptography/ECDSA.sol";

contract SandboxLibTest is Test {
    K1Verifier k1;

    function setUp() public {
        k1 = new K1Verifier();
    }

    // ── Bytecode construction ──

    function test_wrapperBytecodeIs55Bytes() public view {
        bytes memory code = SandboxLib.wrapperBytecode(address(k1), 10, 0);
        assertEq(code.length, 55);
    }

    function test_wrapperBytecodeStartsWithSandboxHeader() public view {
        bytes memory code = SandboxLib.wrapperBytecode(address(k1), 10, 0);

        // PUSH1 9, JUMP
        assertEq(uint8(code[0]), 0x60);
        assertEq(uint8(code[1]), 0x09);
        assertEq(uint8(code[2]), 0x56);

        // Magic "8130"
        assertEq(uint8(code[3]), 0x81);
        assertEq(uint8(code[4]), 0x30);

        // Gas limit = 10 (0x00000a)
        assertEq(uint8(code[5]), 0x00);
        assertEq(uint8(code[6]), 0x00);
        assertEq(uint8(code[7]), 0x0a);

        // Version = 0
        assertEq(uint8(code[8]), 0x00);

        // JUMPDEST
        assertEq(uint8(code[9]), 0x5B);
    }

    function test_wrapperBytecodeContainsPUSH20WithAddress() public view {
        bytes memory code = SandboxLib.wrapperBytecode(address(k1), 10, 0);

        // PUSH20 opcode at offset 19
        assertEq(uint8(code[19]), 0x73);

        // Extract 20-byte address from offsets 20-39
        address embedded;
        assembly {
            embedded := shr(96, mload(add(add(code, 0x20), 20)))
        }
        assertEq(embedded, address(k1));
    }

    function test_wrapperBytecodeEndsWithJUMPDESTAndRETURN() public view {
        bytes memory code = SandboxLib.wrapperBytecode(address(k1), 10, 0);

        // REVERT at offset 52, JUMPDEST at 53, RETURN at 54
        assertEq(uint8(code[52]), 0xFD); // REVERT
        assertEq(uint8(code[53]), 0x5B); // JUMPDEST
        assertEq(uint8(code[54]), 0xF3); // RETURN
    }

    function test_wrapperBytecodeUsesSTATICCALL() public view {
        bytes memory code = SandboxLib.wrapperBytecode(address(k1), 10, 0);

        // GAS at offset 40, STATICCALL at offset 41
        assertEq(uint8(code[40]), 0x5A); // GAS
        assertEq(uint8(code[41]), 0xFA); // STATICCALL
    }

    function test_deploymentCodeIs69Bytes() public view {
        bytes memory code = SandboxLib.deploymentCode(address(k1), 10, 0);
        assertEq(code.length, 14 + 55);
    }

    // ── Deploy and parse ──

    function test_deployAndParseSandboxHeader() public {
        address sandbox = SandboxLib.deploy(address(k1), 10, 0, bytes32("test"));

        (uint24 gasLimitInK, uint8 version, address wrapped, bool valid) =
            SandboxLib.parseSandboxHeader(sandbox);

        assertTrue(valid);
        assertEq(gasLimitInK, 10);
        assertEq(version, 0);
        assertEq(wrapped, address(k1));
    }

    function test_deployedCodeIs55Bytes() public {
        address sandbox = SandboxLib.deploy(address(k1), 10, 0, bytes32("size"));
        assertEq(sandbox.code.length, 55);
    }

    function test_parseSandboxHeader_invalidIfTooShort() public {
        (,,, bool valid) = SandboxLib.parseSandboxHeader(address(k1));
        assertFalse(valid);
    }

    function test_parseSandboxHeader_invalidIfNoMagic() public {
        address sandbox = SandboxLib.deploy(address(k1), 10, 0, bytes32("magic_test"));

        // Deploy a regular contract and try to parse it — should be invalid
        (,,, bool valid) = SandboxLib.parseSandboxHeader(address(new K1Verifier()));
        assertFalse(valid);

        // The actual sandbox should be valid
        (,,, valid) = SandboxLib.parseSandboxHeader(sandbox);
        assertTrue(valid);
    }

    // ── Compute address ──

    function test_computeAddressMatchesDeploy() public {
        bytes32 salt = bytes32("predict");
        address predicted = SandboxLib.computeAddress(address(this), address(k1), 10, 0, salt);
        address actual = SandboxLib.deploy(address(k1), 10, 0, salt);
        assertEq(predicted, actual);
    }

    function test_differentSaltsProduceDifferentAddresses() public view {
        address a = SandboxLib.computeAddress(address(this), address(k1), 10, 0, bytes32("a"));
        address b = SandboxLib.computeAddress(address(this), address(k1), 10, 0, bytes32("b"));
        assertTrue(a != b);
    }

    function test_differentGasLimitsProduceDifferentAddresses() public view {
        address a = SandboxLib.computeAddress(address(this), address(k1), 10, 0, bytes32("same"));
        address b = SandboxLib.computeAddress(address(this), address(k1), 20, 0, bytes32("same"));
        assertTrue(a != b);
    }

    // ── Functional: sandbox wrapper forwards calls correctly ──

    function test_sandboxWrapperForwardsVerifyCalls() public {
        address sandbox = SandboxLib.deploy(address(k1), 10, 0, bytes32("fwd"));

        uint256 pk = 0xBEEF;
        address signer = vm.addr(pk);
        bytes32 keyId = bytes32(bytes20(signer));
        bytes32 hash = keccak256("test message");
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(pk, hash);

        bool result = IAuthVerifier(sandbox).verify(
            address(0x1), keyId, hash, abi.encodePacked(r, s, v)
        );
        assertTrue(result);
    }

    function test_sandboxWrapperReturnsFalseForBadSignature() public {
        address sandbox = SandboxLib.deploy(address(k1), 10, 0, bytes32("bad"));

        uint256 pk = 0xBEEF;
        address signer = vm.addr(pk);
        bytes32 keyId = bytes32(bytes20(signer));
        bytes32 hash = keccak256("test");
        bytes32 wrongHash = keccak256("wrong");
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(pk, wrongHash);

        bool result = IAuthVerifier(sandbox).verify(
            address(0x1), keyId, hash, abi.encodePacked(r, s, v)
        );
        assertFalse(result);
    }

    function test_sandboxWrapperPropagatesReverts() public {
        address sandbox = SandboxLib.deploy(address(k1), 10, 0, bytes32("revert"));

        // K1Verifier reverts if keyId doesn't match bytes32(bytes20(addr)) pattern
        bytes32 badKeyId = bytes32(uint256(0xDEAD));

        vm.expectRevert();
        IAuthVerifier(sandbox).verify(
            address(0x1), badKeyId, bytes32(0), hex"00"
        );
    }

    function test_sandboxWrapperMatchesDirectResult() public {
        address sandbox = SandboxLib.deploy(address(k1), 10, 0, bytes32("match"));

        uint256 pk = 0xCAFE;
        address signer = vm.addr(pk);
        bytes32 keyId = bytes32(bytes20(signer));
        bytes32 hash = keccak256("matching test");
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(pk, hash);
        bytes memory sig = abi.encodePacked(r, s, v);

        bool direct = IAuthVerifier(address(k1)).verify(address(0x1), keyId, hash, sig);
        bool viaSandbox = IAuthVerifier(sandbox).verify(address(0x1), keyId, hash, sig);

        assertEq(direct, viaSandbox);
    }
}
