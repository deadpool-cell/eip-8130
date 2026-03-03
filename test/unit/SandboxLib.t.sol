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

    function test_wrapperBytecodeIs52Bytes() public view {
        bytes memory code = SandboxLib.wrapperBytecode(address(k1), 0);
        assertEq(code.length, 52);
    }

    function test_wrapperBytecodeStartsWithSandboxHeader() public view {
        bytes memory code = SandboxLib.wrapperBytecode(address(k1), 0);

        // PUSH1 6, JUMP
        assertEq(uint8(code[0]), 0x60);
        assertEq(uint8(code[1]), 0x06);
        assertEq(uint8(code[2]), 0x56);

        // Magic "8130"
        assertEq(uint8(code[3]), 0x81);
        assertEq(uint8(code[4]), 0x30);

        // Version = 0
        assertEq(uint8(code[5]), 0x00);

        // JUMPDEST
        assertEq(uint8(code[6]), 0x5B);
    }

    function test_wrapperBytecodeContainsPUSH20WithAddress() public view {
        bytes memory code = SandboxLib.wrapperBytecode(address(k1), 0);

        // PUSH20 opcode at offset 16
        assertEq(uint8(code[16]), 0x73);

        // Extract 20-byte address from offsets 17-36
        address embedded;
        assembly {
            embedded := shr(96, mload(add(add(code, 0x20), 17)))
        }
        assertEq(embedded, address(k1));
    }

    function test_wrapperBytecodeEndsWithJUMPDESTAndRETURN() public view {
        bytes memory code = SandboxLib.wrapperBytecode(address(k1), 0);

        // REVERT at offset 49, JUMPDEST at 50, RETURN at 51
        assertEq(uint8(code[49]), 0xFD); // REVERT
        assertEq(uint8(code[50]), 0x5B); // JUMPDEST
        assertEq(uint8(code[51]), 0xF3); // RETURN
    }

    function test_wrapperBytecodeUsesSTATICCALL() public view {
        bytes memory code = SandboxLib.wrapperBytecode(address(k1), 0);

        // GAS at offset 37, STATICCALL at offset 38
        assertEq(uint8(code[37]), 0x5A); // GAS
        assertEq(uint8(code[38]), 0xFA); // STATICCALL
    }

    function test_deploymentCodeIs66Bytes() public view {
        bytes memory code = SandboxLib.deploymentCode(address(k1), 0);
        assertEq(code.length, 14 + 52);
    }

    function test_wrapperBytecodeWithNonZeroVersion() public view {
        bytes memory code = SandboxLib.wrapperBytecode(address(k1), 1);
        assertEq(uint8(code[5]), 0x01);
    }

    // ── Deploy and parse ──

    function test_deployAndParseSandboxHeader() public {
        address sandbox = SandboxLib.deploy(address(k1), 0, bytes32("test"));

        (uint8 version, address wrapped, bool valid) = SandboxLib.parseSandboxHeader(sandbox);

        assertTrue(valid);
        assertEq(version, 0);
        assertEq(wrapped, address(k1));
    }

    function test_deployedCodeIs52Bytes() public {
        address sandbox = SandboxLib.deploy(address(k1), 0, bytes32("size"));
        assertEq(sandbox.code.length, 52);
    }

    function test_parseSandboxHeader_invalidIfTooShort() public view {
        (,, bool valid) = SandboxLib.parseSandboxHeader(address(k1));
        assertFalse(valid);
    }

    function test_parseSandboxHeader_invalidIfNoMagic() public {
        address sandbox = SandboxLib.deploy(address(k1), 0, bytes32("magic_test"));

        // Deploy a regular contract and try to parse it — should be invalid
        (,, bool valid) = SandboxLib.parseSandboxHeader(address(new K1Verifier()));
        assertFalse(valid);

        // The actual sandbox should be valid
        (,, valid) = SandboxLib.parseSandboxHeader(sandbox);
        assertTrue(valid);
    }

    // ── Compute address ──

    function test_computeAddressMatchesDeploy() public {
        bytes32 salt = bytes32("predict");
        address predicted = SandboxLib.computeAddress(address(this), address(k1), 0, salt);
        address actual = SandboxLib.deploy(address(k1), 0, salt);
        assertEq(predicted, actual);
    }

    function test_differentSaltsProduceDifferentAddresses() public view {
        address a = SandboxLib.computeAddress(address(this), address(k1), 0, bytes32("a"));
        address b = SandboxLib.computeAddress(address(this), address(k1), 0, bytes32("b"));
        assertTrue(a != b);
    }

    function test_differentVersionsProduceDifferentAddresses() public view {
        address a = SandboxLib.computeAddress(address(this), address(k1), 0, bytes32("same"));
        address b = SandboxLib.computeAddress(address(this), address(k1), 1, bytes32("same"));
        assertTrue(a != b);
    }

    // ── Functional: sandbox wrapper forwards calls correctly ──

    function test_sandboxWrapperForwardsVerifyCalls() public {
        address sandbox = SandboxLib.deploy(address(k1), 0, bytes32("fwd"));

        uint256 pk = 0xBEEF;
        address signer = vm.addr(pk);
        bytes32 keyId = bytes32(bytes20(signer));
        bytes32 hash = keccak256("test message");
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(pk, hash);

        bool result = IAuthVerifier(sandbox).verify(address(0x1), keyId, hash, abi.encodePacked(r, s, v));
        assertTrue(result);
    }

    function test_sandboxWrapperReturnsFalseForBadSignature() public {
        address sandbox = SandboxLib.deploy(address(k1), 0, bytes32("bad"));

        uint256 pk = 0xBEEF;
        address signer = vm.addr(pk);
        bytes32 keyId = bytes32(bytes20(signer));
        bytes32 hash = keccak256("test");
        bytes32 wrongHash = keccak256("wrong");
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(pk, wrongHash);

        bool result = IAuthVerifier(sandbox).verify(address(0x1), keyId, hash, abi.encodePacked(r, s, v));
        assertFalse(result);
    }

    function test_sandboxWrapperPropagatesReverts() public {
        address sandbox = SandboxLib.deploy(address(k1), 0, bytes32("revert"));

        // K1Verifier reverts if keyId doesn't match bytes32(bytes20(addr)) pattern
        bytes32 badKeyId = bytes32(uint256(0xDEAD));

        vm.expectRevert();
        IAuthVerifier(sandbox).verify(address(0x1), badKeyId, bytes32(0), hex"00");
    }

    function test_sandboxWrapperMatchesDirectResult() public {
        address sandbox = SandboxLib.deploy(address(k1), 0, bytes32("match"));

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
