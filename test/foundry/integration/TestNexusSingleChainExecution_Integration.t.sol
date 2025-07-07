// SPDX-License-Identifier: MIT
pragma solidity ^0.8.27;

import "../utils/Imports.sol";
import "../utils/NexusTest_Base.t.sol";
import { Execution } from "../../../contracts/types/DataTypes.sol";
import { EIP712Hash } from "../../../contracts/types/EIP712Type.sol";
import { INexusEventsAndErrors } from "../../../contracts/interfaces/INexusEventsAndErrors.sol";
import { IModuleManagerEventsAndErrors } from "../../../contracts/interfaces/base/IModuleManagerEventsAndErrors.sol";
import { MockSimpleValidator } from "../../../../../contracts/mocks/MockSimpleValidator.sol";

/// @title TestNexusSingleChainExecution_Integration
/// @notice Integration tests for Nexus smart account's executeWithSig function (single chain)
/// @dev Tests the simplified single-chain execution flow with signature validation
contract TestNexusSingleChainExecution_Integration is NexusTest_Base {
    using EIP712Hash for Execution[];
    using EIP712Hash for bytes32;

    Vm.Wallet private user;
    Nexus private nexusAccount;
    MockPaymaster private paymaster;
    MockTarget private target;
    MockSimpleValidator SIMPLE_VALIDATOR_MODULE;

    uint256 private constant CURRENT_CHAIN_ID = 31_337;

    /// @notice Sets up the initial state for the tests
    function setUp() public {
        init();

        user = createAndFundWallet("user", 100 ether);
        nexusAccount = deployNexus(user, 10 ether, address(VALIDATOR_MODULE));

        paymaster = new MockPaymaster(address(ENTRYPOINT), BUNDLER_ADDRESS);
        ENTRYPOINT.depositTo{ value: 10 ether }(address(paymaster));

        target = new MockTarget();
        vm.deal(address(nexusAccount), 10 ether);

        SIMPLE_VALIDATOR_MODULE = new MockSimpleValidator();
        installModule();
    }

    function installModule() internal {
        uint256 moduleTypeId = MODULE_TYPE_VALIDATOR;
        address moduleAddress = address(SIMPLE_VALIDATOR_MODULE);
        ExecType execType = EXECTYPE_DEFAULT;
        bytes memory validatorSetupData = abi.encodePacked(ALICE_ADDRESS); // Set ALICE as owner

        vm.prank(0x0000000071727De22E5E9d8BAf0edAc6f37da032);
        nexusAccount.installModule(MODULE_TYPE_VALIDATOR, address(SIMPLE_VALIDATOR_MODULE), validatorSetupData);
    }

    /// @notice Test successful execution of a single transaction
    /// @dev Tests signature validation and execution for single chain flow
    function test_ExecuteWithSig_SingleTransaction() public {
        // Prepare execution data
        Execution[] memory executions = new Execution[](1);
        executions[0] = Execution({ target: address(target), value: 1 ether, callData: abi.encodeWithSelector(MockTarget.receiveEther.selector) });

        uint256 nonce = 123;

        // Create hash for single chain execution
        bytes32 hash = EIP712Hash.hashChainExecutions(block.chainid, nonce, _hashExecutionsMemory(executions));
        bytes32 digest = _createDigestSansChainId(hash);

        // Create signature with validator address prepended
        bytes memory signature = _createSignature(digest);

        // Record balance before execution
        uint256 balanceBefore = address(target).balance;

        // Call executeWithSig (single chain version)
        vm.prank(user.addr);
        nexusAccount.executeWithSig(executions, nonce, signature);

        // Verify execution occurred
        assertEq(address(target).balance, balanceBefore + 1 ether, "Target should have received 1 ether");
    }

    /// @notice Test execution with multiple transactions in a single call
    /// @dev Tests batch execution in single chain flow
    function test_ExecuteWithSig_BatchTransactions() public {
        // Deploy additional targets
        MockTarget target2 = new MockTarget();
        MockTarget target3 = new MockTarget();

        // Prepare multiple executions
        Execution[] memory executions = new Execution[](3);
        executions[0] = Execution({ target: address(target), value: 0.5 ether, callData: abi.encodeWithSelector(MockTarget.receiveEther.selector) });
        executions[1] = Execution({ target: address(target2), value: 0.3 ether, callData: abi.encodeWithSelector(MockTarget.receiveEther.selector) });
        executions[2] = Execution({ target: address(target3), value: 0, callData: abi.encodeWithSelector(MockTarget.setValue.selector, 42) });

        uint256 nonce = 456;

        // Create hash for single chain execution
        bytes32 hash = EIP712Hash.hashChainExecutions(block.chainid, nonce, _hashExecutionsMemory(executions));
        bytes32 digest = _createDigestSansChainId(hash);
        bytes memory signature = _createSignature(digest);

        // Record balances before
        uint256 balance1Before = address(target).balance;
        uint256 balance2Before = address(target2).balance;

        // Call executeWithSig (single chain version)
        vm.prank(user.addr);
        nexusAccount.executeWithSig(executions, nonce, signature);

        // Verify executions occurred
        assertEq(address(target).balance, balance1Before + 0.5 ether, "Target 1 should have received 0.5 ether");
        assertEq(address(target2).balance, balance2Before + 0.3 ether, "Target 2 should have received 0.3 ether");
        assertEq(target3.value(), 42, "Target 3 should have value set to 42");
    }

    /// @notice Test that single chain executeWithSig now uses nonce validation
    /// @dev The single chain version now implements nonce validation like the multi-chain version
    function test_ExecuteWithSig_NonceValidation() public {
        // Prepare execution data
        Execution[] memory executions = new Execution[](1);
        executions[0] = Execution({ target: address(target), value: 1 ether, callData: abi.encodeWithSelector(MockTarget.receiveEther.selector) });

        uint256 nonce = 789; // Use a specific nonce

        // Create hash and signature
        bytes32 hash = EIP712Hash.hashChainExecutions(block.chainid, nonce, _hashExecutionsMemory(executions));
        bytes32 digest = _createDigestSansChainId(hash);
        bytes memory signature = _createSignature(digest);

        uint256 balanceBefore = address(target).balance;

        // Execute transaction
        vm.prank(user.addr);
        nexusAccount.executeWithSig(executions, nonce, signature);

        // Verify execution occurred
        assertEq(address(target).balance, balanceBefore + 1 ether, "Target should have received 1 ether");

        // Single chain version now validates nonces - reusing the same nonce should fail
        vm.prank(user.addr);
        vm.expectRevert(IModuleManagerEventsAndErrors.InvalidNonce.selector);
        nexusAccount.executeWithSig(executions, nonce, signature);
    }

    /// @notice Test that different nonces work independently with nonce validation
    function test_ExecuteWithSig_DifferentNonces() public {
        // Prepare first execution with nonce 100
        Execution[] memory executions1 = new Execution[](1);
        executions1[0] = Execution({ target: address(target), value: 0.5 ether, callData: abi.encodeWithSelector(MockTarget.receiveEther.selector) });

        uint256 nonce1 = 100;
        bytes32 hash1 = EIP712Hash.hashChainExecutions(block.chainid, nonce1, _hashExecutionsMemory(executions1));
        bytes32 digest1 = _createDigestSansChainId(hash1);
        bytes memory signature1 = _createSignature(digest1);

        // Prepare second execution with nonce 200
        Execution[] memory executions2 = new Execution[](1);
        executions2[0] = Execution({ target: address(target), value: 0.3 ether, callData: abi.encodeWithSelector(MockTarget.receiveEther.selector) });

        uint256 nonce2 = 200;
        bytes32 hash2 = EIP712Hash.hashChainExecutions(block.chainid, nonce2, _hashExecutionsMemory(executions2));
        bytes32 digest2 = _createDigestSansChainId(hash2);
        bytes memory signature2 = _createSignature(digest2);

        uint256 balanceBefore = address(target).balance;

        // Execute both transactions with different nonces - both should succeed
        vm.prank(user.addr);
        nexusAccount.executeWithSig(executions1, nonce1, signature1);

        vm.prank(user.addr);
        nexusAccount.executeWithSig(executions2, nonce2, signature2);

        // Verify both executions occurred
        assertEq(address(target).balance, balanceBefore + 0.8 ether, "Target should have received 0.8 ether total");

        // Now try to reuse nonce1 - should fail with nonce validation
        vm.prank(user.addr);
        vm.expectRevert(IModuleManagerEventsAndErrors.InvalidNonce.selector);
        nexusAccount.executeWithSig(executions1, nonce1, signature1);

        // And try to reuse nonce2 - should also fail
        vm.prank(user.addr);
        vm.expectRevert(IModuleManagerEventsAndErrors.InvalidNonce.selector);
        nexusAccount.executeWithSig(executions2, nonce2, signature2);
    }

    /// @notice Test validation with invalid signature should revert
    function test_ExecuteWithSig_InvalidSignature_Reverts() public {
        Execution[] memory executions = new Execution[](1);
        executions[0] = Execution({ target: address(target), value: 1 ether, callData: abi.encodeWithSelector(MockTarget.receiveEther.selector) });

        uint256 nonce = 999;

        // Create hash
        bytes32 hash = EIP712Hash.hashChainExecutions(block.chainid, nonce, _hashExecutionsMemory(executions));
        bytes32 digest = _createDigestSansChainId(hash);

        // Sign with wrong wallet (BOB instead of ALICE)
        bytes memory signature = abi.encodePacked(address(SIMPLE_VALIDATOR_MODULE), signMessage(BOB, digest));

        // Should revert due to invalid signature
        vm.prank(user.addr);
        vm.expectRevert(INexusEventsAndErrors.InvalidSignature.selector);
        nexusAccount.executeWithSig(executions, nonce, signature);
    }

    /// @notice Test execution from any caller (signature-based auth)
    function test_ExecuteWithSig_AnyCaller() public {
        Execution[] memory executions = new Execution[](1);
        executions[0] = Execution({ target: address(target), value: 1 ether, callData: abi.encodeWithSelector(MockTarget.receiveEther.selector) });

        uint256 nonce = 333;

        bytes32 hash = EIP712Hash.hashChainExecutions(block.chainid, nonce, _hashExecutionsMemory(executions));
        bytes32 digest = _createDigestSansChainId(hash);
        bytes memory signature = _createSignature(digest);

        // Record balance before execution
        uint256 balanceBefore = address(target).balance;

        // Anyone should be able to submit the transaction as it's validated by signature
        vm.prank(ALICE.addr);
        nexusAccount.executeWithSig(executions, nonce, signature);

        // Verify execution occurred
        assertEq(address(target).balance, balanceBefore + 1 ether, "Target should have received 1 ether");
    }

    /// @notice Test gas consumption for single chain execution
    function test_Gas_SingleChainExecution() public {
        Execution[] memory executions = new Execution[](1);
        executions[0] = Execution({ target: address(target), value: 1 ether, callData: abi.encodeWithSelector(MockTarget.receiveEther.selector) });

        uint256 nonce = 555;

        bytes32 hash = EIP712Hash.hashChainExecutions(block.chainid, nonce, _hashExecutionsMemory(executions));
        bytes32 digest = _createDigestSansChainId(hash);
        bytes memory signature = _createSignature(digest);

        // Measure gas
        uint256 gasBefore = gasleft();
        vm.prank(user.addr);
        nexusAccount.executeWithSig(executions, nonce, signature);
        uint256 gasUsed = gasBefore - gasleft();

        console2.log("Gas used for single chain execution:", gasUsed);
    }

    /// @notice Test execution with mixed value and data operations
    /// @dev Tests that the function can handle both value transfers and state changes
    function test_ExecuteWithSig_MixedOperations() public {
        // Create executions with both value transfer and state change
        Execution[] memory executions = new Execution[](2);
        executions[0] = Execution({ target: address(target), value: 1 ether, callData: abi.encodeWithSelector(MockTarget.receiveEther.selector) });
        executions[1] = Execution({ target: address(target), value: 0, callData: abi.encodeWithSelector(MockTarget.setValue.selector, 123) });

        uint256 nonce = 777;

        bytes32 hash = EIP712Hash.hashChainExecutions(block.chainid, nonce, _hashExecutionsMemory(executions));
        bytes32 digest = _createDigestSansChainId(hash);
        bytes memory signature = _createSignature(digest);

        uint256 balanceBefore = address(target).balance;

        // Execute transactions with signature validation
        vm.prank(user.addr);
        nexusAccount.executeWithSig(executions, nonce, signature);

        // Verify both operations executed correctly
        assertEq(address(target).balance, balanceBefore + 1 ether, "Target should receive 1 ether");
        assertEq(target.value(), 123, "Target value should be set to 123");
    }

    /// @notice Test return values from executions
    function test_ExecuteWithSig_ReturnValues() public {
        // Create execution that sets value and check return values exist
        Execution[] memory executions = new Execution[](1);
        executions[0] = Execution({ 
            target: address(target), 
            value: 0, 
            callData: abi.encodeWithSelector(MockTarget.setValue.selector, 42) 
        });

        uint256 nonce = 888;

        bytes32 hash = EIP712Hash.hashChainExecutions(block.chainid, nonce, _hashExecutionsMemory(executions));
        bytes32 digest = _createDigestSansChainId(hash);
        bytes memory signature = _createSignature(digest);

        // Execute and capture return values
        vm.prank(user.addr);
        bytes[] memory results = nexusAccount.executeWithSig(executions, nonce, signature);

        // Verify return data exists (setValue might return data)
        assertEq(results.length, 1, "Should return one result");
        // setValue may return empty or non-empty data depending on implementation
        assertEq(target.value(), 42, "Target value should be set to 42");
    }

    /// @notice Test that nonce is invalidated after successful execution
    function test_NonceInvalidation_SuccessfulExecution() public {
        // Prepare execution data
        Execution[] memory executions = new Execution[](1);
        executions[0] = Execution({ target: address(target), value: 1 ether, callData: abi.encodeWithSelector(MockTarget.receiveEther.selector) });

        uint256 nonce = 123; // Use a specific nonce

        // Create hash and signature
        bytes32 hash = EIP712Hash.hashChainExecutions(block.chainid, nonce, _hashExecutionsMemory(executions));
        bytes32 digest = _createDigestSansChainId(hash);
        bytes memory signature = _createSignature(digest);

        // Execute transaction
        vm.prank(user.addr);
        nexusAccount.executeWithSig(executions, nonce, signature);

        // Try to reuse the same nonce - should revert with InvalidNonce
        vm.prank(user.addr);
        vm.expectRevert(IModuleManagerEventsAndErrors.InvalidNonce.selector);
        nexusAccount.executeWithSig(executions, nonce, signature);
    }

    /// @notice Test that using an already used nonce fails immediately
    function test_NonceInvalidation_ReuseNonce() public {
        // Prepare first execution
        Execution[] memory executions1 = new Execution[](1);
        executions1[0] = Execution({ target: address(target), value: 0.5 ether, callData: abi.encodeWithSelector(MockTarget.receiveEther.selector) });

        uint256 nonce = 456; // Use a specific nonce
        bytes32 hash1 = EIP712Hash.hashChainExecutions(block.chainid, nonce, _hashExecutionsMemory(executions1));
        bytes32 digest1 = _createDigestSansChainId(hash1);
        bytes memory signature1 = _createSignature(digest1);

        // Execute first transaction with nonce 456
        vm.prank(user.addr);
        nexusAccount.executeWithSig(executions1, nonce, signature1);

        // Prepare second execution with the same nonce
        Execution[] memory executions2 = new Execution[](1);
        executions2[0] = Execution({ target: address(target), value: 0.3 ether, callData: abi.encodeWithSelector(MockTarget.receiveEther.selector) });

        bytes32 hash2 = EIP712Hash.hashChainExecutions(block.chainid, nonce, _hashExecutionsMemory(executions2));
        bytes32 digest2 = _createDigestSansChainId(hash2);
        bytes memory signature2 = _createSignature(digest2);

        // Try to execute second transaction with same nonce - should revert with InvalidNonce
        vm.prank(user.addr);
        vm.expectRevert(IModuleManagerEventsAndErrors.InvalidNonce.selector);
        nexusAccount.executeWithSig(executions2, nonce, signature2);
    }

    /// @notice Test that different nonces are tracked independently
    function test_NonceInvalidation_IndependentNonces() public {
        // Prepare first execution with nonce 100
        Execution[] memory executions1 = new Execution[](1);
        executions1[0] = Execution({ target: address(target), value: 0.5 ether, callData: abi.encodeWithSelector(MockTarget.receiveEther.selector) });

        uint256 nonce1 = 100;
        bytes32 hash1 = EIP712Hash.hashChainExecutions(block.chainid, nonce1, _hashExecutionsMemory(executions1));
        bytes32 digest1 = _createDigestSansChainId(hash1);
        bytes memory signature1 = _createSignature(digest1);

        // Prepare second execution with nonce 200
        Execution[] memory executions2 = new Execution[](1);
        executions2[0] = Execution({ target: address(target), value: 0.3 ether, callData: abi.encodeWithSelector(MockTarget.receiveEther.selector) });

        uint256 nonce2 = 200;
        bytes32 hash2 = EIP712Hash.hashChainExecutions(block.chainid, nonce2, _hashExecutionsMemory(executions2));
        bytes32 digest2 = _createDigestSansChainId(hash2);
        bytes memory signature2 = _createSignature(digest2);

        uint256 balanceBefore = address(target).balance;

        // Execute both transactions with different nonces - both should succeed
        vm.prank(user.addr);
        nexusAccount.executeWithSig(executions1, nonce1, signature1);

        vm.prank(user.addr);
        nexusAccount.executeWithSig(executions2, nonce2, signature2);

        // Verify both executions occurred
        assertEq(address(target).balance, balanceBefore + 0.8 ether, "Target should have received 0.8 ether total");

        // Now try to reuse nonce1 - should fail
        vm.prank(user.addr);
        vm.expectRevert(IModuleManagerEventsAndErrors.InvalidNonce.selector);
        nexusAccount.executeWithSig(executions1, nonce1, signature1);

        // And try to reuse nonce2 - should also fail
        vm.prank(user.addr);
        vm.expectRevert(IModuleManagerEventsAndErrors.InvalidNonce.selector);
        nexusAccount.executeWithSig(executions2, nonce2, signature2);
    }

    /// @notice Helper function to create EIP712 digest without chain ID
    /// @dev Mimics _hashTypedDataSansChainId behavior
    function _createDigestSansChainId(bytes32 structHash) private view returns (bytes32) {
        bytes32 domainSepSansChainId = keccak256(
            abi.encode(
                keccak256("EIP712Domain(string name,string version,address verifyingContract)"), 
                keccak256("Nexus"), 
                keccak256("1.2.0"), 
                address(nexusAccount)
            )
        );
        return keccak256(abi.encodePacked("\x19\x01", domainSepSansChainId, structHash));
    }

    /// @notice Helper function to create signature with validator address
    /// @dev Creates raw signature without Ethereum prefix since digest is already EIP712
    function _createSignature(bytes32 digest) private view returns (bytes memory) {
        return abi.encodePacked(address(SIMPLE_VALIDATOR_MODULE), signMessage(ALICE, digest));
    }

    /// @notice Helper function to hash executions from memory array
    /// @dev Manually hashes executions since library expects calldata
    function _hashExecutionsMemory(Execution[] memory executions) private pure returns (bytes32) {
        uint256 length = executions.length;
        bytes32[] memory hashes = new bytes32[](length);
        for (uint256 i = 0; i < length; i++) {
            Execution memory execution = executions[i];
            hashes[i] = keccak256(
                abi.encode(
                    0x37fb04e5593580b36bfacc47d8b1a4b9a2acb88a513bf153760f925a6723d4b5, // EXECUTION_TYPEHASH
                    execution.target,
                    execution.value,
                    keccak256(execution.callData)
                )
            );
        }
        return keccak256(abi.encodePacked(hashes));
    }
}