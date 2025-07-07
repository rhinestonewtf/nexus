// SPDX-License-Identifier: MIT
pragma solidity ^0.8.27;

import "../utils/Imports.sol";
import "../utils/NexusTest_Base.t.sol";
import { ChainExecutions, Execution } from "../../../contracts/types/DataTypes.sol";
import { EIP712Hash } from "../../../contracts/types/EIP712Type.sol";
import { INexusEventsAndErrors } from "../../../contracts/interfaces/INexusEventsAndErrors.sol";
import { IModuleManagerEventsAndErrors } from "../../../contracts/interfaces/base/IModuleManagerEventsAndErrors.sol";
import { MockSimpleValidator } from "../../../../../contracts/mocks/MockSimpleValidator.sol";

/// @title TestNexusChainExecution_Integration
/// @notice Integration tests for Nexus smart account's executeMultiChainWithSig function
/// @dev Note: Current implementation validates signatures and executes multi-chain transactions
contract TestNexusChainExecution_Integration is NexusTest_Base {
    using EIP712Hash for Execution[];
    using EIP712Hash for bytes32;

    Vm.Wallet private user;
    Nexus private nexusAccount;
    MockPaymaster private paymaster;
    MockTarget private target;
    MockSimpleValidator SIMPLE_VALIDATOR_MODULE;

    uint256 private constant CURRENT_CHAIN_ID = 31_337;
    uint256 private constant OTHER_CHAIN_ID = 1;

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
        bytes memory validatorSetupData = abi.encodePacked(ALICE_ADDRESS); // Set BOB as owner

        vm.prank(0x0000000071727De22E5E9d8BAf0edAc6f37da032);
        nexusAccount.installModule(MODULE_TYPE_VALIDATOR, address(SIMPLE_VALIDATOR_MODULE), validatorSetupData);
    }

    /// @notice Test successful execution of a single chain execution signature
    /// @dev Tests signature validation and execution
    function test_ExecuteChainExecution_SingleChain() public {
        // Prepare execution data
        Execution[] memory executions = new Execution[](1);
        executions[0] = Execution({ target: address(target), value: 1 ether, callData: abi.encodeWithSelector(MockTarget.receiveEther.selector) });

        ChainExecutions memory chainExecution = ChainExecutions({ chainId: CURRENT_CHAIN_ID, executions: executions });

        // Create the allChains array with the hash of current chain execution
        bytes32[] memory allChains = new bytes32[](1);
        uint256 nonce = 0;
        allChains[0] = EIP712Hash.hashChainExecutions(CURRENT_CHAIN_ID, nonce, _hashExecutionsMemory(executions));

        // Sign the multi-chain execution
        bytes32 multiChainHash = EIP712Hash.hashMultiChainExecutions(keccak256(abi.encodePacked(allChains)));
        bytes32 digest = _createDigestSansChainId(multiChainHash);

        // Create signature with validator address prepended
        bytes memory signature = _createSignature(digest);

        // Record balance before execution
        uint256 balanceBefore = address(target).balance;

        // Call executeMultiChainWithSig (validates signature and executes)
        vm.prank(user.addr);
        nexusAccount.executeMultiChainWithSig(executions, allChains, 0, nonce, signature);

        // Verify execution occurred
        assertEq(address(target).balance, balanceBefore + 1 ether, "Target should have received 1 ether");
    }

    /// @notice Test execution with multiple executions in a single chain
    /// @dev Tests signature validation and execution of multiple transactions
    function test_ExecuteChainExecution_MultipleExecutions() public {
        // Deploy additional targets
        MockTarget target2 = new MockTarget();
        MockTarget target3 = new MockTarget();

        // Prepare multiple executions
        Execution[] memory executions = new Execution[](3);
        executions[0] = Execution({ target: address(target), value: 0.5 ether, callData: abi.encodeWithSelector(MockTarget.receiveEther.selector) });
        executions[1] = Execution({ target: address(target2), value: 0.3 ether, callData: abi.encodeWithSelector(MockTarget.receiveEther.selector) });
        executions[2] = Execution({ target: address(target3), value: 0, callData: abi.encodeWithSelector(MockTarget.setValue.selector, 42) });

        ChainExecutions memory chainExecution = ChainExecutions({ chainId: CURRENT_CHAIN_ID, executions: executions });

        // Create the allChains array
        bytes32[] memory allChains = new bytes32[](1);
        uint256 nonce = 0;
        allChains[0] = EIP712Hash.hashChainExecutions(chainExecution.chainId, nonce, _hashExecutionsMemory(chainExecution.executions));

        // Sign and prepare signature
        bytes32 multiChainHash = EIP712Hash.hashMultiChainExecutions(keccak256(abi.encodePacked(allChains)));
        bytes32 digest = _createDigestSansChainId(multiChainHash);
        bytes memory signature = _createSignature(digest);

        // Record balances before
        uint256 balance1Before = address(target).balance;
        uint256 balance2Before = address(target2).balance;
        uint256 balance3Before = address(target3).balance;

        // Call executeMultiChainWithSig (validates signature and executes)
        vm.prank(user.addr);
        nexusAccount.executeMultiChainWithSig(executions, allChains, 0, nonce, signature);

        // Verify executions occurred
        assertEq(address(target).balance, balance1Before + 0.5 ether, "Target 1 should have received 0.5 ether");
        assertEq(address(target2).balance, balance2Before + 0.3 ether, "Target 2 should have received 0.3 ether");
    }

    /// @notice Test execution as part of a multi-chain execution set
    /// @dev Tests signature validation and execution in multi-chain context
    function test_ExecuteChainExecution_MultiChainContext() public {
        // Prepare execution for current chain
        Execution[] memory executions = new Execution[](1);
        executions[0] = Execution({ target: address(target), value: 1 ether, callData: abi.encodeWithSelector(MockTarget.receiveEther.selector) });

        ChainExecutions memory currentChainExecution = ChainExecutions({ chainId: CURRENT_CHAIN_ID, executions: executions });

        // Prepare execution for another chain (won't be executed on this chain)
        Execution[] memory otherChainExecutions = new Execution[](1);
        otherChainExecutions[0] = Execution({
            target: address(0x1234567890123456789012345678901234567890),
            value: 2 ether,
            callData: abi.encodeWithSelector(MockTarget.receiveEther.selector)
        });

        ChainExecutions memory otherChainExecution = ChainExecutions({ chainId: OTHER_CHAIN_ID, executions: otherChainExecutions });

        // Create the allChains array with both chains
        bytes32[] memory allChains = new bytes32[](2);
        uint256 nonce = 0;
        allChains[0] = EIP712Hash.hashChainExecutions(currentChainExecution.chainId, nonce, _hashExecutionsMemory(currentChainExecution.executions));
        allChains[1] = EIP712Hash.hashChainExecutions(otherChainExecution.chainId, nonce, _hashExecutionsMemory(otherChainExecution.executions));

        // Sign the multi-chain execution
        bytes32 multiChainHash = EIP712Hash.hashMultiChainExecutions(keccak256(abi.encodePacked(allChains)));
        bytes32 digest = _createDigestSansChainId(multiChainHash);
        bytes memory signature = _createSignature(digest);

        // Record balance before execution
        uint256 balanceBefore = address(target).balance;

        // Call executeMultiChainWithSig (validates signature and executes)
        vm.prank(user.addr);
        nexusAccount.executeMultiChainWithSig(executions, allChains, 0, nonce, signature);

        // Verify only current chain execution happened
        assertEq(address(target).balance, balanceBefore + 1 ether, "Target should have received 1 ether");
    }

    /// @notice Test validation with wrong chain ID pointer should revert
    function test_ValidateChainExecution_InvalidChainIdPtr_Reverts() public {
        Execution[] memory executions = new Execution[](1);
        executions[0] = Execution({ target: address(target), value: 1 ether, callData: abi.encodeWithSelector(MockTarget.receiveEther.selector) });

        ChainExecutions memory chainExecution = ChainExecutions({ chainId: CURRENT_CHAIN_ID, executions: executions });

        // Create allChains array with 2 elements but provide wrong hash at index 1
        bytes32[] memory allChains = new bytes32[](2);
        uint256 nonce = 0;
        allChains[0] = EIP712Hash.hashChainExecutions(chainExecution.chainId, nonce, _hashExecutionsMemory(chainExecution.executions));
        allChains[1] = bytes32(uint256(123)); // Wrong hash

        bytes32 multiChainHash = EIP712Hash.hashMultiChainExecutions(keccak256(abi.encodePacked(allChains)));
        bytes32 digest = _createDigestSansChainId(multiChainHash);
        bytes memory signature = _createSignature(digest);

        // Try to execute with wrong chain ID pointer (1 instead of 0) which points to wrong hash
        vm.prank(user.addr);
        vm.expectRevert(INexusEventsAndErrors.InvalidMultiChainHash.selector);
        nexusAccount.executeMultiChainWithSig(executions, allChains, 1, nonce, signature);
    }

    /// @notice Test validation with mismatched chain execution data should revert
    function test_ValidateChainExecution_MismatchedData_Reverts() public {
        // Create correct execution
        Execution[] memory executions = new Execution[](1);
        executions[0] = Execution({ target: address(target), value: 1 ether, callData: abi.encodeWithSelector(MockTarget.receiveEther.selector) });

        ChainExecutions memory chainExecution = ChainExecutions({ chainId: CURRENT_CHAIN_ID, executions: executions });

        // Create different execution for hash
        Execution[] memory differentExecutions = new Execution[](1);
        differentExecutions[0] = Execution({
            target: address(target),
            value: 2 ether, // Different value
            callData: abi.encodeWithSelector(MockTarget.receiveEther.selector)
        });

        // Use the different execution hash in allChains
        bytes32[] memory allChains = new bytes32[](1);
        uint256 nonce = 0;
        allChains[0] = EIP712Hash.hashChainExecutions(CURRENT_CHAIN_ID, nonce, _hashExecutionsMemory(differentExecutions));

        bytes32 multiChainHash = EIP712Hash.hashMultiChainExecutions(keccak256(abi.encodePacked(allChains)));
        bytes32 digest = _createDigestSansChainId(multiChainHash);
        bytes memory signature = _createSignature(digest);

        // Should revert due to hash mismatch
        vm.prank(user.addr);
        vm.expectRevert(INexusEventsAndErrors.InvalidMultiChainHash.selector);
        nexusAccount.executeMultiChainWithSig(executions, allChains, 0, nonce, signature);
    }

    /// @notice Test validation with invalid signature should revert
    function test_ValidateChainExecution_InvalidSignature_Reverts() public {
        Execution[] memory executions = new Execution[](1);
        executions[0] = Execution({ target: address(target), value: 1 ether, callData: abi.encodeWithSelector(MockTarget.receiveEther.selector) });

        ChainExecutions memory chainExecution = ChainExecutions({ chainId: CURRENT_CHAIN_ID, executions: executions });

        bytes32[] memory allChains = new bytes32[](1);
        uint256 nonce = 0;
        allChains[0] = EIP712Hash.hashChainExecutions(chainExecution.chainId, nonce, _hashExecutionsMemory(chainExecution.executions));

        // Sign with wrong wallet
        bytes32 multiChainHash = EIP712Hash.hashMultiChainExecutions(keccak256(abi.encodePacked(allChains)));
        bytes32 digest = _createDigestSansChainId(multiChainHash);
        bytes memory signature = abi.encodePacked(address(SIMPLE_VALIDATOR_MODULE), signMessage(BOB, digest)); // Wrong signer

        // Should revert due to invalid signature
        vm.prank(user.addr);
        vm.expectRevert(INexusEventsAndErrors.InvalidSignature.selector);
        nexusAccount.executeMultiChainWithSig(executions, allChains, 0, nonce, signature);
    }

    /// @notice Test execution from any caller (signature-based auth)
    function test_ExecuteChainExecution_AnyCaller() public {
        Execution[] memory executions = new Execution[](1);
        executions[0] = Execution({ target: address(target), value: 1 ether, callData: abi.encodeWithSelector(MockTarget.receiveEther.selector) });

        ChainExecutions memory chainExecution = ChainExecutions({ chainId: CURRENT_CHAIN_ID, executions: executions });

        bytes32[] memory allChains = new bytes32[](1);
        uint256 nonce = 0;
        allChains[0] = EIP712Hash.hashChainExecutions(chainExecution.chainId, nonce, _hashExecutionsMemory(chainExecution.executions));

        bytes32 multiChainHash = EIP712Hash.hashMultiChainExecutions(keccak256(abi.encodePacked(allChains)));
        bytes32 digest = _createDigestSansChainId(multiChainHash);
        bytes memory signature = _createSignature(digest);

        // Record balance before execution
        uint256 balanceBefore = address(target).balance;

        // Anyone should be able to submit the transaction as it's validated by signature
        vm.prank(ALICE.addr);
        nexusAccount.executeMultiChainWithSig(executions, allChains, 0, nonce, signature);

        // Verify execution occurred
        assertEq(address(target).balance, balanceBefore + 1 ether, "Target should have received 1 ether");
    }

    /// @notice Test gas consumption for chain execution validation
    function test_Gas_ChainExecutionValidation() public {
        Execution[] memory executions = new Execution[](1);
        executions[0] = Execution({ target: address(target), value: 1 ether, callData: abi.encodeWithSelector(MockTarget.receiveEther.selector) });

        ChainExecutions memory chainExecution = ChainExecutions({ chainId: CURRENT_CHAIN_ID, executions: executions });

        bytes32[] memory allChains = new bytes32[](1);
        uint256 nonce = 0;
        allChains[0] = EIP712Hash.hashChainExecutions(chainExecution.chainId, nonce, _hashExecutionsMemory(chainExecution.executions));

        bytes32 multiChainHash = EIP712Hash.hashMultiChainExecutions(keccak256(abi.encodePacked(allChains)));
        bytes32 digest = _createDigestSansChainId(multiChainHash);
        bytes memory signature = _createSignature(digest);

        // Measure gas
        uint256 gasBefore = gasleft();
        vm.prank(user.addr);
        nexusAccount.executeMultiChainWithSig(executions, allChains, 0, nonce, signature);
        uint256 gasUsed = gasBefore - gasleft();

        console2.log("Gas used for chain execution:", gasUsed);
    }

    /// @notice Test execution with mixed value and data operations
    /// @dev Tests that the function can handle both value transfers and state changes
    function test_ExecuteChainExecution_MixedOperations() public {
        // Create executions with both value transfer and state change
        Execution[] memory executions = new Execution[](2);
        executions[0] = Execution({ target: address(target), value: 1 ether, callData: abi.encodeWithSelector(MockTarget.receiveEther.selector) });
        executions[1] = Execution({ target: address(target), value: 0, callData: abi.encodeWithSelector(MockTarget.setValue.selector, 123) });

        ChainExecutions memory chainExecution = ChainExecutions({ chainId: CURRENT_CHAIN_ID, executions: executions });

        bytes32[] memory allChains = new bytes32[](1);
        uint256 nonce = 0;
        allChains[0] = EIP712Hash.hashChainExecutions(chainExecution.chainId, nonce, _hashExecutionsMemory(chainExecution.executions));

        bytes32 multiChainHash = EIP712Hash.hashMultiChainExecutions(keccak256(abi.encodePacked(allChains)));
        bytes32 digest = _createDigestSansChainId(multiChainHash);
        bytes memory signature = _createSignature(digest);

        uint256 balanceBefore = address(target).balance;

        // Execute transactions with signature validation
        vm.prank(user.addr);
        nexusAccount.executeMultiChainWithSig(executions, allChains, 0, nonce, signature);

        // Verify both operations executed correctly
        assertEq(address(target).balance, balanceBefore + 1 ether, "Target should receive 1 ether");
        assertEq(target.value(), 123, "Target value should be set to 123");
    }

    /// @notice Test that nonce is invalidated after successful execution
    function test_NonceInvalidation_SuccessfulExecution() public {
        // Prepare execution data
        Execution[] memory executions = new Execution[](1);
        executions[0] = Execution({ target: address(target), value: 1 ether, callData: abi.encodeWithSelector(MockTarget.receiveEther.selector) });

        bytes32[] memory allChains = new bytes32[](1);
        uint256 nonce = 123; // Use a specific nonce
        allChains[0] = EIP712Hash.hashChainExecutions(CURRENT_CHAIN_ID, nonce, _hashExecutionsMemory(executions));

        bytes32 multiChainHash = EIP712Hash.hashMultiChainExecutions(keccak256(abi.encodePacked(allChains)));
        bytes32 digest = _createDigestSansChainId(multiChainHash);
        bytes memory signature = _createSignature(digest);

        // Execute transaction
        vm.prank(user.addr);
        nexusAccount.executeMultiChainWithSig(executions, allChains, 0, nonce, signature);

        // Try to reuse the same nonce - should revert with InvalidNonce
        vm.prank(user.addr);
        vm.expectRevert(IModuleManagerEventsAndErrors.InvalidNonce.selector);
        nexusAccount.executeMultiChainWithSig(executions, allChains, 0, nonce, signature);
    }

    /// @notice Test that using an already used nonce fails immediately
    function test_NonceInvalidation_ReuseNonce() public {
        // Prepare first execution
        Execution[] memory executions1 = new Execution[](1);
        executions1[0] = Execution({ target: address(target), value: 0.5 ether, callData: abi.encodeWithSelector(MockTarget.receiveEther.selector) });

        bytes32[] memory allChains1 = new bytes32[](1);
        uint256 nonce = 456; // Use a specific nonce
        allChains1[0] = EIP712Hash.hashChainExecutions(CURRENT_CHAIN_ID, nonce, _hashExecutionsMemory(executions1));

        bytes32 multiChainHash1 = EIP712Hash.hashMultiChainExecutions(keccak256(abi.encodePacked(allChains1)));
        bytes32 digest1 = _createDigestSansChainId(multiChainHash1);
        bytes memory signature1 = _createSignature(digest1);

        // Execute first transaction with nonce 456
        vm.prank(user.addr);
        nexusAccount.executeMultiChainWithSig(executions1, allChains1, 0, nonce, signature1);

        // Prepare second execution with the same nonce
        Execution[] memory executions2 = new Execution[](1);
        executions2[0] = Execution({ target: address(target), value: 0.3 ether, callData: abi.encodeWithSelector(MockTarget.receiveEther.selector) });

        bytes32[] memory allChains2 = new bytes32[](1);
        allChains2[0] = EIP712Hash.hashChainExecutions(CURRENT_CHAIN_ID, nonce, _hashExecutionsMemory(executions2));

        bytes32 multiChainHash2 = EIP712Hash.hashMultiChainExecutions(keccak256(abi.encodePacked(allChains2)));
        bytes32 digest2 = _createDigestSansChainId(multiChainHash2);
        bytes memory signature2 = _createSignature(digest2);

        // Try to execute second transaction with same nonce - should revert with InvalidNonce
        vm.prank(user.addr);
        vm.expectRevert(IModuleManagerEventsAndErrors.InvalidNonce.selector);
        nexusAccount.executeMultiChainWithSig(executions2, allChains2, 0, nonce, signature2);
    }

    /// @notice Test that different nonces work independently
    function test_NonceInvalidation_DifferentNonces() public {
        // Prepare first execution with nonce 100
        Execution[] memory executions1 = new Execution[](1);
        executions1[0] = Execution({ target: address(target), value: 0.5 ether, callData: abi.encodeWithSelector(MockTarget.receiveEther.selector) });

        bytes32[] memory allChains1 = new bytes32[](1);
        uint256 nonce1 = 100;
        allChains1[0] = EIP712Hash.hashChainExecutions(CURRENT_CHAIN_ID, nonce1, _hashExecutionsMemory(executions1));

        bytes32 multiChainHash1 = EIP712Hash.hashMultiChainExecutions(keccak256(abi.encodePacked(allChains1)));
        bytes32 digest1 = _createDigestSansChainId(multiChainHash1);
        bytes memory signature1 = _createSignature(digest1);

        // Prepare second execution with nonce 200
        Execution[] memory executions2 = new Execution[](1);
        executions2[0] = Execution({ target: address(target), value: 0.3 ether, callData: abi.encodeWithSelector(MockTarget.receiveEther.selector) });

        bytes32[] memory allChains2 = new bytes32[](1);
        uint256 nonce2 = 200;
        allChains2[0] = EIP712Hash.hashChainExecutions(CURRENT_CHAIN_ID, nonce2, _hashExecutionsMemory(executions2));

        bytes32 multiChainHash2 = EIP712Hash.hashMultiChainExecutions(keccak256(abi.encodePacked(allChains2)));
        bytes32 digest2 = _createDigestSansChainId(multiChainHash2);
        bytes memory signature2 = _createSignature(digest2);

        uint256 balanceBefore = address(target).balance;

        // Execute both transactions with different nonces - both should succeed
        vm.prank(user.addr);
        nexusAccount.executeMultiChainWithSig(executions1, allChains1, 0, nonce1, signature1);

        vm.prank(user.addr);
        nexusAccount.executeMultiChainWithSig(executions2, allChains2, 0, nonce2, signature2);

        // Verify both executions occurred
        assertEq(address(target).balance, balanceBefore + 0.8 ether, "Target should have received 0.8 ether total");

        // Now try to reuse nonce1 - should fail
        vm.prank(user.addr);
        vm.expectRevert(IModuleManagerEventsAndErrors.InvalidNonce.selector);
        nexusAccount.executeMultiChainWithSig(executions1, allChains1, 0, nonce1, signature1);

        // And try to reuse nonce2 - should also fail
        vm.prank(user.addr);
        vm.expectRevert(IModuleManagerEventsAndErrors.InvalidNonce.selector);
        nexusAccount.executeMultiChainWithSig(executions2, allChains2, 0, nonce2, signature2);
    }

    /// @notice Helper function to demonstrate how the execute function should iterate through executions
    /// @dev This shows the expected implementation pattern
    function _expectedExecutionLogic(ChainExecutions memory chainExecution) private view {
        // The execute function should implement something like:
        // for (uint256 i = 0; i < chainExecution.executions.length; i++) {
        //     Execution memory exec = chainExecution.executions[i];
        //     (bool success,) = exec.target.call{value: exec.value}(exec.callData);
        //     require(success, "Execution failed");
        // }
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

    /// @notice Helper function to create EIP712 digest without chain ID
    /// @dev Mimics _hashTypedDataSansChainId behavior
    function _createDigestSansChainId(bytes32 structHash) private view returns (bytes32) {
        bytes32 domainSepSansChainId = keccak256(
            abi.encode(
                keccak256("EIP712Domain(string name,string version,address verifyingContract)"), keccak256("Nexus"), keccak256("1.2.0"), address(nexusAccount)
            )
        );
        return keccak256(abi.encodePacked("\x19\x01", domainSepSansChainId, structHash));
    }

    /// @notice Helper function to create signature with validator address
    /// @dev Creates raw signature without Ethereum prefix since digest is already EIP712
    function _createSignature(bytes32 digest) private view returns (bytes memory) {
        return abi.encodePacked(address(SIMPLE_VALIDATOR_MODULE), signMessage(ALICE, digest));
    }
}
