// SPDX-License-Identifier: MIT
pragma solidity ^0.8.27;

import { Execution } from "./DataTypes.sol";
import { EfficientHashLib } from "solady/utils/EfficientHashLib.sol";

library EIP712Types {
    struct MultiChainExecutions {
        ChainExecutions[] multiChainExecutions;
    }

    struct ChainExecutions {
        uint256 chainId;
        uint256 nonce;
        Execution[] executions;
    }
}

/**
 * @title EIP712Hash Library
 * @notice Provides secure EIP-712 compliant hashing functions for multi-chain execution data structures
 * @dev This library implements cryptographic hashing for structured execution data used in cross-chain
 *      smart account operations. All functions follow EIP-712 standard for structured data hashing
 *      to ensure signature safety and compatibility with wallet implementations.
 *
 * @dev Security Considerations:
 *      - All hashes use keccak256 for cryptographic security
 *      - EIP-712 structured data hashing prevents signature confusion attacks
 *      - Type hashes are precomputed constants to prevent manipulation
 *      - Nested structure hashing maintains data integrity across complex objects
 *
 * @dev Gas Optimization:
 *      - Uses EfficientHashLib for optimized array hashing
 *      - Precomputed type hashes reduce gas costs
 *      - Minimal external calls and memory allocations
 *
 * @author Biconomy Team
 * @custom:security-note All functions in this library are critical for signature security.
 *                       Type hash constants must never be modified after deployment.
 */
library EIP712Hash {
    using EfficientHashLib for bytes32[];

    // EIP712 TYPEHASH constants - CRITICAL: These must never be changed after deployment
    // SECURITY: Precomputed hashes prevent runtime manipulation and ensure consistency

    /**
     * @dev Type hash for ChainExecutions structure
     * @dev Represents: ChainExecutions(uint256 chainId,uint256 nonce,Execution[] executions)Execution(address target,uint256 value,bytes callData)
     * @dev SECURITY: This hash ensures that chain execution data cannot be tampered with or confused with other structures
     */
    bytes32 internal constant CHAINEXECUTIONS_TYPEHASH = 0x202030f3d0c10e3a7e7fa09313576a83d2539bc3f2bc9a639fc1d2a22a837abe;

    /**
     * @dev Type hash for individual Execution structure
     * @dev Represents: Execution(address target,uint256 value,bytes callData)
     * @dev SECURITY: This hash ensures individual transaction data integrity and prevents substitution attacks
     */
    bytes32 internal constant EXECUTION_TYPEHASH = 0x37fb04e5593580b36bfacc47d8b1a4b9a2acb88a513bf153760f925a6723d4b5;

    /**
     * @dev Type hash for MultiChainExecutions structure
     * @dev Represents: MultiChainExecutions(ChainExecutions[] multiChainExecutions)ChainExecutions(uint256 chainId,uint256 nonce,Execution[]
     * executions)Execution(address target,uint256 value,bytes callData)
     * @dev SECURITY: This hash ensures the complete multi-chain transaction set cannot be altered or replayed across different contexts
     */
    bytes32 internal constant MULTICHAINEXECUTIONS_TYPEHASH = 0xae6c965accf9121eb189e9cce285333fc4477dbf367cbfab682677cf87bf7595;

    /**
     * @notice Computes EIP-712 hash for a single execution transaction
     * @dev Creates a standardized hash for individual transaction data following EIP-712 specification.
     *      This hash ensures the transaction details cannot be tampered with and provides clear
     *      identification of the transaction structure for signature verification.
     *
     * @dev Security Features:
     *      - Uses EXECUTION_TYPEHASH for structure identification
     *      - Hashes callData separately to handle variable-length data securely
     *      - Follows EIP-712 encoding standards for wallet compatibility
     *
     * @param target The contract address that will be called in this execution
     * @param value The amount of ETH (in wei) to be sent with this execution
     * @param callData The encoded function call data for the execution
     * @return bytes32 The EIP-712 compliant hash of the execution data
     *
     * @custom:security-note This hash is used in signature verification - any changes to the
     *                       computation would invalidate existing signatures
     */
    function hashExecution(address target, uint256 value, bytes calldata callData) internal pure returns (bytes32) {
        // SECURITY: Create EIP-712 compliant hash for single execution
        // - EXECUTION_TYPEHASH: Ensures type safety and prevents confusion with other structures
        // - target: Contract address to call - ensures destination integrity
        // - value: ETH amount to send - ensures value transfer integrity
        // - keccak256(callData): Hash variable-length data separately for security
        // This encoding prevents any ambiguity about the structure being signed
        return keccak256(abi.encode(EXECUTION_TYPEHASH, target, value, keccak256(callData)));
    }

    /**
     * @notice Computes EIP-712 hash for an array of execution transactions
     * @dev Creates a composite hash representing multiple executions in a deterministic order.
     *      This enables batch transaction authorization while maintaining individual transaction
     *      integrity and preventing reordering attacks.
     *
     * @dev Security Features:
     *      - Each execution is hashed individually before combining
     *      - Uses EfficientHashLib for gas-optimized array hashing
     *      - Maintains execution order integrity
     *      - Prevents individual transaction substitution within the batch
     *
     * @dev Gas Optimization:
     *      - Pre-allocates memory array for efficiency
     *      - Uses optimized hashing library for array operations
     *      - Minimizes redundant hash computations
     *
     * @param _executions Array of execution transactions to hash
     * @return bytes32 The combined hash representing all executions in order
     *
     * @custom:security-note The order of executions affects the hash - reordering would
     *                       produce a different hash and invalidate signatures
     */
    function hashExecutions(Execution[] calldata _executions) internal pure returns (bytes32) {
        // SECURITY: Process array of executions maintaining order integrity
        uint256 length = _executions.length;

        // GAS OPTIMIZATION: Pre-allocate memory array using efficient library
        // This avoids dynamic resizing and reduces gas costs for large arrays
        bytes32[] memory a = EfficientHashLib.malloc(length);

        // SECURITY: Hash each execution individually to prevent substitution attacks
        // The order matters - changing the order would produce a different hash
        // This ensures that transaction batches execute in the exact order specified
        for (uint256 i; i < length; i++) {
            Execution calldata _execution = _executions[i];
            // SECURITY: Each execution gets its own secure hash before combining
            // This prevents any individual transaction from being modified without detection
            a.set(i, hashExecution(_execution.target, _execution.value, _execution.callData));
        }

        // SECURITY: Combine all execution hashes using cryptographically secure method
        // The final hash represents the complete batch with order preserved
        return a.hash();
    }

    /**
     * @notice Computes EIP-712 hash for multi-chain executions using pre-computed hash
     * @dev Creates the final hash structure for multi-chain transaction authorization.
     *      This function wraps a pre-computed multi-chain hash with the appropriate
     *      EIP-712 type identifier for signature verification.
     *
     * @dev Security Features:
     *      - Uses MULTICHAINEXECUTIONS_TYPEHASH for type safety
     *      - Follows EIP-712 standards for structured data
     *      - Ensures multi-chain transaction integrity
     *
     * @param multiChainExecutionsHash Pre-computed hash of all chain executions
     * @return bytes32 The EIP-712 compliant multi-chain execution hash
     *
     * @custom:usage Used when you have already computed the chain executions hash
     *               and need to wrap it in the final EIP-712 structure
     */
    function hashMultiChainExecutions(bytes32 multiChainExecutionsHash) internal pure returns (bytes32) {
        // SECURITY: Wrap pre-computed multi-chain hash with EIP-712 type identifier
        // - MULTICHAINEXECUTIONS_TYPEHASH: Ensures proper structure identification
        // - multiChainExecutionsHash: Pre-computed hash of all chain executions
        // This creates the final hash that will be signed by the user for multi-chain authorization
        return keccak256(abi.encode(MULTICHAINEXECUTIONS_TYPEHASH, multiChainExecutionsHash));
    }

    /**
     * @notice Computes EIP-712 hash for multi-chain executions from structured data
     * @dev Creates a complete hash for cross-chain transaction authorization by processing
     *      an array of chain-specific execution sets. Each chain's executions are hashed
     *      individually before being combined into the final multi-chain hash.
     *
     * @dev Security Features:
     *      - Each chain's executions are processed independently
     *      - Chain ID inclusion prevents cross-chain replay attacks
     *      - Nonce inclusion provides per-chain replay protection
     *      - Complete transaction set integrity is maintained
     *
     * @dev Cross-Chain Security:
     *      - Each chain processes only its designated executions
     *      - Chain ID validation prevents execution on wrong chains
     *      - Nonce management is per-chain to avoid conflicts
     *      - Complete multi-chain authorization in single signature
     *
     * @param chainExecutions Array of chain-specific execution sets
     * @return bytes32 The complete multi-chain execution hash for signature verification
     *
     * @custom:security-note This function is critical for cross-chain security - it ensures
     *                       that each chain can independently verify its part of a multi-chain
     *                       transaction while maintaining overall transaction integrity
     */
    function hashMultiChainExecutions(EIP712Types.ChainExecutions[] calldata chainExecutions) internal pure returns (bytes32) {
        // SECURITY: Process complete multi-chain transaction set
        uint256 length = chainExecutions.length;

        // GAS OPTIMIZATION: Pre-allocate memory for chain hashes
        bytes32[] memory a = EfficientHashLib.malloc(length);

        // SECURITY: Process each chain's executions independently
        // This ensures that each chain can verify its portion of the multi-chain transaction
        // without needing access to other chains' execution data
        for (uint256 i; i < length; i++) {
            EIP712Types.ChainExecutions calldata chainExecution = chainExecutions[i];

            // SECURITY: Create chain-specific hash including:
            // - chainId: Prevents cross-chain replay attacks
            // - nonce: Provides per-chain replay protection
            // - executions: Ensures transaction data integrity for this chain
            a.set(i, hashChainExecutions(chainExecution.chainId, chainExecution.nonce, hashExecutions(chainExecution.executions)));
        }

        // SECURITY: Combine all chain hashes into final multi-chain hash
        // This allows a single signature to authorize executions across multiple chains
        // while maintaining security boundaries between chains
        return hashMultiChainExecutions(a.hash());
    }

    /**
     * @notice Computes EIP-712 hash for chain-specific execution data
     * @dev Creates a hash representing executions intended for a specific blockchain.
     *      This hash includes chain ID for cross-chain safety, nonce for replay protection,
     *      and execution data for transaction integrity.
     *
     * @dev Security Features:
     *      - Chain ID prevents cross-chain replay attacks
     *      - Nonce provides replay protection within the chain
     *      - Execution hash ensures transaction data integrity
     *      - EIP-712 compliance for wallet compatibility
     *
     * @dev Multi-Chain Design:
     *      - Each chain has its own ChainExecutions hash
     *      - Allows selective execution across different chains
     *      - Maintains security boundaries between chains
     *      - Enables atomic multi-chain operations
     *
     * @param chainId The blockchain identifier where these executions will run
     * @param nonce The replay protection nonce for this chain
     * @param executionsHash The hash of executions intended for this chain
     * @return bytes32 The chain-specific execution hash
     *
     * @custom:security-note Chain ID and nonce are critical for preventing replay attacks
     *                       across chains and within chains respectively
     */
    function hashChainExecutions(uint256 chainId, uint256 nonce, bytes32 executionsHash) internal pure returns (bytes32) {
        // SECURITY: Create chain-specific execution hash with multiple security layers
        // - CHAINEXECUTIONS_TYPEHASH: EIP-712 type identifier for structure safety
        // - chainId: Blockchain identifier prevents cross-chain replay attacks
        // - nonce: Unique number provides replay protection within the chain
        // - executionsHash: Hash of actual transaction data ensures data integrity
        // This combination ensures that executions can only be executed on the intended
        // chain and only once per nonce, providing comprehensive security
        return keccak256(abi.encode(CHAINEXECUTIONS_TYPEHASH, chainId, nonce, executionsHash));
    }
}
