// SPDX-License-Identifier: MIT
pragma solidity ^0.8.27;

/// @title Initialize Library
/// @dev Provides hashing and chain verification functions for account initialization.
library InitializeLib {
    /*//////////////////////////////////////////////////////////////
                                 ERRORS
    //////////////////////////////////////////////////////////////*/

    /// @notice Error thrown when the chain is not supported.
    error UnsupportedChain();

    /// @notice Error thrown when the chain index is out of bounds.
    error ChainIndexOutOfBounds();

    /*//////////////////////////////////////////////////////////////
                               CONSTANTS
    //////////////////////////////////////////////////////////////*/

    /// @notice keccak256("Initialize(address nexus,uint256[] chainIds,bytes initData)")
    bytes32 public constant INITIALIZE_TYPEHASH = 0xf519a60f511204e58bb5b531a9f542b2ed706bb768589316a8be873ab2cfeb09;

    /*//////////////////////////////////////////////////////////////
                                  HASH
    //////////////////////////////////////////////////////////////*/

    /// @notice Parse data to decode the initialization parameters, check if the passed chainIds[chainIdIndex]
    ///         matches current chainId or is 0 (allow all chains) and return the hashed parameters.
    /// @param data The data to parse, in the following format:
    ///        abi.encodePacked(uint256 chainIdIndex, uint256 chainIdsLength, uint256[] chainIds, bytes initData)
    /// @param nexus The Nexus implementation address to be used in the hash
    /// @return _hash The keccak256 hash of the initialization parameters
    /// @return initData The true initialization data, which is the last part of the data
    function hash(bytes calldata data, address nexus) internal view returns (bytes32 _hash, bytes calldata initData) {
        // Init hash
        bytes32 chainIdsHash;

        assembly {
            // Decode chainIdIndex and chainIdsLength
            let chainIdIndex := calldataload(data.offset)
            let chainIdsLength := calldataload(add(data.offset, 0x20))

            // Calculate where chainIds start in calldata
            let chainIdsStart := add(data.offset, 0x40)
            let chainIdsSize := mul(chainIdsLength, 0x20)

            // Copy chainIds from calldata to memory
            let ptr := mload(0x40)
            calldatacopy(ptr, chainIdsStart, chainIdsSize)

            // Hash chainIds
            chainIdsHash := keccak256(ptr, chainIdsSize)

            // Set initData to point to the remaining calldata
            let chainIdsEnd := add(chainIdsStart, chainIdsSize)
            initData.offset := chainIdsEnd
            initData.length := sub(add(data.offset, data.length), chainIdsEnd)

            // Validate chainIdIndex is within bounds
            if iszero(lt(chainIdIndex, chainIdsLength)) {
                mstore(0x00, 0x28cad507) // ChainIndexOutOfBounds()
                revert(0x1c, 0x04)
            }

            // Load the specific chainId at chainIdIndex
            let selectedChainId := calldataload(add(chainIdsStart, mul(chainIdIndex, 0x20)))

            // Check if selectedChainId is 0 or matches current chainid
            if iszero(or(iszero(selectedChainId), eq(selectedChainId, chainid()))) {
                mstore(0x00, 0xd21eab37) // UnsupportedChain()
                revert(0x1c, 0x04)
            }
        }

        // Hash the parameters
        _hash = keccak256(abi.encode(INITIALIZE_TYPEHASH, nexus, chainIdsHash, keccak256(initData)));
    }
}
