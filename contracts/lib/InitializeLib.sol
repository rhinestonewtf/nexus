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
    /// @param data The data to parse, should be abi-encoded as (uint256 chainIdIndex, uint256[] chainIds, bytes initData)
    /// @param nexus The Nexus implementation address to be used in the hash
    function hash(bytes calldata data, address nexus) internal view returns (bytes32 _hash) {
        // Decode the data
        (uint256 chainIdIndex, uint256[] memory chainIds, bytes memory initData) = abi.decode(data, (uint256, uint256[], bytes));

        // A chain ID of 0 means the account can be initialized on any chain, otherwise, it must match the current chain ID
        require((chainIds[chainIdIndex] == 0 || chainIds[chainIdIndex] == block.chainid), UnsupportedChain());

        // Hash the parameters
        _hash = keccak256(abi.encode(INITIALIZE_TYPEHASH, nexus, keccak256(abi.encodePacked(chainIds)), keccak256(initData)));
    }
}
