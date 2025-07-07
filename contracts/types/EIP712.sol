library EIP712Types {
    struct MultiChainExecutions {
        ChainExecutions[] multiChainExecutions;
    }

    struct ChainExecutions {
        uint256 chainId;
        uint256 nonce;
        Execution[] executions;
    }

    /// @title Execution
    /// @notice Struct to encapsulate execution data for a transaction
    struct Execution {
        /// @notice The target address for the transaction
        address target;
        /// @notice The value in wei to send with the transaction
        uint256 value;
        /// @notice The calldata for the transaction
        bytes callData;
    }
}
