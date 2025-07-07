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

library EIP712Hash {
    using EfficientHashLib for bytes32[];

    // EIP712 TYPEHASH constants
    // ChainExecutions(uint256 chainId,uint256 nonce,Execution[] executions)Execution(address target,uint256 value,bytes callData)
    bytes32 internal constant CHAINEXECUTIONS_TYPEHASH = 0x202030f3d0c10e3a7e7fa09313576a83d2539bc3f2bc9a639fc1d2a22a837abe;

    // Execution(address target,uint256 value,bytes callData)
    bytes32 internal constant EXECUTION_TYPEHASH = 0x37fb04e5593580b36bfacc47d8b1a4b9a2acb88a513bf153760f925a6723d4b5;

    // MultiChainExecutions(ChainExecutions[] multiChainExecutions)ChainExecutions(uint256 chainId,uint256 nonce,Execution[] executions)Execution(address
    // target,uint256 value,bytes callData)
    bytes32 internal constant MULTICHAINEXECUTIONS_TYPEHASH = 0xae6c965accf9121eb189e9cce285333fc4477dbf367cbfab682677cf87bf7595;

    function hashExecution(address target, uint256 value, bytes calldata callData) internal pure returns (bytes32) {
        return keccak256(abi.encode(EXECUTION_TYPEHASH, target, value, keccak256(callData)));
    }

    function hashExecutions(Execution[] calldata _executions) internal pure returns (bytes32) {
        uint256 length = _executions.length;
        bytes32[] memory a = EfficientHashLib.malloc(length);
        for (uint256 i; i < length; i++) {
            Execution calldata _execution = _executions[i];
            a.set(i, hashExecution(_execution.target, _execution.value, _execution.callData));
        }
        return a.hash();
    }

    function hashMultiChainExecutions(bytes32 multiChainExecutionsHash) internal pure returns (bytes32) {
        return keccak256(abi.encode(MULTICHAINEXECUTIONS_TYPEHASH, multiChainExecutionsHash));
    }

    function hashMultiChainExecutions(EIP712Types.ChainExecutions[] calldata chainExecutions) internal pure returns (bytes32) {
        uint256 length = chainExecutions.length;
        bytes32[] memory a = EfficientHashLib.malloc(length);
        for (uint256 i; i < length; i++) {
            EIP712Types.ChainExecutions calldata chainExecution = chainExecutions[i];
            a.set(i, hashChainExecutions(chainExecution.chainId, chainExecution.nonce, hashExecutions(chainExecution.executions)));
        }
        return hashMultiChainExecutions(a.hash());
    }

    function hashChainExecutions(uint256 chainId, uint256 nonce, bytes32 executionsHash) internal pure returns (bytes32) {
        return keccak256(abi.encode(CHAINEXECUTIONS_TYPEHASH, chainId, nonce, executionsHash));
    }
}
