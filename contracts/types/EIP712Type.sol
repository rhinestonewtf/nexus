import { Execution } from "./DataTypes.sol";
import { EfficientHashLib } from "solady/utils/EfficientHashLib.sol";

library EIP712Types {
    struct MultiChainExecutions {
        ChainExecutions[] multiChainExecutions;
    }

    struct ChainExecutions {
        uint256 chainId;
        Execution[] executions;
    }
}

library EIP712Hash {
    using EfficientHashLib for bytes32[];
    // EIP712 TYPEHASH constants
    // Execution(address target,uint256 value,bytes callData)

    bytes32 internal constant EXECUTION_TYPEHASH = 0x37fb04e5593580b36bfacc47d8b1a4b9a2acb88a513bf153760f925a6723d4b5;

    // MultiChainExecutions(ChainExecutions[] multiChainExecutions)ChainExecutions(uint256 chainId,Execution[] executions)Execution(address target,uint256
    // value,bytes callData)
    bytes32 internal constant MULTICHAINEXECUTIONS_TYPEHASH = 0x39c2b030abe9123e82a27029aa3ca724fa9db47449be8b1a9e37ee52d338a89d;

    // ChainExecutions(uint256 chainId,Execution[] executions)Execution(address target,uint256 value,bytes callData)
    bytes32 internal constant CHAINEXECUTIONS_TYPEHASH = 0x604489d065f51dde183686730d241312b920624df0d384d3b095f1e9a472cbd1;

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
            a.set(i, hashChainExecutions(chainExecution.chainId, hashExecutions(chainExecution.executions)));
        }
        return hashMultiChainExecutions(a.hash());
    }

    function hashChainExecutions(uint256 chainId, bytes32 executionsHash) internal pure returns (bytes32) {
        return keccak256(abi.encode(CHAINEXECUTIONS_TYPEHASH, chainId, executionsHash));
    }
}
