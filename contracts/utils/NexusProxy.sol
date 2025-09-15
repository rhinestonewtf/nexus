// SPDX-License-Identifier: MIT
pragma solidity ^0.8.27;

import { Proxy } from "@openzeppelin/contracts/proxy/Proxy.sol";
import { ERC1967Utils } from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Utils.sol";
import { Initializable } from "../lib/Initializable.sol";

/// @title NexusProxy
/// @dev A proxy contract that uses the ERC1967 upgrade pattern and sets the initializable flag
///      in the constructor to prevent reinitialization
contract NexusProxy is Proxy {
    /// @notice Emitted when the contract receives Ether
    event NexusReceived(address indexed sender, uint256 amount);

    constructor(address implementation, bytes memory data) payable {
        Initializable.setInitializable();
        ERC1967Utils.upgradeToAndCall(implementation, data);
    }

    function _implementation() internal view virtual override returns (address) {
        return ERC1967Utils.getImplementation();
    }

    receive() external payable {
        assembly {
            // Store msg.value in memory
            mstore(0x00, callvalue())

            // Emit "NexusReceived(address indexed,uint256)
            log2(
                0x00, // Memory offset
                0x20, // Size
                0xa77be744658ed76e5e1397645e54770ffc61af32ea6b1238900f1d3df79aa3f2, // Event sig
                caller() // Indexed sender
            )
        }
    }
}
