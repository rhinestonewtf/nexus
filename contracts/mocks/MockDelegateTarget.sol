// SPDX-License-Identifier: MIT
pragma solidity ^0.8.27;

contract MockDelegateTarget {
    function sendValue(address target, uint256 _value) public {
        (bool success,) = target.call{ value: _value }("");
        require(success, "Call failed");
    }
}
