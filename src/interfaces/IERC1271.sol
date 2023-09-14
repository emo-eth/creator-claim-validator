// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

interface IERC1271 {
    function isValidSignature(bytes32 hash, bytes calldata signature)
        external
        view
        returns (bytes4);
}
