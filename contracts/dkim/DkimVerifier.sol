// SPDX-License-Identifier: MIT

pragma solidity 0.8.19;

import "../libraries/strings.sol";
import "./Algorithm.sol";
import "./DkimKeys.sol";
import "../common/Errors.sol";
import "hardhat/console.sol";


contract DkimVerifier is DkimErrors {
    using strings for *;

    DkimKeys public immutable keys;

    constructor(DkimKeys _keys) {
        keys = _keys;
    }

//    function hexToBytes32(string memory hexString) public pure returns (bytes32) {
//        require(bytes(hexString).length == 66, "invalid length hex string");
//        bytes32 result;
//        assembly {
//            result := mload(add(hexString, 0x20))
//        }
//        return result;
//    }

    function verifySignature(bytes memory data, bytes memory signature, string memory domain, string memory selector, string memory hashAlgo) public view returns (bool) {
        (bytes memory modulus, bytes memory exponent) = keys.getKey(domain, selector);
        if (modulus.length == 0 || exponent.length == 0) {
            revert NoDNSRecord();
        }

        if ("sha256".toSlice().equals(hashAlgo.toSlice())) {
            return Algorithm.verifyRSASHA256(modulus, exponent, data, signature);
        } else {
            return Algorithm.verifyRSASHA1(modulus, exponent, data, signature);
        }
    }

}
