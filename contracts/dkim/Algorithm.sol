// SPDX-License-Identifier: MIT

pragma solidity 0.8.19;

import "@ensdomains/solsha1/contracts/SHA1.sol";
import "hardhat/console.sol";

library Algorithm {

    function verifyRSASHA256(bytes memory modulus, bytes memory exponent, bytes memory data, bytes memory sig) internal view returns (bool) {
        // Recover the message from the signature
        bool ok;
        bytes memory result;
        (ok, result) = modexp(sig, exponent, modulus);

        // Verify it ends with the hash of our data
        return ok && sha256(data) == readBytes32(result, result.length - 32);
    }

    function verifyRSASHA1(bytes memory modulus, bytes memory exponent, bytes memory data, bytes memory sig) internal view returns (bool) {
        // Recover the message from the signature
        bool ok;
        bytes memory result;
        (ok, result) = modexp(sig, exponent, modulus);

        // Verify it ends with the hash of our data
        return ok && SHA1.sha1(data) == readBytes20(result, result.length - 20);
    }

    function modexp(bytes memory base, bytes memory exponent, bytes memory modulus) internal view returns (bool success, bytes memory output) {
        bytes memory input = abi.encodePacked(
            uint256(base.length),
            uint256(exponent.length),
            uint256(modulus.length),
            base,
            exponent,
            modulus
        );
        output = new bytes(modulus.length);

        assembly {
            success := staticcall(gas(), 5, add(input, 32), mload(input), add(output, 32), mload(modulus))
        }
    }


    function readBytes32(bytes memory self, uint idx) internal pure returns (bytes32 ret) {
        require(idx + 32 <= self.length);
        assembly {
            ret := mload(add(add(self, 32), idx))
        }
    }

    function readBytes20(bytes memory self, uint idx) internal pure returns (bytes20 ret) {
        require(idx + 20 <= self.length);
        assembly {
            ret := and(mload(add(add(self, 32), idx)), 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF000000000000000000000000)
        }
    }

}