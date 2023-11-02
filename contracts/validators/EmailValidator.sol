// SPDX-License-Identifier: MIT
pragma solidity 0.8.19;

import "../common/Contants.sol";
import "./BaseValidator.sol";
import "../dkim/DkimVerifier.sol";
import "../libraries/DkimDecoder.sol";

import "hardhat/console.sol";

contract EmailValidator is BaseValidator {
    using strings for *;
    using DkimDecoder for *;

    string public constant override NAME = "Email Validator";
    string public constant override VERSION = "0.0.1";

    event EmailChanged(address indexed account, string oldEmail, string newEmail);

    DkimVerifier public immutable verifier;
    mapping(address => string) public emails;

    constructor(DkimVerifier _verifier) {
        verifier = _verifier;
    }

    function validateSignature(address account, bytes32 userOpHash, bytes calldata signature)
    external
    payable
    override
    returns (uint256 validationData)
    {
        string memory sender = emails[account];
        if (bytes(sender).length == 0) {
            return Contants.SIG_VALIDATION_FAILED;
        }
        (bytes memory sig, bytes memory data) = abi.decode(
            signature,
            (bytes, bytes)
        );

        if (verify(sig, data, userOpHash, sender)) {
            return 0;
        }
        return Contants.SIG_VALIDATION_FAILED;
    }

    function verify(bytes memory signature, bytes memory data, bytes32 userOpHash, string memory sender) public view returns (bool) {

        DkimDecoder.Headers memory headers = DkimDecoder.parse(string(data));

        string memory from = DkimDecoder.getFromHeader(headers);

        //  Check if the from address is valid
        if (!sender.toSlice().equals(from.toSlice())) {
            return false;
        }
        // TODO Check if the signature is expired
        // TODO Check if userOpHash matches the one in the email

        string memory subject = DkimDecoder.getHeader(headers, "subject");
        console.log("subject: ", subject);
        (DkimDecoder.SigTags memory sigTags, bool success) = DkimDecoder.parseSigTags(headers.signature);

        return success ? verifier.verifySignature(data, signature, sigTags.d, sigTags.s, sigTags.aHash) : false;
    }

    function enable(bytes calldata data) external payable override {
        string memory old = emails[msg.sender];
        emails[msg.sender] = string(data);
        emit EmailChanged(msg.sender, old, string(data));
    }

    function recover(bytes calldata data) external payable override returns (bool) {
        revert("not implemented");
    }

    function validCaller(address, bytes calldata) external pure override returns (bool) {
        revert("not implemented");
    }
}
