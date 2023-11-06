// SPDX-License-Identifier: MIT
pragma solidity 0.8.19;

import "../../common/Contants.sol";
import "../BaseValidator.sol";
import "./ISecp256r1.sol";
import "./Base64.sol";
import "../../dkim/DkimVerifier.sol";
import "../../libraries/DkimDecoder.sol";

contract WebauthnValidator is BaseValidator {
    using DkimDecoder for *;
    using strings for *;

    string public constant override NAME = "Webauthn Validator";
    string public constant override VERSION = "0.0.1";

    //event PkChanged(address indexed account, bytes oldPk, bytes newPk);
    event PkAdded(address indexed account, string keyId);
    event EmailChanged(
        address indexed account,
        string oldEmail,
        string newEmail
    );
    event NonceIncrease(address indexed account, uint nonce);

    // TODO remove it
    event VerifySubject(string subject);

    ISecp256r1 public immutable impl;
    DkimVerifier public immutable verifier;

    //mapping(address => bytes) public pks;
    mapping(address => mapping(string => bytes)) public publicKeys;

    mapping(address => string) public emails;
    mapping(address => uint) public recoveryNonce;

    constructor(ISecp256r1 _impl, DkimVerifier _verifier) {
        impl = _impl;
        verifier = _verifier;
    }

    function validateSignature(
        address account,
        bytes32 userOpHash,
        bytes calldata signature
    ) external payable override returns (uint256 validationData) {
        bytes memory sig;
        bytes32 messageHash;
        string memory keyId;
        {
            (
                bytes memory realSig,
                bytes memory authenticatorData,
                string memory clientDataJSONPre,
                string memory clientDataJSONPost,
                string memory passkeyId
            ) = abi.decode(signature, (bytes, bytes, string, string, string));

            string memory clientDataJSON = string.concat(
                clientDataJSONPre,
                Base64.encode(bytes.concat(userOpHash)),
                clientDataJSONPost
            );
            bytes32 clientDataHash = sha256(bytes(clientDataJSON));
            messageHash = sha256(
                bytes.concat(authenticatorData, clientDataHash)
            );
            sig = realSig;
            keyId = passkeyId;
        }

        if (
            impl.validateSignature(messageHash, sig, publicKeys[account][keyId])
        ) {
            return 0;
        }
        return Contants.SIG_VALIDATION_FAILED;
    }

    function enable(bytes calldata data) external payable override {
        (bytes memory keyBytes, string memory keyId, string memory email) = abi
            .decode(data, (bytes, string, string));
        addPubkey(msg.sender, keyBytes, keyId);
        changeEmail(msg.sender, email);
    }

    // use webauthn passkey signature to bind an email to account
    function bindEmail(bytes calldata data) external payable returns (bool) {
        (
            address account,
            string memory emailToBind,
            bytes memory signature
        ) = abi.decode(data, (address, string, bytes));

        string memory oldEmail = emails[account];
        if (!oldEmail.toSlice().equals("".toSlice())) {
            revert("account email not empty");
        }

        bytes memory sig;
        bytes32 messageHash;
        string memory keyId;
        {
            (
                bytes memory realSig,
                bytes memory authenticatorData,
                string memory clientDataJSONPre,
                string memory clientDataJSONPost,
                string memory passkeyId
            ) = abi.decode(signature, (bytes, bytes, string, string, string));

            bytes32 challenge = keccak256(abi.encode(account, emailToBind));

            string memory clientDataJSON = string.concat(
                clientDataJSONPre,
                Base64.encode(bytes.concat(challenge)),
                clientDataJSONPost
            );
            bytes32 clientDataHash = sha256(bytes(clientDataJSON));
            messageHash = sha256(
                bytes.concat(authenticatorData, clientDataHash)
            );
            sig = realSig;
            keyId = passkeyId;
        }

        if (
            impl.validateSignature(messageHash, sig, publicKeys[account][keyId])
        ) {
            emails[account] = emailToBind;
            return true;
        }

        return false;
    }

    // If you don't have any validator to enable your passkey, we can recover it externally.
    function recover(
        bytes calldata data
    ) external payable override returns (bool) {
        // TODO Perhaps we should consider adding a time lock here to prevent the loss of control over email
        (bytes memory signature, bytes memory dkimHeaders) = abi.decode(
            data,
            (bytes, bytes)
        );

        return recoveryEmail(signature, dkimHeaders);
    }

    function recoveryEmail(
        bytes memory signature,
        bytes memory dkimHeaders
    ) public returns (bool) {
        DkimDecoder.Headers memory headers = DkimDecoder.parse(
            string(dkimHeaders)
        );

        // TODO Check if the signature is expired
        string memory subject = DkimDecoder.getHeader(headers, "subject");
        bytes memory subjectBytes = fromHex(subject);
        emit VerifySubject(subject);

        (
            uint chainId,
            address validator,
            address account,
            uint nonce,
            bytes memory keyBytes,
            string memory keyId
        ) = abi.decode(
                subjectBytes,
                (uint, address, address, uint, bytes, string)
            );
        string memory from = DkimDecoder.getFromHeader(headers);

        if (!validateParams(chainId, validator, account, nonce, from)) {
            return false;
        }

        (DkimDecoder.SigTags memory sigTags, bool success) = DkimDecoder
            .parseSigTags(headers.signature);
        if (!success) {
            return false;
        }

        if (
            !verifier.verifySignature(
                dkimHeaders,
                signature,
                sigTags.d,
                sigTags.s,
                sigTags.aHash
            )
        ) {
            return false;
        }

        //changePubkey(account, newPub);
        addPubkey(account, keyBytes, keyId);
        increaseNonce(account);

        return true;
    }

    function validateParams(
        uint chainId,
        address validator,
        address account,
        uint nonce,
        string memory from
    ) public view returns (bool) {
        // we should check data in subject to prevent replay attacking
        // data.subject = chainid + address(this) + opCode + nonce + account + publickey (maybe also should including function selector)
        // TODO
        //        if (chainId != block.chainid || validator != address(this)) {
        //            return false;
        //        }

        uint nonceStored = recoveryNonce[account];
        if (nonceStored != nonce) {
            return false;
        }

        // Check if the from address is valid
        string memory fromStored = emails[account];

        if (!fromStored.toSlice().equals(from.toSlice())) {
            return false;
        }

        // TODO check the length of new public key

        return true;
    }

    function increaseNonce(address account) internal {
        uint nonce = recoveryNonce[account]++;
        emit NonceIncrease(account, nonce + 1);
    }

    // Convert an hexadecimal character to their value
    function fromHexChar(uint8 c) public pure returns (uint8) {
        if (bytes1(c) >= bytes1("0") && bytes1(c) <= bytes1("9")) {
            return c - uint8(bytes1("0"));
        }
        if (bytes1(c) >= bytes1("a") && bytes1(c) <= bytes1("f")) {
            return 10 + c - uint8(bytes1("a"));
        }
        if (bytes1(c) >= bytes1("A") && bytes1(c) <= bytes1("F")) {
            return 10 + c - uint8(bytes1("A"));
        }
        revert("invalid hex string");
    }

    // Convert an hexadecimal string to raw bytes
    function fromHex(string memory s) public pure returns (bytes memory) {
        bytes memory ss = bytes(s);
        require(ss.length % 2 == 0);
        bytes memory r = new bytes(ss.length / 2);
        for (uint i = 0; i < ss.length / 2; ++i) {
            r[i] = bytes1(
                fromHexChar(uint8(ss[2 * i])) *
                    16 +
                    fromHexChar(uint8(ss[2 * i + 1]))
            );
        }
        return r;
    }

    /*
    function changePubkey(address account, bytes memory pub) internal {
        bytes memory oldPub = pks[msg.sender];
        pks[msg.sender] = pub;
        emit PkChanged(account, oldPub, pub);
    }
    */

    function addPubkey(
        address account,
        bytes memory keyBytes,
        string memory keyId
    ) internal {
        if (publicKeys[account][keyId].length != 0) {
            revert("duplicate key");
        }
        publicKeys[account][keyId] = keyBytes;
        emit PkAdded(account, keyId);
    }

    function changeEmail(address account, string memory email) internal {
        string memory oldEmail = emails[msg.sender];
        emails[msg.sender] = email;
        emit EmailChanged(account, oldEmail, email);
    }

    function validCaller(
        address,
        bytes calldata
    ) external pure override returns (bool) {
        revert("not implemented");
    }
}
