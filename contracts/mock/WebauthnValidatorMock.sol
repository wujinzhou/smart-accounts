// SPDX-License-Identifier: MIT
pragma solidity 0.8.19;

import '../validators/p256/WebauthnValidator.sol';

contract WebauthnValidatorMock is WebauthnValidator {
    constructor(ISecp256r1 _impl, DkimVerifier _verifier) WebauthnValidator(_impl, _verifier) {}

    function createAccount(address account, bytes memory keyBytes, string memory keyId, string memory email) public {
        publicKeys[account][keyId] = keyBytes;
        emails[account] = email;
    }

    function increase(address account) public {
        increaseNonce(account);
    }
}
