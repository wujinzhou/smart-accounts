// SPDX-License-Identifier: LGPL-3.0-only
pragma solidity 0.8.19;

contract DkimErrors {

    error WrongDkimVersion();

    error MalformedAlgorithm();

    error UnsupportedHash();

    error UnsupportedKey();

    error DomainMismatch();

    error NoDNSRecord();

}

