// SPDX-License-Identifier: MIT

pragma solidity ^0.8.0;

import "./strings.sol";

import "hardhat/console.sol";

library DkimDecoder {
    using strings for *;

    struct Headers {
        uint len;
        string[] name;
        string[] value;
        string signature;
    }

    struct SigTags {
        string d;
        string i;
        string s;
        string b;
        string bh;
        string cHeader;
        string cBody;
        string aHash;
        string aKey;
        string h;
        uint l;
    }

    function parse(string memory all) public pure returns (Headers memory) {
        strings.slice memory crlf = "\r\n".toSlice();
        strings.slice memory colon = ":".toSlice();
        strings.slice memory signame = "dkim-signature".toSlice();

        strings.slice memory parsedAll = all.toSlice();

        Headers memory headers = Headers(0, new string[](80), new string[](80), "");
        strings.slice memory headerName = strings.slice(0, 0);
        strings.slice memory headerValue = strings.slice(0, 0);

        while (!parsedAll.empty()) {

            strings.slice memory part = parsedAll.split(crlf);

            strings.slice memory partCopy = part.copy();
            headerName = partCopy.split(colon);
            headerValue = partCopy;

            if (headerName.equals(signame)) {
                headers.signature = headerValue.toString();
            } else if (!headerName.empty()) {
                headers.name[headers.len] = headerName.toString();
                headers.value[headers.len] = headerValue.toString();
                headers.len++;
            }

        }
        return headers;
    }

    function parseSigTags(string memory signature) public pure returns (SigTags memory sigTags, bool success) {
        strings.slice memory sc = ";".toSlice();
        strings.slice memory eq = "=".toSlice();

        strings.slice memory sliceSignature = signature.toSlice();

        while (!sliceSignature.empty()) {

            strings.slice memory value = sliceSignature.split(sc);
            strings.slice memory name = trim(value.split(eq));
            value = trim(value);

            if (name.equals("v".toSlice()) && !value.equals("1".toSlice())) {
                return (sigTags, false);
            } else if (name.equals("d".toSlice())) {
                sigTags.d = value.toString();
            } else if (name.equals("i".toSlice())) {
                sigTags.i = value.toString();
            } else if (name.equals("s".toSlice())) {
                sigTags.s = value.toString();
            } else if (name.equals("c".toSlice())) {
                if (value.empty()) {
                    sigTags.cHeader = "simple";
                    sigTags.cBody = "simple";
                } else {
                    sigTags.cHeader = value.split("/".toSlice()).toString();
                    sigTags.cBody = value.toString();
                    if (sigTags.cBody.toSlice().empty()) {
                        sigTags.cBody = "simple";
                    }
                }
            } else if (name.equals("a".toSlice())) {
                sigTags.aKey = value.split("-".toSlice()).toString();
                sigTags.aHash = value.toString();
                if (sigTags.aHash.toSlice().empty()) {
                    return (sigTags, false);
                }
                if (!sigTags.aHash.toSlice().equals("sha256".toSlice()) && !sigTags.aHash.toSlice().equals("sha1".toSlice())) {
                    return (sigTags, false);
                }
                if (!sigTags.aKey.toSlice().equals("rsa".toSlice())) {
                    return (sigTags, false);
                }
            } else if (name.equals("bh".toSlice())) {
                sigTags.bh = value.toString();
            } else if (name.equals("h".toSlice())) {
                sigTags.h = value.toString();
            } else if (name.equals("b".toSlice())) {
                sigTags.b = value.toString();
            } else if (name.equals("l".toSlice())) {
                sigTags.l = stringToUint(value.toString());
            }
        }

        if (sigTags.i.toSlice().empty()) {
            // behave as though the value of i tag were "@d"
        } else if (!sigTags.i.toSlice().endsWith(sigTags.d.toSlice())) {
            return (sigTags, false);
        }

        return (sigTags, true);
    }

    function getHeader(Headers memory headers, string memory headerName) public pure returns (string memory) {
        for (uint i = 0; i < headers.len; i++) {
            if (headers.name[i].toSlice().equals(headerName.toSlice())) return headers.value[i];
        }
        return "";
    }

    function getFromHeader(Headers memory headers) public pure returns (string memory) {
        string memory from = getHeader(headers, "from");
        return parseEmailAddr(from.toSlice());
    }

    function trim(strings.slice memory self) internal pure returns (strings.slice memory) {
        strings.slice memory sp = "\x20".toSlice();
        strings.slice memory tab = "\x09".toSlice();
        strings.slice memory crlf = "\r\n".toSlice();
        if (self.startsWith(crlf)) {
            self._len -= 2;
            self._ptr += 2;
        }
        while (self.startsWith(sp) || self.startsWith(tab)) {
            self._len -= 1;
            self._ptr += 1;
        }
        if (self.endsWith(crlf)) {
            self._len -= 2;
        }
        while (self.endsWith(sp) || self.endsWith(tab)) {
            self._len -= 1;
        }
        return self;
    }

    function stringToUint(string memory s) internal pure returns (uint result) {
        bytes memory b = bytes(s);
        uint i;
        result = 0;
        for (i = 0; i < b.length; i++) {
            uint c = uint(uint8(b[i]));
            if (c >= 48 && c <= 57) {
                result = result * 10 + (c - 48);
            }
        }
    }

    function parseEmailAddr(strings.slice memory emailAddr) internal pure returns (string memory) {
        strings.slice memory leftBracket = "<".toSlice();
        strings.slice memory rightBracket = ">".toSlice();
        if (emailAddr.contains(leftBracket) && emailAddr.contains(rightBracket)) {
            emailAddr.split(leftBracket);
            return emailAddr.split(rightBracket).toString();
        }
        return emailAddr.toString();
    }
}