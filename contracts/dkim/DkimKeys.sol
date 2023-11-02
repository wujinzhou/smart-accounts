// SPDX-License-Identifier: MIT
pragma solidity ^0.8.13;

import "@openzeppelin/contracts/access/Ownable.sol";

contract DkimKeys is Ownable {

    event UpdateDKIMKey(string domain, string selector, bytes exponent, bytes modulus);
    event DeleteDKIMKey(string domain, string selector, bytes exponent, bytes modulus);

    struct key {
        bytes exponent;
        bytes modulus;
    }

    mapping(string => mapping(string => key)) private dkimKeys;

    constructor() {
        dkimKeys["gmail.com"]["20230601"] = key(
            hex"9EDBD2293D6192A84A7B4C5C699D31F906E8B83B09B817DBCBF4BCDA3C6CA02FD2A1D99F995B360F52801F79A2D40A9D31D535DA1D957C44DE389920198AB996377DF7A009EEE7764B238B42696168D1C7ECBC7E31D69BF3FCC337549DC4F0110E070CEC0B111021F0435E51DB415A2940011AEE0D4DB4767C32A76308AAE634320642D63FE2E018E81F505E13E0765BD8F6366D0B443FA41EA8EB5C5B8AEBB07DB82FB5E10FE1D265BD61B22B6B13454F6E1273C43C08E0917CD795CC9D25636606145CFF02C48D58D0538D96AB50620B28AD9F5AA685B528F41EF1BAD24A546C8BDB1707FB6EE7A2E61BBB440CD9AB6795D4C106145000C13AEEEDD678B05F",
            hex"010001"
        );
        dkimKeys["gmail.com"]["20161025"] = key(
            hex"be23c6064e1907ae147d2a96c8089c751ee5a1d872b5a7be11845056d28384cfb59978c4a91b4ffe90d3dec0616b3926038f27da4e4d254c8c1283bc9dcdabeac500fbf0e89b98d1059a7aa832893b08c9e51fcea476a69511be611250a91b6a1204a22561bb87b79f1985a687851184533d93dfab986fc2c02830c7b12df9cf0e3259e068b974e3f6cf99fa63744c8b5b23629a4efad425fa2b29b3622443373d4c389389ececc5692e0f15b54b9f49b999fd0754db41a4fc16b8236f68555f9546311326e56c1ea1fe858e3c66f3a1282d440e3b487579dd2c198c8b15a5bab82f1516f48c4013063319c4a06789f943c5fc4e7768c2c0d4ce871c3c51a177",
            hex"010001"
        );
        dkimKeys["fusemachines.com"]["google"] = key(
            hex"9157daff5eb845df246f5e315144ff112ac4f7caa555ad9185620b0a2e5ffb7b14492417c804f23e9d1ce90b5a6ee5719465a85e1ad8ff9b558353d4eb14ae3022f2ef2b25fae5e78fc37c0db1431524fefa6da783b62950694939e623caab7873a110cff9bb848f43e58afcfcb14de54af4f1fd3939e2472c6b9514f174e955",
            hex"010001"
        );
    }

    function updateKey(string memory domain, string memory selector, bytes memory exponent, bytes memory modulus) external onlyOwner {
        dkimKeys[domain][selector] = key(exponent, modulus);
        emit UpdateDKIMKey(domain, selector, exponent, modulus);
    }

    function removeKey(string memory domain, string memory selector) external onlyOwner {
        key memory k = dkimKeys[domain][selector];
        delete dkimKeys[domain][selector];
        emit DeleteDKIMKey(domain, selector, k.exponent, k.modulus);
    }

    function getKey(string memory domain, string memory selector) public view returns (bytes memory, bytes memory) {
        key memory k = dkimKeys[domain][selector];
        return (k.exponent, k.modulus);
    }

}
