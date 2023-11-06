// SPDX-License-Identifier: MIT
pragma solidity ^0.8.13;

import "@openzeppelin/contracts/access/Ownable.sol";

contract DkimKeys is Ownable {
    event UpdateDKIMKey(
        string domain,
        string selector,
        bytes exponent,
        bytes modulus
    );
    event DeleteDKIMKey(
        string domain,
        string selector,
        bytes exponent,
        bytes modulus
    );

    struct key {
        bytes exponent;
        bytes modulus;
    }

    mapping(string => mapping(string => key)) private dkimKeys;

    constructor() {
        dkimKeys["gmail.com"]["20230601"] = key(
            hex"9edbd2293d6192a84a7b4c5c699d31f906e8b83b09b817dbcbf4bcda3c6ca02fd2a1d99f995b360f52801f79a2d40a9d31d535da1d957c44de389920198ab996377df7a009eee7764b238b42696168d1c7ecbc7e31d69bf3fcc337549dc4f0110e070cec0b111021f0435e51db415a2940011aee0d4db4767c32a76308aae634320642d63fe2e018e81f505e13e0765bd8f6366d0b443fa41ea8eb5c5b8aebb07db82fb5e10fe1d265bd61b22b6b13454f6e1273c43c08e0917cd795cc9d25636606145cff02c48d58d0538d96ab50620b28ad9f5aa685b528f41ef1bad24a546c8bdb1707fb6ee7a2e61bbb440cd9ab6795d4c106145000c13aeeedd678b05f",
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
        dkimKeys["yahoo.com"]["s2048"] = key(
            hex"ba85ae7e06d6c39f0c7335066ccbf5efa45ac5d64638c9109a7f0e389fc71a843a75a95231688b6a3f0831c1c2d5cb9b271da0ce200f40754fb4561acb22c0e1ac89512364d74feea9f072894f2a88f084e09485ae9c5f961308295e1bb7e835b87c3bc0bce0b827f8600a11e97c54291b00a07ba817b33ebfa6cc67f5f51bebe258790197851f80943a3bc17572428aa19e4aa949091f9a436aa6e0b3e1773e9ca201441f07a104cce03528c3d15891a9ce03ed2a8ba40dc42e294c3d180ba5ee4488c84722ceaadb69428d2c6026cf47a592a467cc8b15a73ea3753d7f615e518ba614390e6c3796ea37367c4f1a109646d5472e9e28e8d49e84924e648087",
            hex"010001"
        );
    }

    function updateKey(
        string memory domain,
        string memory selector,
        bytes memory exponent,
        bytes memory modulus
    ) external onlyOwner {
        dkimKeys[domain][selector] = key(exponent, modulus);
        emit UpdateDKIMKey(domain, selector, exponent, modulus);
    }

    function removeKey(
        string memory domain,
        string memory selector
    ) external onlyOwner {
        key memory k = dkimKeys[domain][selector];
        delete dkimKeys[domain][selector];
        emit DeleteDKIMKey(domain, selector, k.exponent, k.modulus);
    }

    function getKey(
        string memory domain,
        string memory selector
    ) public view returns (bytes memory, bytes memory) {
        key memory k = dkimKeys[domain][selector];
        return (k.exponent, k.modulus);
    }
}
