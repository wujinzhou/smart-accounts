// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.0;
import "@openzeppelin/contracts/token/ERC721/ERC721.sol";
contract MockNFT is ERC721{
    uint256 public totalSupply;
    constructor() ERC721("MockNFT", "MNFT") {
    }
    function mint() external {
        totalSupply++;
        _mint(msg.sender, totalSupply);
    }
}
