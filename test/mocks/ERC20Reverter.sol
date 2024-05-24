// SPDX-License-Identifier: MIT

pragma solidity ^0.8.9;

import "@openzeppelin/contracts/token/ERC20/ERC20.sol";

contract ERC20Reverter is ERC20 {
    constructor() ERC20("ERC-721C Mock", "MOCK") {}

    function mint(address to, uint256 amount) external {
        _mint(to, amount);
    }

    function transferFrom(address sender, address recipient, uint256 amount) public override returns (bool) {
        revert();
    }
}
