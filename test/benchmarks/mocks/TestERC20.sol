// SPDX-License-Identifier: Unlicense
pragma solidity 0.8.19;

import { ERC20 as SolmateERC20 } from "@rari-capital/solmate/src/tokens/ERC20.sol";

// Used for minting test ERC20s in our tests
contract TestERC20 is SolmateERC20("Test20", "TST20", 18) {
    constructor() {}

    function mint(address to, uint256 amount) external returns (bool) {
        _mint(to, amount);
        return true;
    }
}
