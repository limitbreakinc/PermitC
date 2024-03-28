// SPDX-License-Identifier: Unlicense
pragma solidity 0.8.19;

contract ContractMock {
    constructor() {}

    fallback() external payable {}
    receive() external payable {}
}