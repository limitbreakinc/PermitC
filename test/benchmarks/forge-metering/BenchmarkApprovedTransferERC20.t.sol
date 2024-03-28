pragma solidity ^0.8.9;

import "../BenchmarkBase.t.sol";


contract ForgeBenchmarkApprovedTransferERC20 is BenchmarkBase {
    function setUp() public virtual override {
        super.setUp();

        vm.prank(alice);
        permitC.approve(
            address(token20),
            0,
            address(operator),
            uint200(USER_STARTING_BALANCE),
            uint48(block.timestamp + 100000)
        );

    }

    function testBenchmarkApprovedTransferFromERC20_x1000() public metered {
        _runBenchmarkApprovedTransferFromERC20(false, 1000, "Approved Transfer From ERC20");
    }
}
