pragma solidity ^0.8.9;

import "../BenchmarkBase.t.sol";


contract ForgeBenchmarkPermitTransferFromERC20 is BenchmarkBase {
    function testBenchmarkPermitTransferFromERC20_x1000() public metered {
        _runBenchmarkPermitTransferFromERC20(false, 1000, "Permit Transfer From ERC20");
    }

    function testBenchmarkPermitTransferFromWithAddtionalDataHashERC20_x1000() public metered {
        _runBenchmarkPermitTransferFromWithAdditionalDataHashERC20(false, 1000, "Permit Transfer From With Additional Data Hash ERC20");
    }
}
