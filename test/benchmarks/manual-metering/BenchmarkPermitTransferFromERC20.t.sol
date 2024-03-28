pragma solidity ^0.8.9;

import "../BenchmarkBase.t.sol";


contract ManualBenchmarkPermitTransferFromERC20 is BenchmarkBase {
    function testBenchmarkPermitTransferFromERC20_x1000() public manuallyMetered {
        _runBenchmarkPermitTransferFromERC20(true, 1000, "Permit Transfer From ERC20");
    }

    function testBenchmarkPermitTransferFromWithAddtionalDataHashERC20_x1000() public manuallyMetered {
        _runBenchmarkPermitTransferFromWithAdditionalDataHashERC20(true, 1000, "Permit Transfer From With Additional Data Hash ERC20");
    }
}
