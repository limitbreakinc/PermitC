pragma solidity ^0.8.9;

import "../BenchmarkBase.t.sol";


contract ManualBenchmarkApprove is BenchmarkBase {
    function testBenchmarkApproveERC20_x1000() public manuallyMetered {
        _runBenchmarkApproveERC20(true, 1000, "Approve ERC20");
    }

    function testBenchmarkSignatureApproveERC20_x1000() public manuallyMetered {
        _runBenchmarkSignatureApproveERC20(true, 1000, "Signature Approve ERC20");
    }
}
