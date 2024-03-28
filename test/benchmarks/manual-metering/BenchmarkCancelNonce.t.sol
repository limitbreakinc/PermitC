pragma solidity ^0.8.9;

import "../BenchmarkBase.t.sol";


contract ManualBenchmarkCancelNonce is BenchmarkBase {
    function testBenchmarkCancelNonce_x1000() public manuallyMetered {
        _runBenchmarkCancelNonce(true, 1000, "Cancel Nonce");
    }
}
