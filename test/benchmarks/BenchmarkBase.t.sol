pragma solidity ^0.8.9;

import "forge-std/Test.sol";
import "forge-std/console.sol";

import "src/Constants.sol";
import "src/PermitC.sol";
import "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import "@openzeppelin/contracts/utils/math/Math.sol";

import "./mocks/ContractMock.sol";
import "./mocks/TestERC20.sol";

import {MainnetMetering} from "forge-gas-metering/src/MainnetMetering.sol";

contract BenchmarkBase is MainnetMetering, Test {
    struct TransferPermit {
        address token;
        uint256 id;
        uint256 amount;
        uint256 nonce;
        address operator;
        uint256 expiration;
        uint160 signerKey;
        address owner;
        address to;
    }

    struct GasMetrics {
        uint256 min;
        uint256 max;
        uint256 total;
        uint256 observations;
    }

    uint256 internal USER_STARTING_BALANCE = 1_000_000_000_000_000;
    uint256 internal BENCHMARK_TRANSFER_AMOUNT = 1_000_000;

    bool constant DEBUG_ACCESSES = false;

    PermitC permitC;
    TestERC20 token20;
    ContractMock operator;

    uint160 internal alicePk = 0xa11ce;
    uint160 internal bobPk = 0xb0b;
    address payable internal alice = payable(vm.addr(alicePk));
    address payable internal bob = payable(vm.addr(bobPk));

    GasMetrics internal gasMetrics;

    mapping (address => uint256) internal _nonces;

    bytes32 constant MOAR_DATA_HASH = bytes32(0x15978d334b98e79a31905990c775bcf838d5f3b17662696ebc3caa71f9b58404);
    bytes32 constant MOAR_DATA_PERMIT_HASH = bytes32(0x585369b11932ef54806b5909738c52d4e5f247a909a911bc80018a19ac879cb1);
    string constant MOAR_DATA_TYPE_STRING = "MoarData data)MoarData(uint256 one,uint256 two,uint256 three,uint256 four,uint256 five,uint256 six)";

    function setUp() public virtual {
        setUpMetering({verbose: false});

        permitC = new PermitC("PermitC", "1");
        token20 = new TestERC20();
        operator = new ContractMock();

        token20.mint(alice, USER_STARTING_BALANCE);
        token20.mint(bob, USER_STARTING_BALANCE);

        vm.startPrank(alice);
        token20.approve(address(permitC), type(uint256).max);
        permitC.invalidateUnorderedNonce(_getNextNonce(alice));
        vm.stopPrank();

        vm.startPrank(bob);
        token20.approve(address(permitC), type(uint256).max);
        permitC.invalidateUnorderedNonce(_getNextNonce(bob));
        vm.stopPrank();

        permitC.registerAdditionalDataHash(MOAR_DATA_TYPE_STRING);

        // Warp to a more realistic timestamp
        vm.warp(1703688340);
    }

    function _clearGasMetrics() internal {
        gasMetrics.min = type(uint256).max;
        gasMetrics.max = 0;
        gasMetrics.total = 0;
        gasMetrics.observations = 0;
    }

    function _updateGasMetrics(uint256 gasMeasurement) internal {
        gasMetrics.min = Math.min(gasMetrics.min, gasMeasurement);
        gasMetrics.max = Math.max(gasMetrics.max, gasMeasurement);
        gasMetrics.total += gasMeasurement;
        gasMetrics.observations++;
    }

    function _logGasMetrics(bool manuallyMetered_, string memory label) internal view {
        if (manuallyMetered_) {
            console.log(label);
            console.log("Min: %s", gasMetrics.min);
            console.log("Max: %s", gasMetrics.max);
            console.log("Avg: %s", gasMetrics.total / gasMetrics.observations);
        }
    }

    function _record() internal {
        if (!DEBUG_ACCESSES) {
            return;
        }

        vm.record();
    }

    function _logAccesses(address account) internal {
        if (!DEBUG_ACCESSES) {
            return;
        }

        (bytes32[] memory reads, bytes32[] memory writes) = vm.accesses(account);

        console.log("Reads: %s", reads.length);
        for (uint256 j = 0; j < reads.length; j++) {
            console.logBytes32(reads[j]);
        }
        console.log("Writes: %s", writes.length);
        for (uint256 j = 0; j < writes.length; j++) {
            console.logBytes32(writes[j]);
        }
    }

    function _getNextNonce(address account) internal returns (uint256) {
        uint256 nextUnusedNonce = _nonces[account];
        ++_nonces[account];
        return nextUnusedNonce;
    }

    function _runBenchmarkCancelNonce(bool manuallyMetered_, uint256 runs, string memory label) internal {
        _clearGasMetrics();

        for (uint256 i = 0; i < runs; i++) {
            uint256 nonce = _getNextNonce(alice);

            if (!manuallyMetered_) {
                _record();
                vm.prank(alice);
                permitC.invalidateUnorderedNonce(nonce);
                _logAccesses(address(permitC));
            } else {
                (uint256 gasUsed,) = meterCall({
                    from: alice,
                    to: address(permitC),
                    callData: abi.encodeWithSignature(
                        "invalidateUnorderedNonce(uint256)", 
                        nonce
                    ),
                    value: 0,
                    transaction: true
                });

                _updateGasMetrics(gasUsed);
            }
        }

        _logGasMetrics(manuallyMetered_, label);
    }

    function _runBenchmarkPermitTransferFromERC20(bool manuallyMetered_, uint256 runs, string memory label) internal {
        _clearGasMetrics();

        for (uint256 i = 0; i < runs; i++) {
            TransferPermit memory permitRequest = TransferPermit({
                token: address(token20),
                id: 0,
                amount: BENCHMARK_TRANSFER_AMOUNT,
                nonce: _getNextNonce(alice),
                operator: address(operator),
                expiration: block.timestamp + 1000,
                signerKey: alicePk,
                owner: alice,
                to: bob
            });
    
            bytes memory signedPermit = _getSignedSingleUseTransferPermit(permitRequest);

            if (!manuallyMetered_) {
                _record();
                vm.prank(address(operator), alice);
                permitC.permitTransferFromERC20(
                    permitRequest.token,
                    permitRequest.nonce,
                    permitRequest.amount,
                    permitRequest.expiration,
                    permitRequest.owner,
                    permitRequest.to,
                    permitRequest.amount,
                    signedPermit
                );
                _logAccesses(address(permitC));
            } else {
                (uint256 gasUsed,) = meterCall({
                    from: address(operator),
                    to: address(permitC),
                    callData: abi.encodeWithSignature(
                        "permitTransferFromERC20(address,uint256,uint256,uint256,address,address,uint256,bytes)", 
                        permitRequest.token,
                        permitRequest.nonce,
                        permitRequest.amount,
                        permitRequest.expiration,
                        permitRequest.owner,
                        permitRequest.to,
                        permitRequest.amount,
                        signedPermit
                    ),
                    value: 0,
                    transaction: true
                });

                _updateGasMetrics(gasUsed);
            }
        }

        _logGasMetrics(manuallyMetered_, label);
    }

    function _runBenchmarkPermitTransferFromWithAdditionalDataHashERC20(bool manuallyMetered_, uint256 runs, string memory label) internal {
        _clearGasMetrics();

        for (uint256 i = 0; i < runs; i++) {
            TransferPermit memory permitRequest = TransferPermit({
                token: address(token20),
                id: 0,
                amount: BENCHMARK_TRANSFER_AMOUNT,
                nonce: _getNextNonce(alice),
                operator: address(operator),
                expiration: block.timestamp + 1000,
                signerKey: alicePk,
                owner: alice,
                to: bob
            });
    
            (
                bytes memory signedPermit, 
                bytes32 additionalData
            ) = _getSignedSingleUseTransferPermitWithAdditionalData(permitRequest);

            if (!manuallyMetered_) {
                _record();
                vm.prank(address(operator), alice);
                permitC.permitTransferFromWithAdditionalDataERC20(
                    permitRequest.token,
                    permitRequest.nonce,
                    permitRequest.amount,
                    permitRequest.expiration,
                    permitRequest.owner,
                    permitRequest.to,
                    permitRequest.amount,
                    additionalData,
                    MOAR_DATA_PERMIT_HASH,
                    signedPermit
                );
                _logAccesses(address(permitC));
            } else {
                (uint256 gasUsed,) = meterCall({
                    from: address(operator),
                    to: address(permitC),
                    callData: abi.encodeWithSignature(
                        "permitTransferFromWithAdditionalDataERC20(address,uint256,uint256,uint256,address,address,uint256,bytes32,bytes32,bytes)", 
                        permitRequest.token,
                        permitRequest.nonce,
                        permitRequest.amount,
                        permitRequest.expiration,
                        permitRequest.owner,
                        permitRequest.to,
                        permitRequest.amount,
                        additionalData,
                        MOAR_DATA_PERMIT_HASH,
                        signedPermit
                    ),
                    value: 0,
                    transaction: true
                });

                _updateGasMetrics(gasUsed);
            }
        }

        _logGasMetrics(manuallyMetered_, label);
    }

    function _runBenchmarkApproveERC20(bool manuallyMetered_, uint256 runs, string memory label) internal {
        _clearGasMetrics();

        for (uint256 i = 0; i < runs; i++) {
            TransferPermit memory permitRequest = TransferPermit({
                token: address(token20),
                id: 0,
                amount: BENCHMARK_TRANSFER_AMOUNT,
                nonce: _getNextNonce(alice),
                operator: address(operator),
                expiration: block.timestamp + 1000,
                signerKey: alicePk,
                owner: alice,
                to: bob
            });

            if (!manuallyMetered_) {
                _record();
                vm.prank(alice);
                permitC.approve(
                    permitRequest.token,
                    permitRequest.id,
                    permitRequest.operator,
                    uint200(permitRequest.amount),
                    uint48(permitRequest.expiration)
                );
                _logAccesses(address(permitC));
            } else {
                (uint256 gasUsed,) = meterCall({
                    from: alice,
                    to: address(permitC),
                    callData: abi.encodeWithSignature(
                        "approve(address,uint256,address,uint200,uint48)", 
                        permitRequest.token,
                        permitRequest.id,
                        permitRequest.operator,
                        uint200(permitRequest.amount),
                        uint48(permitRequest.expiration)
                    ),
                    value: 0,
                    transaction: true
                });

                _updateGasMetrics(gasUsed);
            }
        }

        _logGasMetrics(manuallyMetered_, label);
    }

    function _runBenchmarkSignatureApproveERC20(bool manuallyMetered_, uint256 runs, string memory label) internal {
        _clearGasMetrics();

        for (uint256 i = 0; i < runs; i++) {
            TransferPermit memory permitRequest = TransferPermit({
                token: address(token20),
                id: 0,
                amount: BENCHMARK_TRANSFER_AMOUNT,
                nonce: _getNextNonce(alice),
                operator: address(operator),
                expiration: block.timestamp + 1000,
                signerKey: alicePk,
                owner: alice,
                to: bob
            });

            bytes memory signedPermit = _getSignedApprovalPermit(permitRequest);

            if (!manuallyMetered_) {
                _record();
                vm.prank(alice);
                permitC.updateApprovalBySignature(
                    permitRequest.token,
                    permitRequest.id,
                    permitRequest.nonce,
                    uint200(permitRequest.amount),
                    permitRequest.operator,
                    uint48(permitRequest.expiration),
                    uint48(permitRequest.expiration),
                    permitRequest.owner,
                    signedPermit
                );
                _logAccesses(address(permitC));
            } else {
                (uint256 gasUsed,) = meterCall({
                    from: alice,
                    to: address(permitC),
                    callData: abi.encodeWithSignature(
                        "updateApprovalBySignature(address,uint256,uint256,uint200,address,uint48,uint48,address,bytes)", 
                        permitRequest.token,
                        permitRequest.id,
                        permitRequest.nonce,
                        uint200(permitRequest.amount),
                        permitRequest.operator,
                        uint48(permitRequest.expiration),
                        uint48(permitRequest.expiration),
                        permitRequest.owner,
                        signedPermit
                    ),
                    value: 0,
                    transaction: true
                });

                _updateGasMetrics(gasUsed);
            }
        }

        _logGasMetrics(manuallyMetered_, label);
    }

    function _runBenchmarkApprovedTransferFromERC20(bool manuallyMetered_, uint256 runs, string memory label) internal {
        _clearGasMetrics();

        for (uint256 i = 0; i < runs; i++) {
            TransferPermit memory permitRequest = TransferPermit({
                token: address(token20),
                id: 0,
                amount: BENCHMARK_TRANSFER_AMOUNT,
                nonce: _getNextNonce(alice),
                operator: address(operator),
                expiration: block.timestamp + 1000,
                signerKey: alicePk,
                owner: alice,
                to: bob
            });
    
            if (!manuallyMetered_) {
                _record();
                vm.prank(address(operator), alice);
                permitC.transferFromERC20(
                    permitRequest.owner,
                    permitRequest.to,
                    permitRequest.token,
                    permitRequest.amount
                );
                _logAccesses(address(permitC));
            } else {
                (uint256 gasUsed,) = meterCall({
                    from: address(operator),
                    to: address(permitC),
                    callData: abi.encodeWithSignature(
                        "transferFromERC20(address,address,address,uint256)", 
                        permitRequest.owner,
                        permitRequest.to,
                        permitRequest.token,
                        permitRequest.amount
                    ),
                    value: 0,
                    transaction: true
                });

                _updateGasMetrics(gasUsed);
            }
        }

        _logGasMetrics(manuallyMetered_, label);
    }

    function _getSignedSingleUseTransferPermit(
        TransferPermit memory permitRequest
    ) internal view returns (bytes memory signedPermit) {
        bytes32 digest = ECDSA.toTypedDataHash(
            permitC.domainSeparatorV4(),
            keccak256(
                abi.encode(
                    SINGLE_USE_PERMIT_TYPEHASH,
                    permitRequest.token,
                    permitRequest.id,
                    permitRequest.amount,
                    permitRequest.nonce,
                    permitRequest.operator,
                    permitRequest.expiration,
                    permitC.masterNonce(vm.addr(permitRequest.signerKey))
                )
            )
        );

        (uint8 v, bytes32 r, bytes32 s) = vm.sign(permitRequest.signerKey, digest);
        signedPermit = abi.encodePacked(r, s, v);
    }

    function _getSignedSingleUseTransferPermitWithAdditionalData(
        TransferPermit memory permitRequest
    ) internal view returns (bytes memory signedPermit, bytes32 additionalData) {
        additionalData = keccak256(abi.encode(MOAR_DATA_HASH, 1, 2, 3, 4, 5, 6));

        bytes32 digest = ECDSA.toTypedDataHash(
            permitC.domainSeparatorV4(),
            keccak256(
                bytes.concat(
                    abi.encode(
                        MOAR_DATA_PERMIT_HASH,
                        permitRequest.token,
                        permitRequest.id,
                        permitRequest.amount,
                        permitRequest.nonce
                    ),
                    abi.encode(
                        permitRequest.operator,
                        permitRequest.expiration,
                        permitC.masterNonce(vm.addr(permitRequest.signerKey)),
                        additionalData
                    )
                )
            )
        );

        (uint8 v, bytes32 r, bytes32 s) = vm.sign(permitRequest.signerKey, digest);
        signedPermit = abi.encodePacked(r, s, v);
    }

    function _getSignedApprovalPermit(
        TransferPermit memory permitRequest
    ) internal view returns (bytes memory signedPermit) {
        bytes32 digest = ECDSA.toTypedDataHash(
            permitC.domainSeparatorV4(),
            keccak256(
                bytes.concat(
                    abi.encode(
                        UPDATE_APPROVAL_TYPEHASH,
                        permitRequest.token,
                        permitRequest.id,
                        permitRequest.amount,
                        permitRequest.nonce
                    ),
                    abi.encode(
                        permitRequest.operator,
                        permitRequest.expiration,
                        permitRequest.expiration,
                        permitC.masterNonce(vm.addr(permitRequest.signerKey))
                    )
                )
            )
        );

        (uint8 v, bytes32 r, bytes32 s) = vm.sign(permitRequest.signerKey, digest);
        signedPermit = abi.encodePacked(r, s, v);
    }
}
