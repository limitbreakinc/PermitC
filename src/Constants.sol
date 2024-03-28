// SPDX-License-Identifier: MIT
pragma solidity ^0.8.4;

bytes32 constant ZERO_BYTES32 = bytes32(0);

uint256 constant ZERO = 0;
uint256 constant ONE = 1;

uint8 constant ORDER_STATE_OPEN = 0;
uint8 constant ORDER_STATE_FILLED = 1;
uint8 constant ORDER_STATE_CANCELLED = 2;

bytes32 constant UPPER_BIT_MASK = (0x7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff);

// keccak256("UpdateApprovalBySignature(address token,uint256 id,uint256 amount,uint256 nonce,address operator,uint256 approvalExpiration,uint256 sigDeadline,uint256 masterNonce)")
bytes32 constant UPDATE_APPROVAL_TYPEHASH =
    0x81b133f56c472bf5da2040f8c656a8878b79c9f03dc577987254677a15aa1c8d;
// keccak256("PermitTransferFrom(address token,uint256 id,uint256 amount,uint256 nonce,address operator,uint256 expiration,uint256 masterNonce)")
bytes32 constant SINGLE_USE_PERMIT_TYPEHASH =
    0xf160315df13e27581afef864174cfcb89432db5cf7a399a29f606b80f7f64fd9;

string constant SINGLE_USE_PERMIT_ADVANCED_TYPEHASH_STUB =
    "PermitTransferFromWithAdditionalData(address token,uint256 id,uint256 amount,uint256 nonce,address operator,uint256 expiration,uint256 masterNonce,";