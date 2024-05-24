// SPDX-License-Identifier: MIT
pragma solidity ^0.8.4;

/// @dev Constant bytes32 value of 0x000...000
bytes32 constant ZERO_BYTES32 = bytes32(0);

/// @dev Constant value of 0
uint256 constant ZERO = 0;
/// @dev Constant value of 1
uint256 constant ONE = 1;

/// @dev Constant value representing an open order in storage
uint8 constant ORDER_STATE_OPEN = 0;
/// @dev Constant value representing a filled order in storage
uint8 constant ORDER_STATE_FILLED = 1;
/// @dev Constant value representing a cancelled order in storage
uint8 constant ORDER_STATE_CANCELLED = 2;

/// @dev Constant value representing the ERC721 token type for signatures and transfer hooks
uint256 constant TOKEN_TYPE_ERC721 = 721;
/// @dev Constant value representing the ERC1155 token type for signatures and transfer hooks
uint256 constant TOKEN_TYPE_ERC1155 = 1155;
/// @dev Constant value representing the ERC20 token type for signatures and transfer hooks
uint256 constant TOKEN_TYPE_ERC20 = 20;

/// @dev Constant value to mask the upper bits of a signature that uses a packed `vs` value to extract `s`
bytes32 constant UPPER_BIT_MASK = 0x7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff;

/// @dev EIP-712 typehash used for validating signature based stored approvals
bytes32 constant UPDATE_APPROVAL_TYPEHASH =
    keccak256("UpdateApprovalBySignature(uint256 tokenType,address token,uint256 id,uint256 amount,uint256 nonce,address operator,uint256 approvalExpiration,uint256 sigDeadline,uint256 masterNonce)");

/// @dev EIP-712 typehash used for validating a single use permit without additional data
bytes32 constant SINGLE_USE_PERMIT_TYPEHASH =
    keccak256("PermitTransferFrom(uint256 tokenType,address token,uint256 id,uint256 amount,uint256 nonce,address operator,uint256 expiration,uint256 masterNonce)");

/// @dev EIP-712 typehash used for validating a single use permit with additional data
string constant SINGLE_USE_PERMIT_TRANSFER_ADVANCED_TYPEHASH_STUB =
    "PermitTransferFromWithAdditionalData(uint256 tokenType,address token,uint256 id,uint256 amount,uint256 nonce,address operator,uint256 expiration,uint256 masterNonce,";

/// @dev EIP-712 typehash used for validating an order permit that updates storage as it fills
string constant PERMIT_ORDER_ADVANCED_TYPEHASH_STUB =
    "PermitOrderWithAdditionalData(uint256 tokenType,address token,uint256 id,uint256 amount,uint256 salt,address operator,uint256 expiration,uint256 masterNonce,";

/// @dev Pausable flag for stored approval transfers of ERC721 assets
uint256 constant PAUSABLE_APPROVAL_TRANSFER_FROM_ERC721 = 1 << 0;
/// @dev Pausable flag for stored approval transfers of ERC1155 assets
uint256 constant PAUSABLE_APPROVAL_TRANSFER_FROM_ERC1155 = 1 << 1;
/// @dev Pausable flag for stored approval transfers of ERC20 assets
uint256 constant PAUSABLE_APPROVAL_TRANSFER_FROM_ERC20 = 1 << 2;

/// @dev Pausable flag for single use permit transfers of ERC721 assets
uint256 constant PAUSABLE_PERMITTED_TRANSFER_FROM_ERC721 = 1 << 3;
/// @dev Pausable flag for single use permit transfers of ERC1155 assets
uint256 constant PAUSABLE_PERMITTED_TRANSFER_FROM_ERC1155 = 1 << 4;
/// @dev Pausable flag for single use permit transfers of ERC20 assets
uint256 constant PAUSABLE_PERMITTED_TRANSFER_FROM_ERC20 = 1 << 5;

/// @dev Pausable flag for order fill transfers of ERC1155 assets
uint256 constant PAUSABLE_ORDER_TRANSFER_FROM_ERC1155 = 1 << 6;
/// @dev Pausable flag for order fill transfers of ERC20 assets
uint256 constant PAUSABLE_ORDER_TRANSFER_FROM_ERC20 = 1 << 7;