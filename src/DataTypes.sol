// SPDX-License-Identifier: MIT
pragma solidity ^0.8.4;

/// @dev Storage data struct for stored approvals and order approvals
struct PackedApproval {
    // Only used for partial fill position 1155 transfers
    uint8 state;
    // Amount allowed
    uint200 amount;
    // Permission expiry
    uint48 expiration;
}

/// @dev Calldata data struct for order fill amounts
struct OrderFillAmounts {
    uint256 orderStartAmount;
    uint256 requestedFillAmount;
    uint256 minimumFillAmount;
}