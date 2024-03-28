// SPDX-License-Identifier: MIT
pragma solidity ^0.8.4;

struct PackedApproval {
    // Only used for partial fill position 1155 transfers
    uint8 state;
    // Amount allowed
    uint200 amount;
    // Permission expiry
    uint48 expiration;
}

struct OrderFillAmounts {
    uint256 orderStartAmount;
    uint256 requestedFillAmount;
    uint256 minimumFillAmount;
}