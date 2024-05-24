// SPDX-License-Identifier: MIT
pragma solidity ^0.8.4;

/// @dev Thrown when a stored approval exceeds type(uint200).max
error PermitC__AmountExceedsStorageMaximum();

/// @dev Thrown when a transfer amount requested exceeds the permitted amount
error PermitC__ApprovalTransferExceededPermittedAmount();

/// @dev Thrown when a transfer is requested after the permit has expired
error PermitC__ApprovalTransferPermitExpiredOrUnset();

/// @dev Thrown when attempting to close an order by an account that is not the owner or operator
error PermitC__CallerMustBeOwnerOrOperator();

/// @dev Thrown when attempting to approve a token type that is not valid for PermitC
error PermitC__InvalidTokenType();

/// @dev Thrown when attempting to invalidate a nonce that has already been used
error PermitC__NonceAlreadyUsedOrRevoked();

/// @dev Thrown when attempting to restore a nonce that has not been used
error PermitC__NonceNotUsedOrRevoked();

/// @dev Thrown when attempting to fill an order that has already been filled or cancelled
error PermitC__OrderIsEitherCancelledOrFilled();

/// @dev Thrown when a transfer amount requested exceeds the permitted amount
error PermitC__SignatureTransferExceededPermittedAmount();

/// @dev Thrown when a transfer is requested after the permit has expired
error PermitC__SignatureTransferExceededPermitExpired();

/// @dev Thrown when attempting to use an advanced permit typehash that is not registered
error PermitC__SignatureTransferPermitHashNotRegistered();

/// @dev Thrown when a permit signature is invalid
error PermitC__SignatureTransferInvalidSignature();

/// @dev Thrown when the remaining fill amount is less than the requested minimum fill
error PermitC__UnableToFillMinimumRequestedQuantity();