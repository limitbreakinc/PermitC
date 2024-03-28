// SPDX-License-Identifier: MIT
pragma solidity ^0.8.4;

import {SINGLE_USE_PERMIT_ADVANCED_TYPEHASH_STUB, SINGLE_USE_PERMIT_TYPEHASH, UPDATE_APPROVAL_TYPEHASH} from "../Constants.sol";

library PermitHash {

    function hashOnChainApproval(
        address token,
        uint256 id,
        uint256 amount,
        uint256 nonce,
        address operator, 
        uint256 approvalExpiration,
        uint256 sigDeadline,
        uint256 masterNonce
    ) internal pure returns (bytes32) {
        return keccak256(
            abi.encode(
                UPDATE_APPROVAL_TYPEHASH,
                token,
                id,
                amount,
                nonce,
                operator,
                approvalExpiration,
                sigDeadline,
                masterNonce
            )
        );
    }

    function hashSingleUsePermit(
        address token,
        uint256 id,
        uint256 amount,
        uint256 nonce,
        uint256 expiration,
        uint256 masterNonce
    ) internal view returns (bytes32) {
        return keccak256(
            abi.encode(
                SINGLE_USE_PERMIT_TYPEHASH,
                token,
                id,
                amount,
                nonce,
                msg.sender,
                expiration,
                masterNonce
            )
        );
    }

    function hashSingleUsePermitWithAdditionalData(
        address token,
        uint256 id,
        uint256 amount,
        uint256 nonce,
        uint256 expiration,
        bytes32 additionalData,
        bytes32 additionalDataTypeHash,
        uint256 masterNonce
    ) internal view returns (bytes32) {
        return keccak256(
            abi.encode(
                additionalDataTypeHash,
                token,
                id,
                amount,
                nonce,
                msg.sender,
                expiration,
                masterNonce,
                additionalData
            )
        );
    }
}
