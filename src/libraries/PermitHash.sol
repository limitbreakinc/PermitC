// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {SINGLE_USE_PERMIT_TYPEHASH, UPDATE_APPROVAL_TYPEHASH} from "../Constants.sol";

library PermitHash {

    /**
     * @notice  Hashes the permit data for a stored approval
     * 
     * @param tokenType           The type of token
     * @param token               The address of the token
     * @param id                  The id of the token
     * @param amount              The amount authorized by the owner signature
     * @param nonce               The nonce for the permit
     * @param operator            The account that is allowed to use the permit
     * @param approvalExpiration  The time the permit approval expires
     * @param sigDeadline         The deadline for submitting the permit onchain
     * @param masterNonce         The signers master nonce
     * 
     * @return hash  The hash of the permit data
     */
    function hashOnChainApproval(
        uint256 tokenType,
        address token,
        uint256 id,
        uint256 amount,
        uint256 nonce,
        address operator, 
        uint256 approvalExpiration,
        uint256 sigDeadline,
        uint256 masterNonce
    ) internal pure returns (bytes32 hash) {
        hash = keccak256(
            abi.encode(
                UPDATE_APPROVAL_TYPEHASH,
                tokenType,
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

    /**
     * @notice  Hashes the permit data with the single user permit without additional data typehash
     * 
     * @param tokenType               The type of token
     * @param token                   The address of the token
     * @param id                      The id of the token
     * @param amount                  The amount authorized by the owner signature
     * @param nonce                   The nonce for the permit
     * @param expiration              The time the permit expires
     * @param masterNonce             The signers master nonce
     * 
     * @return hash  The hash of the permit data
     */
    function hashSingleUsePermit(
        uint256 tokenType,
        address token,
        uint256 id,
        uint256 amount,
        uint256 nonce,
        uint256 expiration,
        uint256 masterNonce
    ) internal view returns (bytes32 hash) {
        hash = keccak256(
            abi.encode(
                SINGLE_USE_PERMIT_TYPEHASH,
                tokenType,
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

    /**
     * @notice  Hashes the permit data with the supplied typehash
     * 
     * @param tokenType               The type of token
     * @param token                   The address of the token
     * @param id                      The id of the token
     * @param amount                  The amount authorized by the owner signature
     * @param nonce                   The nonce for the permit
     * @param expiration              The time the permit expires
     * @param additionalData          The additional data to validate with the permit signature
     * @param additionalDataTypeHash  The typehash of the permit to use for validating the signature
     * @param masterNonce             The signers master nonce
     * 
     * @return hash  The hash of the permit data with the supplied typehash
     */
    function hashSingleUsePermitWithAdditionalData(
        uint256 tokenType,
        address token,
        uint256 id,
        uint256 amount,
        uint256 nonce,
        uint256 expiration,
        bytes32 additionalData,
        bytes32 additionalDataTypeHash,
        uint256 masterNonce
    ) internal view returns (bytes32 hash) {
        hash = keccak256(
            abi.encode(
                additionalDataTypeHash,
                tokenType,
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
