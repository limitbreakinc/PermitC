// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "./Errors.sol";
import {IERC20} from "@openzeppelin/contracts/interfaces/IERC20.sol";
import {IERC721} from "@openzeppelin/contracts/interfaces/IERC721.sol";
import {IERC1155} from "@openzeppelin/contracts/interfaces/IERC1155.sol";
import {IERC1271} from "@openzeppelin/contracts/interfaces/IERC1271.sol";
import {Ownable} from "./openzeppelin-optimized/Ownable.sol";
import {EIP712} from "./openzeppelin-optimized/EIP712.sol";
import {
    ZERO_BYTES32,
    ZERO, 
    ONE, 
    ORDER_STATE_OPEN,
    ORDER_STATE_FILLED,
    ORDER_STATE_CANCELLED,
    SINGLE_USE_PERMIT_TRANSFER_ADVANCED_TYPEHASH_STUB,
    PERMIT_ORDER_ADVANCED_TYPEHASH_STUB,
    UPPER_BIT_MASK,
    TOKEN_TYPE_ERC1155,
    TOKEN_TYPE_ERC20,
    TOKEN_TYPE_ERC721,
    PAUSABLE_APPROVAL_TRANSFER_FROM_ERC721,
    PAUSABLE_APPROVAL_TRANSFER_FROM_ERC1155,
    PAUSABLE_APPROVAL_TRANSFER_FROM_ERC20,
    PAUSABLE_PERMITTED_TRANSFER_FROM_ERC721,
    PAUSABLE_PERMITTED_TRANSFER_FROM_ERC1155,
    PAUSABLE_PERMITTED_TRANSFER_FROM_ERC20,
    PAUSABLE_ORDER_TRANSFER_FROM_ERC1155,
    PAUSABLE_ORDER_TRANSFER_FROM_ERC20
} from "./Constants.sol";
import {PackedApproval, OrderFillAmounts} from "./DataTypes.sol";
import {PermitHash} from './libraries/PermitHash.sol';
import {IPermitC} from './interfaces/IPermitC.sol';
import {CollateralizedPausableFlags} from './CollateralizedPausableFlags.sol';

/*
                                                     @@@@@@@@@@@@@@             
                                                    @@@@@@@@@@@@@@@@@@(         
                                                   @@@@@@@@@@@@@@@@@@@@@        
                                                  @@@@@@@@@@@@@@@@@@@@@@@@      
                                                           #@@@@@@@@@@@@@@      
                                                               @@@@@@@@@@@@     
                            @@@@@@@@@@@@@@*                    @@@@@@@@@@@@     
                           @@@@@@@@@@@@@@@     @               @@@@@@@@@@@@     
                          @@@@@@@@@@@@@@@     @                @@@@@@@@@@@      
                         @@@@@@@@@@@@@@@     @@               @@@@@@@@@@@@      
                        @@@@@@@@@@@@@@@     #@@             @@@@@@@@@@@@/       
                        @@@@@@@@@@@@@@.     @@@@@@@@@@@@@@@@@@@@@@@@@@@         
                       @@@@@@@@@@@@@@@     @@@@@@@@@@@@@@@@@@@@@@@@@            
                      @@@@@@@@@@@@@@@     @@@@@@@@@@@@@@@@@@@@@@@@@             
                     @@@@@@@@@@@@@@@     @@@@@@@@@@@@@@@@@@@@@@@@@@@@           
                    @@@@@@@@@@@@@@@     @@@@@&%%%%%%%%&&@@@@@@@@@@@@@@          
                    @@@@@@@@@@@@@@      @@@@@               @@@@@@@@@@@         
                   @@@@@@@@@@@@@@@     @@@@@                 @@@@@@@@@@@        
                  @@@@@@@@@@@@@@@     @@@@@@                 @@@@@@@@@@@        
                 @@@@@@@@@@@@@@@     @@@@@@@                 @@@@@@@@@@@        
                @@@@@@@@@@@@@@@     @@@@@@@                 @@@@@@@@@@@&        
                @@@@@@@@@@@@@@     *@@@@@@@               (@@@@@@@@@@@@         
               @@@@@@@@@@@@@@@     @@@@@@@@             @@@@@@@@@@@@@@          
              @@@@@@@@@@@@@@@     @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@           
             @@@@@@@@@@@@@@@     @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@            
            @@@@@@@@@@@@@@@     @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@              
           .@@@@@@@@@@@@@@     @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@                 
           @@@@@@@@@@@@@@%     @@@@@@@@@@@@@@@@@@@@@@@@(                        
          @@@@@@@@@@@@@@@                                                       
         @@@@@@@@@@@@@@@                                                        
        @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@                                         
       @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@                                          
       @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@&                                          
      @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@                                           
 
* @title PermitC
* @custom:version 1.0.0
* @author Limit Break, Inc.
* @description Advanced approval management for ERC20, ERC721 and ERC1155 tokens
*              allowing for single use permit transfers, time-bound approvals
*              and order ID based transfers.
*/
contract PermitC is Ownable, CollateralizedPausableFlags, EIP712, IPermitC {

    /**
     * @notice Map of approval details for the provided bytes32 hash to allow for multiple accessors
     *
     * @dev    keccak256(abi.encode(owner, tokenType, token, id, orderId, masterNonce)) => 
     * @dev        operator => (state, amount, expiration)
     * @dev    Utilized for stored approvals by an owner's direct call to `approve` and  
     * @dev    approvals by signature in `updateApprovalBySignature`. Both methods use a
     * @dev    bytes32(0) value for the `orderId`.
     */
    mapping(bytes32 => mapping(address => PackedApproval)) private _transferApprovals;

    /**
     * @notice Map of approval details for the provided bytes32 hash to allow for multiple accessors
     *
     * @dev    keccak256(abi.encode(owner, tokenType, token, id, orderId, masterNonce)) => 
     * @dev        operator => (state, amount, expiration)
     * @dev    Utilized for order approvals by `fillPermittedOrderERC20` and `fillPermittedOrderERC1155`
     * @dev    with the `orderId` provided by the sender.
     */
    mapping(bytes32 => mapping(address => PackedApproval)) private _orderApprovals;

    /**
     * @notice Map of registered additional data hashes for transfer permits.
     *
     * @dev    This is used to prevent someone from providing an invalid EIP712 envelope label
     * @dev    and tricking a user into signing a different message than they expect.
     */
    mapping(bytes32 => bool) private _registeredTransferHashes;

    /**
     * @notice Map of registered additional data hashes for order permits.
     *
     * @dev    This is used to prevent someone from providing an invalid EIP712 envelope label
     * @dev    and tricking a user into signing a different message than they expect.
     */
    mapping(bytes32 => bool) private _registeredOrderHashes;

    /// @dev Map of an address to a bitmap (slot => status)
    mapping(address => mapping(uint256 => uint256)) private _unorderedNonces;

    /**
     * @notice Master nonce used to invalidate all outstanding approvals for an owner
     *
     * @dev    owner => masterNonce
     * @dev    This is incremented when the owner calls lockdown()
     */
    mapping(address => uint256) private _masterNonces;

    constructor(
        string memory name,
        string memory version,
        address _defaultContractOwner,
        uint256 _nativeValueToCheckPauseState
    ) CollateralizedPausableFlags(_nativeValueToCheckPauseState) EIP712(name, version) {
        _transferOwnership(_defaultContractOwner);
    }

    /**
     * =================================================
     * ================= Modifiers =====================
     * =================================================
     */

    modifier onlyRegisteredTransferAdvancedTypeHash(bytes32 advancedPermitHash) {
        _requireTransferAdvancedPermitHashIsRegistered(advancedPermitHash);
        _;
    }

    modifier onlyRegisteredOrderAdvancedTypeHash(bytes32 advancedPermitHash) {
        _requireOrderAdvancedPermitHashIsRegistered(advancedPermitHash);
        _;
    }

    /**
     * =================================================
     * ============== Approval Transfers ===============
     * =================================================
     */

    /**
     * @notice Approve an operator to spend a specific token / ID combination
     * @notice This function is compatible with ERC20, ERC721 and ERC1155
     * @notice To give unlimited approval for ERC20 and ERC1155, set amount to type(uint200).max
     * @notice When approving an ERC721, you MUST set amount to `1`
     * @notice When approving an ERC20, you MUST set id to `0`
     *
     * @dev    <h4>Postconditions:</h4>
     * @dev    1. Updates the approval for an operator to use an amount of a specific token / ID combination
     * @dev    2. If the expiration is 0, the approval is valid only in the context of the current block
     * @dev    3. If the expiration is not 0, the approval is valid until the expiration timestamp
     * @dev    4. If the provided amount is type(uint200).max, the approval is unlimited
     *
     * @param  tokenType  The type of token being approved - must be 20, 721 or 1155.
     * @param  token      The address of the token contract
     * @param  id         The token ID
     * @param  operator   The address of the operator
     * @param  amount     The amount of tokens to approve
     * @param  expiration The expiration timestamp of the approval
     */
    function approve(
        uint256 tokenType,
        address token, 
        uint256 id, 
        address operator, 
        uint200 amount, 
        uint48 expiration
    ) external {
        _requireValidTokenType(tokenType);
        _storeApproval(tokenType, token, id, amount, expiration, msg.sender, operator);
    }

    /**
     * @notice Use a signed permit to increase the allowance for a provided operator
     * @notice This function is compatible with ERC20, ERC721 and ERC1155
     * @notice To give unlimited approval for ERC20 and ERC1155, set amount to type(uint200).max
     * @notice When approving an ERC721, you MUST set amount to `1`
     * @notice When approving an ERC20, you MUST set id to `0`
     * @notice An `approvalExpiration` of zero is considered an atomic permit which will use the 
     * @notice current block time as the expiration time when storing the permit data.
     *
     * @dev    - Throws if the permit has expired
     * @dev    - Throws if the permit's nonce has already been used
     * @dev    - Throws if the permit signature is does not recover to the provided owner
     *
     * @dev    <h4>Postconditions:</h4>
     * @dev    1. Updates the approval for an operator to use an amount of a specific token / ID combination
     * @dev    3. Sets the expiration of the approval to the expiration timestamp of the permit
     * @dev    4. If the provided amount is type(uint200).max, the approval is unlimited
     *
     * @param  tokenType            The type of token being approved - must be 20, 721 or 1155.
     * @param  token                Address of the token to approve
     * @param  id                   The token ID
     * @param  nonce                The nonce of the permit
     * @param  amount               The amount of tokens to approve
     * @param  operator             The address of the operator
     * @param  approvalExpiration   The expiration timestamp of the approval
     * @param  sigDeadline          The deadline timestamp for the permit signature
     * @param  owner                The owner of the tokens
     * @param  signedPermit         The permit signature, signed by the owner
     */
    function updateApprovalBySignature(
        uint256 tokenType,
        address token,
        uint256 id,
        uint256 nonce,
        uint200 amount,
        address operator,
        uint48 approvalExpiration,
        uint48 sigDeadline,
        address owner,
        bytes calldata signedPermit
    ) external {
        if (block.timestamp > sigDeadline) {
            revert PermitC__ApprovalTransferPermitExpiredOrUnset();
        }
        _requireValidTokenType(tokenType);
        _checkAndInvalidateNonce(owner, nonce);
        _verifyPermitSignature(
            _hashTypedDataV4(
                PermitHash.hashOnChainApproval(
                    tokenType,
                    token,
                    id,
                    amount,
                    nonce,
                    operator,
                    approvalExpiration,
                    sigDeadline,
                    _masterNonces[owner]
                )
            ),
            signedPermit, 
            owner
        );

        // Expiration of zero is considered an atomic permit which is only valid in the 
        // current block.
        approvalExpiration = approvalExpiration == 0 ? uint48(block.timestamp) : approvalExpiration;

        _storeApproval(tokenType, token, id, amount, approvalExpiration, owner, operator);
    }

    /**
     * @notice Returns the amount of allowance an operator has and it's expiration for a specific token and id
     * @notice If the expiration on the allowance has expired, returns 0
     * @notice To retrieve allowance for ERC20, set id to `0`
     * 
     * @param  owner     The owner of the token
     * @param  operator  The operator of the token
     * @param  tokenType The type of token the allowance is for
     * @param  token     The address of the token contract
     * @param  id        The token ID
     *
     * @return allowedAmount The amount of allowance the operator has
     * @return expiration    The expiration timestamp of the allowance
     */
    function allowance(
        address owner, 
        address operator, 
        uint256 tokenType,
        address token, 
        uint256 id
    ) external view returns (uint256 allowedAmount, uint256 expiration) {
        return _allowance(_transferApprovals, owner, operator, tokenType, token, id, ZERO_BYTES32);
    }

    /**
     * =================================================
     * ================ Signed Transfers ===============
     * =================================================
     */

    /**
     * @notice Registers the combination of a provided string with the `SINGLE_USE_PERMIT_TRANSFER_ADVANCED_TYPEHASH_STUB` 
     * @notice and `PERMIT_ORDER_ADVANCED_TYPEHASH_STUB` to create valid additional data hashes
     *
     * @dev    This function prevents malicious actors from changing the label of the EIP712 hash
     * @dev    to a value that would fool an external user into signing a different message.
     *
     * @dev    <h4>Postconditions:</h4>
     * @dev    1. The provided string is combined with the `SINGLE_USE_PERMIT_TRANSFER_ADVANCED_TYPEHASH_STUB` string
     * @dev    2. The combined string is hashed using keccak256
     * @dev    3. The resulting hash is added to the `_registeredTransferHashes` mapping
     * @dev    4. The provided string is combined with the `PERMIT_ORDER_ADVANCED_TYPEHASH_STUB` string
     * @dev    5. The combined string is hashed using keccak256
     * @dev    6. The resulting hash is added to the `_registeredOrderHashes` mapping
     *
     * @param  additionalDataTypeString The string to register as a valid additional data hash
     */
    function registerAdditionalDataHash(string calldata additionalDataTypeString) external {
        _registeredTransferHashes[
            keccak256(
                bytes(
                    string.concat(
                        SINGLE_USE_PERMIT_TRANSFER_ADVANCED_TYPEHASH_STUB, 
                        additionalDataTypeString
                    )
                )
            )
        ] = true;

        _registeredOrderHashes[
            keccak256(
                bytes(
                    string.concat(
                        PERMIT_ORDER_ADVANCED_TYPEHASH_STUB, 
                        additionalDataTypeString
                    )
                )
            )
        ] = true;
    }

    /**
     * @notice Transfer an ERC721 token from the owner to the recipient using a permit signature.
     *
     * @dev    Be advised that the permitted amount for ERC721 is always inferred to be 1, so signed permitted amount
     * @dev    MUST always be set to 1.
     *
     * @dev    - Throws if the permit is expired
     * @dev    - Throws if the nonce has already been used
     * @dev    - Throws if the permit is not signed by the owner
     * @dev    - Throws if the requested amount exceeds the permitted amount
     * @dev    - Throws if the provided token address does not implement ERC721 transferFrom function
     * @dev    - Returns `false` if the transfer fails
     *
     * @dev    <h4>Postconditions:</h4>
     * @dev    1. Transfers the token from the owner to the recipient
     * @dev    2. The nonce of the permit is marked as used
     * @dev    3. Performs any additional checks in the before and after hooks
     *
     * @param token         The address of the token
     * @param id            The ID of the token
     * @param nonce         The nonce of the permit
     * @param expiration    The expiration timestamp of the permit
     * @param owner         The owner of the token
     * @param to            The address to transfer the tokens to
     * @param signedPermit  The permit signature, signed by the owner
     *
     * @return isError      True if the transfer failed, false otherwise
     */
    function permitTransferFromERC721(
        address token,
        uint256 id,
        uint256 nonce,
        uint256 expiration,
        address owner,
        address to,
        bytes calldata signedPermit
    ) external returns (bool isError) {
        _requireNotPaused(PAUSABLE_PERMITTED_TRANSFER_FROM_ERC721);

        _checkPermitApproval(TOKEN_TYPE_ERC721, token, id, ONE, nonce, expiration, owner, ONE, signedPermit);
        isError = _transferFromERC721(owner, to, token, id);

        if (isError) {
            _restoreNonce(owner, nonce);
        }
    }


    /**
     * @notice Transfers an ERC721 token from the owner to the recipient using a permit signature
     * @notice This function includes additional data to verify on the signature, allowing
     * @notice protocols to extend the validation in one function call. NOTE: before calling this 
     * @notice function you MUST register the stub end of the additional data typestring using
     * @notice the `registerAdditionalDataHash` function.
     *
     * @dev    Be advised that the permitted amount for ERC721 is always inferred to be 1, so signed permitted amount
     * @dev    MUST always be set to 1.
     *
     * @dev    - Throws for any reason permitTransferFromERC721 would.
     * @dev    - Throws if the additional data does not match the signature
     * @dev    - Throws if the provided hash has not been registered as a valid additional data hash
     * @dev    - Throws if the provided hash does not match the provided additional data
     *
     * @dev    <h4>Postconditions:</h4>
     * @dev    1. Transfers the token from the owner to the recipient
     * @dev    2. Performs any additional checks in the before and after hooks
     * @dev    3. The nonce of the permit is marked as used
     * 
     * @param  token                    The address of the token
     * @param  id                       The ID of the token
     * @param  nonce                    The nonce of the permit
     * @param  expiration               The expiration timestamp of the permit
     * @param  owner                    The owner of the token
     * @param  to                       The address to transfer the tokens to
     * @param  additionalData           The additional data to verify on the signature
     * @param  advancedPermitHash       The hash of the additional data
     * @param  signedPermit             The permit signature, signed by the owner
     *
     * @return isError                  True if the transfer failed, false otherwise
     */
    function permitTransferFromWithAdditionalDataERC721(
        address token,
        uint256 id,
        uint256 nonce,
        uint256 expiration,
        address owner,
        address to,
        bytes32 additionalData,
        bytes32 advancedPermitHash,
        bytes calldata signedPermit
   ) external onlyRegisteredTransferAdvancedTypeHash(advancedPermitHash) returns (bool isError) {
        _requireNotPaused(PAUSABLE_PERMITTED_TRANSFER_FROM_ERC721);

        _checkPermitApprovalWithAdditionalDataERC721(
            token,
            id,
            ONE,
            nonce,
            expiration,
            owner,
            ONE,
            signedPermit,
            additionalData,
            advancedPermitHash
        );
        isError = _transferFromERC721(owner, to, token, id);

        if (isError) {
            _restoreNonce(owner, nonce);
        }
    }

    /**
     * @notice Transfer an ERC1155 token from the owner to the recipient using a permit signature
     *
     * @dev    - Throws if the permit is expired
     * @dev    - Throws if the nonce has already been used
     * @dev    - Throws if the permit is not signed by the owner
     * @dev    - Throws if the requested amount exceeds the permitted amount
     * @dev    - Throws if the provided token address does not implement ERC1155 safeTransferFrom function
     * @dev    - Returns `false` if the transfer fails
     *
     * @dev    <h4>Postconditions:</h4>
     * @dev    1. Transfers the token (in the requested amount) from the owner to the recipient
     * @dev    2. The nonce of the permit is marked as used
     * @dev    3. Performs any additional checks in the before and after hooks
     *
     * @param token           The address of the token
     * @param id              The ID of the token
     * @param nonce           The nonce of the permit
     * @param permitAmount    The amount of tokens permitted by the owner
     * @param expiration      The expiration timestamp of the permit
     * @param owner           The owner of the token
     * @param to              The address to transfer the tokens to
     * @param transferAmount  The amount of tokens to transfer
     * @param signedPermit    The permit signature, signed by the owner
     *
     * @return isError        True if the transfer failed, false otherwise
     */
    function permitTransferFromERC1155(
        address token,
        uint256 id,
        uint256 nonce,
        uint256 permitAmount,
        uint256 expiration,
        address owner,
        address to,
        uint256 transferAmount,
        bytes calldata signedPermit
    ) external returns (bool isError) {
        _requireNotPaused(PAUSABLE_PERMITTED_TRANSFER_FROM_ERC1155);

        _checkPermitApproval(TOKEN_TYPE_ERC1155, token, id, permitAmount, nonce, expiration, owner, transferAmount, signedPermit);
        isError = _transferFromERC1155(token, owner, to, id, transferAmount);

        if (isError) {
            _restoreNonce(owner, nonce);
        }
    }

    /**
     * @notice Transfers a token from the owner to the recipient using a permit signature
     * @notice This function includes additional data to verify on the signature, allowing
     * @notice protocols to extend the validation in one function call. NOTE: before calling this 
     * @notice function you MUST register the stub end of the additional data typestring using
     * @notice the `registerAdditionalDataHash` function.
     *
     * @dev    - Throws for any reason permitTransferFrom would.
     * @dev    - Throws if the additional data does not match the signature
     * @dev    - Throws if the provided hash has not been registered as a valid additional data hash
     * @dev    - Throws if the provided hash does not match the provided additional data
     * @dev    - Throws if the provided hash has not been registered as a valid additional data hash
     * @dev    - Returns `false` if the transfer fails
     *
     * @dev    <h4>Postconditions:</h4>
     * @dev    1. Transfers the token (in the requested amount) from the owner to the recipient
     * @dev    2. Performs any additional checks in the before and after hooks
     * @dev    3. The nonce of the permit is marked as used
     *
     * @param  token                    The address of the token
     * @param  id                       The ID of the token
     * @param  nonce                    The nonce of the permit
     * @param  permitAmount             The amount of tokens permitted by the owner
     * @param  expiration               The expiration timestamp of the permit
     * @param  owner                    The owner of the token
     * @param  to                       The address to transfer the tokens to
     * @param  transferAmount           The amount of tokens to transfer
     * @param  additionalData           The additional data to verify on the signature
     * @param  advancedPermitHash       The hash of the additional data
     * @param  signedPermit             The permit signature, signed by the owner
     *
     * @return isError                  True if the transfer failed, false otherwise
     */
    function permitTransferFromWithAdditionalDataERC1155(
        address token,
        uint256 id,
        uint256 nonce,
        uint256 permitAmount,
        uint256 expiration,
        address owner,
        address to,
        uint256 transferAmount,
        bytes32 additionalData,
        bytes32 advancedPermitHash,
        bytes calldata signedPermit
    ) external onlyRegisteredTransferAdvancedTypeHash(advancedPermitHash) returns (bool isError) {
        _requireNotPaused(PAUSABLE_PERMITTED_TRANSFER_FROM_ERC1155);

        _checkPermitApprovalWithAdditionalDataERC1155(
            token,
            id,
            permitAmount,
            nonce,
            expiration,
            owner,
            transferAmount,
            signedPermit,
            additionalData,
            advancedPermitHash
        );
        
        // copy id to top of stack to avoid stack too deep
        uint256 tmpId = id;
        isError = _transferFromERC1155(token, owner, to, tmpId, transferAmount);

        if (isError) {
            _restoreNonce(owner, nonce);
        }
    }

    /**
     * @notice Transfer an ERC20 token from the owner to the recipient using a permit signature.
     *
     * @dev    Be advised that the token ID for ERC20 is always inferred to be 0, so signed token ID
     * @dev    MUST always be set to 0.
     *
     * @dev    - Throws if the permit is expired
     * @dev    - Throws if the nonce has already been used
     * @dev    - Throws if the permit is not signed by the owner
     * @dev    - Throws if the requested amount exceeds the permitted amount
     * @dev    - Throws if the provided token address does not implement ERC20 transferFrom function
     * @dev    - Returns `false` if the transfer fails
     *
     * @dev    <h4>Postconditions:</h4>
     * @dev    1. Transfers the token in the requested amount from the owner to the recipient
     * @dev    2. The nonce of the permit is marked as used
     * @dev    3. Performs any additional checks in the before and after hooks
     *
     * @param token         The address of the token
     * @param nonce         The nonce of the permit
     * @param permitAmount  The amount of tokens permitted by the owner
     * @param expiration    The expiration timestamp of the permit
     * @param owner         The owner of the token
     * @param to            The address to transfer the tokens to
     * @param signedPermit  The permit signature, signed by the owner
     *
     * @return isError      True if the transfer failed, false otherwise
     */
    function permitTransferFromERC20(
        address token,
        uint256 nonce,
        uint256 permitAmount,
        uint256 expiration,
        address owner,
        address to,
        uint256 transferAmount,
        bytes calldata signedPermit
    ) external returns (bool isError) {
        _requireNotPaused(PAUSABLE_PERMITTED_TRANSFER_FROM_ERC20);

        _checkPermitApproval(TOKEN_TYPE_ERC20, token, ZERO, permitAmount, nonce, expiration, owner, transferAmount, signedPermit);
        isError = _transferFromERC20(token, owner, to, ZERO, transferAmount);

        if (isError) {
            _restoreNonce(owner, nonce);
        }
    }

    /**
     * @notice Transfers an ERC20 token from the owner to the recipient using a permit signature
     * @notice This function includes additional data to verify on the signature, allowing
     * @notice protocols to extend the validation in one function call. NOTE: before calling this 
     * @notice function you MUST register the stub end of the additional data typestring using
     * @notice the `registerAdditionalDataHash` function.
     *
     * @dev    Be advised that the token ID for ERC20 is always inferred to be 0, so signed token ID
     * @dev    MUST always be set to 0.
     *
     * @dev    - Throws for any reason permitTransferFromERC20 would.
     * @dev    - Throws if the additional data does not match the signature
     * @dev    - Throws if the provided hash has not been registered as a valid additional data hash
     * @dev    - Throws if the provided hash does not match the provided additional data
     * @dev    - Returns `false` if the transfer fails
     *
     * @dev    <h4>Postconditions:</h4>
     * @dev    1. Transfers the token (in the requested amount) from the owner to the recipient
     * @dev    2. Performs any additional checks in the before and after hooks
     * @dev    3. The nonce of the permit is marked as used
     *
     * @param  token                    The address of the token
     * @param  nonce                    The nonce of the permit
     * @param  permitAmount             The amount of tokens permitted by the owner
     * @param  expiration               The expiration timestamp of the permit
     * @param  owner                    The owner of the token
     * @param  to                       The address to transfer the tokens to
     * @param  transferAmount           The amount of tokens to transfer
     * @param  additionalData           The additional data to verify on the signature
     * @param  advancedPermitHash       The hash of the additional data
     * @param  signedPermit             The permit signature, signed by the owner
     *
     * @return isError                  True if the transfer failed, false otherwise
     */
    function permitTransferFromWithAdditionalDataERC20(
        address token,
        uint256 nonce,
        uint256 permitAmount,
        uint256 expiration,
        address owner,
        address to,
        uint256 transferAmount,
        bytes32 additionalData,
        bytes32 advancedPermitHash,
        bytes calldata signedPermit
    ) external onlyRegisteredTransferAdvancedTypeHash(advancedPermitHash) returns (bool isError) {
        _requireNotPaused(PAUSABLE_PERMITTED_TRANSFER_FROM_ERC20);

        _checkPermitApprovalWithAdditionalDataERC20(
            token,
            ZERO,
            permitAmount,
            nonce,
            expiration,
            owner,
            transferAmount,
            signedPermit,
            additionalData,
            advancedPermitHash
        );
        isError = _transferFromERC20(token, owner, to, ZERO, transferAmount);

        if (isError) {
            _restoreNonce(owner, nonce);
        }
    }

    /**
     * @notice Returns true if the provided hash has been registered as a valid additional data hash for transfers.
     *
     * @param  hash The hash to check
     *
     * @return isRegistered true if the hash is valid, false otherwise
     */
    function isRegisteredTransferAdditionalDataHash(bytes32 hash) external view returns (bool isRegistered) {
        isRegistered = _registeredTransferHashes[hash];
    }

    /**
     * @notice Returns true if the provided hash has been registered as a valid additional data hash for orders.
     *
     * @param  hash The hash to check
     *
     * @return isRegistered true if the hash is valid, false otherwise
     */
    function isRegisteredOrderAdditionalDataHash(bytes32 hash) external view returns (bool isRegistered) {
        isRegistered = _registeredOrderHashes[hash];
    }

    /**
     * =================================================
     * =============== Order Transfers =================
     * =================================================
     */

    /**
     * @notice Transfers an ERC1155 token from the owner to the recipient using a permit signature
     * @notice Order transfers are used to transfer a specific amount of a token from a specific order
     * @notice and allow for multiple uses of the same permit up to the allocated amount. NOTE: before calling this 
     * @notice function you MUST register the stub end of the additional data typestring using
     * @notice the `registerAdditionalDataHash` function.
     *
     * @dev    - Throws if the permit is expired
     * @dev    - Throws if the permit is not signed by the owner
     * @dev    - Throws if the requested amount + amount already filled exceeds the permitted amount
     * @dev    - Throws if the requested amount is less than the minimum fill amount
     * @dev    - Throws if the provided token address does not implement ERC1155 safeTransferFrom function
     * @dev    - Throws if the provided advanced permit hash has not been registered
     * @dev    - Returns `false` if the transfer fails
     *
     * @dev    <h4>Postconditions:</h4>
     * @dev    1. Transfers the token (in the requested amount) from the owner to the recipient
     * @dev    2. Updates the amount filled for the order ID
     * @dev    3. If completely filled, marks the order as filled
     * 
     * @param  signedPermit         The permit signature, signed by the owner
     * @param  orderFillAmounts     The amount of tokens to transfer
     * @param  token                The address of the token
     * @param  id                   The ID of the token
     * @param  owner                The owner of the token
     * @param  to                   The address to transfer the tokens to
     * @param  salt                 The salt of the permit
     * @param  expiration           The expiration timestamp of the permit
     * @param  orderId              The order ID
     * @param  advancedPermitHash   The hash of the additional data
     *
     * @return quantityFilled       The amount of tokens filled
     * @return isError              True if the transfer failed, false otherwise
     */
    function fillPermittedOrderERC1155(
        bytes calldata signedPermit,
        OrderFillAmounts calldata orderFillAmounts,
        address token,
        uint256 id,
        address owner,
        address to,
        uint256 salt,
        uint48 expiration,
        bytes32 orderId,
        bytes32 advancedPermitHash
    ) external onlyRegisteredOrderAdvancedTypeHash(advancedPermitHash) returns (uint256 quantityFilled, bool isError) {
        _requireNotPaused(PAUSABLE_ORDER_TRANSFER_FROM_ERC1155);

        PackedApproval storage orderStatus = _checkOrderTransferERC1155(
            signedPermit,
            orderFillAmounts,
            token,
            id,
            owner,
            salt,
            expiration,
            orderId,
            advancedPermitHash
        );

        (
            quantityFilled,
            isError
        ) = _orderTransfer(
                orderStatus,
                orderFillAmounts,
                token, 
                id, 
                owner, 
                to, 
                orderId,
                _transferFromERC1155
        );

        if (isError) {
            _restoreFillableItems(orderStatus, owner, orderId, quantityFilled, true);
        }
    }

    /**
     * @notice Transfers an ERC20 token from the owner to the recipient using a permit signature
     * @notice Order transfers are used to transfer a specific amount of a token from a specific order
     * @notice and allow for multiple uses of the same permit up to the allocated amount. NOTE: before calling this
     * @notice function you MUST register the stub end of the additional data typestring using
     * @notice the `registerAdditionalDataHash` function.
     *
     * @dev    - Throws if the permit is expired
     * @dev    - Throws if the permit is not signed by the owner
     * @dev    - Throws if the requested amount + amount already filled exceeds the permitted amount
     * @dev    - Throws if the requested amount is less than the minimum fill amount
     * @dev    - Throws if the provided token address does not implement ERC20 transferFrom function
     * @dev    - Throws if the provided advanced permit hash has not been registered
     * @dev    - Returns `false` if the transfer fails
     *
     * @dev    <h4>Postconditions:</h4>
     * @dev    1. Transfers the token (in the requested amount) from the owner to the recipient
     * @dev    2. Updates the amount filled for the order ID
     * @dev    3. If completely filled, marks the order as filled
     *
     * @param  signedPermit         The permit signature, signed by the owner
     * @param  orderFillAmounts     The amount of tokens to transfer
     * @param  token                The address of the token
     * @param  owner                The owner of the token
     * @param  to                   The address to transfer the tokens to
     * @param  salt                 The salt of the permit
     * @param  expiration           The expiration timestamp of the permit
     * @param  orderId              The order ID
     * @param  advancedPermitHash   The hash of the additional data
     *
     * @return quantityFilled       The amount of tokens filled
     * @return isError              True if the transfer failed, false otherwise
     */
    function fillPermittedOrderERC20(
        bytes calldata signedPermit,
        OrderFillAmounts calldata orderFillAmounts,
        address token,
        address owner,
        address to,
        uint256 salt,
        uint48 expiration,
        bytes32 orderId,
        bytes32 advancedPermitHash
    ) external onlyRegisteredOrderAdvancedTypeHash(advancedPermitHash) returns (uint256 quantityFilled, bool isError) {
        _requireNotPaused(PAUSABLE_ORDER_TRANSFER_FROM_ERC20);

        PackedApproval storage orderStatus = _checkOrderTransferERC20(
            signedPermit,
            orderFillAmounts,
            token,
            ZERO,
            owner,
            salt,
            expiration,
            orderId,
            advancedPermitHash
        );

        (
            quantityFilled,
            isError
        ) = _orderTransfer(
                orderStatus,
                orderFillAmounts,
                token, 
                ZERO, 
                owner, 
                to, 
                orderId,
                _transferFromERC20
        );

        if (isError) {
            _restoreFillableItems(orderStatus, owner, orderId, quantityFilled, true);
        }
    }

    /**
     * @notice Closes an outstanding order to prevent further execution of transfers.
     *
     * @dev    - Throws if the order is not in the open state
     *
     * @dev    <h4>Postconditions:</h4>
     * @dev    1. Marks the order as cancelled
     * @dev    2. Sets the order amount to 0
     * @dev    3. Sets the order expiration to 0
     * @dev    4. Emits a OrderClosed event
     *
     * @param  owner      The owner of the token
     * @param  operator   The operator allowed to transfer the token
     * @param  tokenType  The type of token the order is for - must be 20, 721 or 1155.
     * @param  token      The address of the token contract
     * @param  id         The token ID
     * @param  orderId    The order ID
     */
    function closePermittedOrder(
        address owner,
        address operator,
        uint256 tokenType,
        address token,
        uint256 id,
        bytes32 orderId
    ) external {
        if(!(msg.sender == owner || msg.sender == operator)) {
            revert PermitC__CallerMustBeOwnerOrOperator();
        }
        _requireValidTokenType(tokenType);
        PackedApproval storage orderStatus = _getPackedApprovalPtr(_orderApprovals, owner, tokenType, token, id, orderId, operator);
    
        if (orderStatus.state == ORDER_STATE_OPEN) {
            orderStatus.state = ORDER_STATE_CANCELLED;
            orderStatus.amount = 0;
            orderStatus.expiration = 0;
            emit OrderClosed(orderId, owner, operator, true);
        } else {
            revert PermitC__OrderIsEitherCancelledOrFilled();
        }
    }

    /**
     * @notice Returns the amount of allowance an operator has for a specific token and id
     * @notice If the expiration on the allowance has expired, returns 0
     *
     * @dev    Overload of the on chain allowance function for approvals with a specified order ID
     * 
     * @param  owner    The owner of the token
     * @param  operator The operator of the token
     * @param  token    The address of the token contract
     * @param  id       The token ID
     *
     * @return allowedAmount The amount of allowance the operator has
     */
    function allowance(
        address owner, 
        address operator, 
        uint256 tokenType,
        address token, 
        uint256 id, 
        bytes32 orderId
    ) external view returns (uint256 allowedAmount, uint256 expiration) {
        return _allowance(_orderApprovals, owner, operator, tokenType, token, id, orderId);
    }

    /**
     * =================================================
     * ================ Nonce Management ===============
     * =================================================
     */

    /**
     * @notice Invalidates the provided nonce
     *
     * @dev    - Throws if the provided nonce has already been used
     *
     * @dev    <h4>Postconditions:</h4>
     * @dev    1. Sets the provided nonce as used for the sender
     *
     * @param  nonce Nonce to invalidate
     */
    function invalidateUnorderedNonce(uint256 nonce) external {
        _checkAndInvalidateNonce(msg.sender, nonce);
    }

    /**
     * @notice Returns if the provided nonce has been used
     *
     * @param  owner The owner of the token
     * @param  nonce The nonce to check
     *
     * @return isValid true if the nonce is valid, false otherwise
     */
    function isValidUnorderedNonce(address owner, uint256 nonce) external view returns (bool isValid) {
        isValid = ((_unorderedNonces[owner][uint248(nonce >> 8)] >> uint8(nonce)) & ONE) == ZERO;
    }

    /**
     * @notice Revokes all outstanding approvals for the sender
     *
     * @dev    <h4>Postconditions:</h4>
     * @dev    1. Increments the master nonce for the sender
     * @dev    2. All outstanding approvals for the sender are invalidated
     */
    function lockdown() external {
        unchecked {
            _masterNonces[msg.sender]++;
        }

        emit Lockdown(msg.sender);
    }

    /**
     * @notice Returns the master nonce for the provided owner address
     *
     * @param  owner The owner address
     *
     * @return The master nonce
     */
    function masterNonce(address owner) external view returns (uint256) {
        return _masterNonces[owner];
    }

    /**
     * =================================================
     * ============== Transfer Functions ===============
     * =================================================
     */

    /**
     * @notice Transfer an ERC721 token from the owner to the recipient using on chain approvals
     *
     * @dev    Public transfer function overload for approval transfers
     * @dev    - Throws if the provided token address does not implement ERC721 transferFrom function
     * @dev    - Throws if the requested amount exceeds the approved amount
     * @dev    - Throws if the approval is expired
     * @dev    - Returns `false` if the transfer fails
     *
     * @dev    <h4>Postconditions:</h4>
     * @dev    1. Transfers the token (in the requested amount) from the owner to the recipient
     * @dev    2. Decrements the approval amount by the requested amount
     * @dev    3. Performs any additional checks in the before and after hooks
     *
     * @param  owner    The owner of the token
     * @param  to       The recipient of the token
     * @param  token    The address of the token
     * @param  id       The id of the token
     *
     * @return isError  True if the transfer failed, false otherwise
     */
    function transferFromERC721(
        address owner,
        address to,
        address token,
        uint256 id
    ) external returns (bool isError) {
        _requireNotPaused(PAUSABLE_APPROVAL_TRANSFER_FROM_ERC721);

        PackedApproval storage approval = _checkAndUpdateApproval(owner, TOKEN_TYPE_ERC721, token, id, ONE, true);
        isError = _transferFromERC721(owner, to, token, id);

        if (isError) {
            _restoreFillableItems(approval, owner, ZERO_BYTES32, ONE, false);
        }
    }

    /**
     * @notice Transfer an ERC1155 token from the owner to the recipient using on chain approvals
     *
     * @dev    Public transfer function overload for approval transfers
     * @dev    - Throws if the provided token address does not implement ERC1155 safeTransferFrom function
     * @dev    - Throws if the requested amount exceeds the approved amount
     * @dev    - Throws if the approval is expired
     * @dev    - Returns `false` if the transfer fails
     *
     * @dev    <h4>Postconditions:</h4>
     * @dev    1. Transfers the token (in the requested amount) from the owner to the recipient
     * @dev    2. Decrements the approval amount by the requested amount
     * @dev    3. Performs any additional checks in the before and after hooks
     *
     * @param  owner     The owner of the token
     * @param  to       The recipient of the token
     * @param  amount   The amount of the token to transfer
     * @param  token    The address of the token
     * @param  id       The id of the token
     *
     * @return isError  True if the transfer failed, false otherwise
     */
    function transferFromERC1155(
        address owner,
        address to,
        address token,
        uint256 id,
        uint256 amount
    ) external returns (bool isError) {
        _requireNotPaused(PAUSABLE_APPROVAL_TRANSFER_FROM_ERC1155);

        PackedApproval storage approval = _checkAndUpdateApproval(owner, TOKEN_TYPE_ERC1155, token, id, amount, false);
        isError = _transferFromERC1155(token, owner, to, id, amount);

        if (isError) {
            _restoreFillableItems(approval, owner, ZERO_BYTES32, amount, false);
        }
    }

    /**
     * @notice Transfer an ERC20 token from the owner to the recipient using on chain approvals
     *
     * @dev    Public transfer function overload for approval transfers
     * @dev    - Throws if the provided token address does not implement ERC20 transferFrom function
     * @dev    - Throws if the requested amount exceeds the approved amount
     * @dev    - Throws if the approval is expired
     * @dev    - Returns `false` if the transfer fails
     *
     * @dev    <h4>Postconditions:</h4>
     * @dev    1. Transfers the token (in the requested amount) from the owner to the recipient
     * @dev    2. Decrements the approval amount by the requested amount
     * @dev    3. Performs any additional checks in the before and after hooks
     *
     * @param  owner     The owner of the token
     * @param  to       The recipient of the token
     * @param  amount   The amount of the token to transfer
     * @param  token    The address of the token
     *
     * @return isError  True if the transfer failed, false otherwise
     */
    function transferFromERC20(
        address owner,
        address to,
        address token,
        uint256 amount
    ) external returns (bool isError) {
        _requireNotPaused(PAUSABLE_APPROVAL_TRANSFER_FROM_ERC20);

        PackedApproval storage approval = _checkAndUpdateApproval(owner, TOKEN_TYPE_ERC20, token, ZERO, amount, false);
        isError = _transferFromERC20(token, owner, to, ZERO, amount);

        if (isError) {
            _restoreFillableItems(approval, owner, ZERO_BYTES32, amount, false);
        }
    }

    /**
     * @notice  Performs a transfer of an ERC721 token.
     * 
     * @dev     Will **NOT** attempt transfer if `_beforeTransferFrom` hook returns false.
     * @dev     Will **NOT** revert if the transfer is unsucessful.
     * @dev     Invokers **MUST** check `isError` return value to determine success.
     * 
     * @param owner  The owner of the token being transferred
     * @param to     The address to transfer the token to
     * @param token  The token address of the token being transferred
     * @param id     The token id being transferred
     * 
     * @return isError True if the token was not transferred, false if token was transferred
     */
    function _transferFromERC721(
        address owner,
        address to,
        address token,
        uint256 id
    ) private returns (bool isError) {
        isError = _beforeTransferFrom(TOKEN_TYPE_ERC721, token, owner, to, id, ONE);

        if (!isError) {
            try IERC721(token).transferFrom(owner, to, id) { } 
            catch {
                isError = true;
            }
        }
    }

    /**
     * @notice  Performs a transfer of an ERC1155 token.
     * 
     * @dev     Will **NOT** attempt transfer if `_beforeTransferFrom` hook returns false.
     * @dev     Will **NOT** revert if the transfer is unsucessful.
     * @dev     Invokers **MUST** check `isError` return value to determine success.
     * 
     * @param token  The token address of the token being transferred
     * @param owner  The owner of the token being transferred
     * @param to     The address to transfer the token to
     * @param id     The token id being transferred
     * @param amount The quantity of token id to transfer
     * 
     * @return isError True if the token was not transferred, false if token was transferred
     */
    function _transferFromERC1155(
        address token,
        address owner,
        address to,
        uint256 id,
        uint256 amount
    ) private returns (bool isError) {
        isError = _beforeTransferFrom(TOKEN_TYPE_ERC1155, token, owner, to, id, amount);

        if (!isError) {
            try IERC1155(token).safeTransferFrom(owner, to, id, amount, "") { } catch {
                isError = true;
            }
        }
    }

    /**
     * @notice  Performs a transfer of an ERC20 token.
     * 
     * @dev     Will **NOT** attempt transfer if `_beforeTransferFrom` hook returns false.
     * @dev     Will **NOT** revert if the transfer is unsucessful.
     * @dev     Invokers **MUST** check `isError` return value to determine success.
     * 
     * @param token  The token address of the token being transferred
     * @param owner  The owner of the token being transferred
     * @param to     The address to transfer the token to
     * @param amount The quantity of token id to transfer
     * 
     * @return isError True if the token was not transferred, false if token was transferred
     */
    function _transferFromERC20(
        address token,
        address owner,
        address to,
        uint256 /*id*/,
        uint256 amount
      ) private returns (bool isError) {
        isError = _beforeTransferFrom(TOKEN_TYPE_ERC20, token, owner, to, ZERO, amount);

        if (!isError) {
            (bool success, bytes memory data) = token.call(abi.encodeWithSelector(IERC20.transferFrom.selector, owner, to, amount));
            if (!success) {
                isError = true;
            } else if (data.length > 0) {
                isError = !abi.decode(data, (bool));
            }
        }
    }

    /**
     * =================================================
     * ============ Signature Verification =============
     * =================================================
     */

    /**
     * @notice Returns the domain separator used in the permit signature
     *
     * @return domainSeparator The domain separator
     */
    function domainSeparatorV4() external view returns (bytes32 domainSeparator) {
        domainSeparator = _domainSeparatorV4();
    }

    /**
     * @notice  Verifies a permit signature based on the bytes length of the signature provided.
     * 
     * @dev     Throws when -
     * @dev         The bytes signature length is 64 or 65 bytes AND
     * @dev         The ECDSA recovered signer is not the owner AND
     * @dev         The owner's code length is zero OR the owner does not return a valid EIP-1271 response
     * @dev 
     * @dev         OR
     * @dev
     * @dev         The bytes signature length is not 64 or 65 bytes AND
     * @dev         The owner's code length is zero OR the owner does not return a valid EIP-1271 response
     */
    function _verifyPermitSignature(bytes32 digest, bytes calldata signature, address owner) private view {
        if (signature.length == 65) {
            bytes32 r;
            bytes32 s;
            uint8 v;
            // Divide the signature in r, s and v variables
            /// @solidity memory-safe-assembly
            assembly {
                r := calldataload(signature.offset)
                s := calldataload(add(signature.offset, 32))
                v := byte(0, calldataload(add(signature.offset, 64)))
            }
            (bool isError, address signer) = _ecdsaRecover(digest, v, r, s);
            if (owner != signer || isError) {
                _verifyEIP1271Signature(owner, digest, signature);
            }
        } else if (signature.length == 64) {
            bytes32 r;
            bytes32 vs;
            // Divide the signature in r and vs variables
            /// @solidity memory-safe-assembly
            assembly {
                r := calldataload(signature.offset)
                vs := calldataload(add(signature.offset, 32))
            }
            (bool isError, address signer) = _ecdsaRecover(digest, r, vs);
            if (owner != signer || isError) {
                _verifyEIP1271Signature(owner, digest, signature);
            }
        } else {
            _verifyEIP1271Signature(owner, digest, signature);
        }
    }

    /**
     * @notice Verifies an EIP-1271 signature.
     * 
     * @dev    Throws when `signer` code length is zero OR the EIP-1271 call does not
     * @dev    return the correct magic value.
     * 
     * @param signer     The signer address to verify a signature with
     * @param hash       The hash digest to verify with the signer
     * @param signature  The signature to verify
     */
    function _verifyEIP1271Signature(address signer, bytes32 hash, bytes calldata signature) private view {
        if(signer.code.length == 0) {
            revert PermitC__SignatureTransferInvalidSignature();
        }

        if (!_safeIsValidSignature(signer, hash, signature)) {
            revert PermitC__SignatureTransferInvalidSignature();
        }
    }

    /**
     * @notice  Overload of the `_ecdsaRecover` function to unpack the `v` and `s` values
     * 
     * @param digest    The hash digest that was signed
     * @param r         The `r` value of the signature
     * @param vs        The packed `v` and `s` values of the signature
     * 
     * @return isError  True if the ECDSA function is provided invalid inputs
     * @return signer   The recovered address from ECDSA
     */
    function _ecdsaRecover(bytes32 digest, bytes32 r, bytes32 vs) private pure returns (bool isError, address signer) {
        unchecked {
            bytes32 s = vs & UPPER_BIT_MASK;
            uint8 v = uint8(uint256(vs >> 255)) + 27;

            (isError, signer) = _ecdsaRecover(digest, v, r, s);
        }
    }

    /**
     * @notice  Recovers the signer address using ECDSA
     * 
     * @dev     Does **NOT** revert if invalid input values are provided or `signer` is recovered as address(0)
     * @dev     Returns an `isError` value in those conditions that is handled upstream
     * 
     * @param digest    The hash digest that was signed
     * @param v         The `v` value of the signature
     * @param r         The `r` value of the signature
     * @param s         The `s` value of the signature
     * 
     * @return isError  True if the ECDSA function is provided invalid inputs
     * @return signer   The recovered address from ECDSA
     */
    function _ecdsaRecover(bytes32 digest, uint8 v, bytes32 r, bytes32 s) private pure returns (bool isError, address signer) {
        if (uint256(s) > 0x7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF5D576E7357A4501DDFE92F46681B20A0) {
            // Invalid signature `s` value - return isError = true and signer = address(0) to check EIP-1271
            return (true, address(0));
        }

        signer = ecrecover(digest, v, r, s);
        isError = (signer == address(0));
    }

    /**
     * @notice A gas efficient, and fallback-safe way to call the isValidSignature function for EIP-1271.
     *
     * @param signer     The EIP-1271 signer to call to check for a valid signature.
     * @param hash       The hash digest to verify with the EIP-1271 signer.
     * @param signature  The supplied signature to verify.
     * 
     * @return isValid   True if the EIP-1271 signer returns the EIP-1271 magic value.
     */
    function _safeIsValidSignature(
        address signer,
        bytes32 hash,
        bytes calldata signature
    ) private view returns(bool isValid) {
        assembly {
            function _callIsValidSignature(_signer, _hash, _signatureOffset, _signatureLength) -> _isValid {
                let ptr := mload(0x40)
                // store isValidSignature(bytes32,bytes) selector
                mstore(ptr, hex"1626ba7e")
                // store bytes32 hash value in abi encoded location
                mstore(add(ptr, 0x04), _hash)
                // store abi encoded location of the bytes signature data
                mstore(add(ptr, 0x24), 0x40)
                // store bytes signature length
                mstore(add(ptr, 0x44), _signatureLength)
                // copy calldata bytes signature to memory
                calldatacopy(add(ptr, 0x64), _signatureOffset, _signatureLength)
                // calculate data length based on abi encoded data with rounded up signature length
                let dataLength := add(0x64, and(add(_signatureLength, 0x1F), not(0x1F)))
                // update free memory pointer
                mstore(0x40, add(ptr, dataLength))

                // static call _signer with abi encoded data
                // skip return data check if call failed or return data size is not at least 32 bytes
                if and(iszero(lt(returndatasize(), 0x20)), staticcall(gas(), _signer, ptr, dataLength, 0x00, 0x20)) {
                    // check if return data is equal to isValidSignature magic value
                    _isValid := eq(mload(0x00), hex"1626ba7e")
                    leave
                }
            }
            isValid := _callIsValidSignature(signer, hash, signature.offset, signature.length)
        }
    }

    /**
     * =================================================
     * ===================== Hooks =====================
     * =================================================
     */

    /**
     * @dev    This function is empty by default. Override it to add additional logic after the approval transfer.
     * @dev    The function returns a boolean value instead of reverting to indicate if there is an error for more granular control in inheriting protocols.
     */
    function _beforeTransferFrom(uint256 tokenType, address token, address owner, address to, uint256 id, uint256 amount) internal virtual returns (bool isError) {}

    /**
     * =================================================
     * ==================== Internal ===================
     * =================================================
     */

    /**
     * @notice Checks if an advanced permit typehash has been registered with PermitC
     * 
     * @dev    Throws when the typehash has not been registered
     * 
     * @param advancedPermitHash  The permit typehash to check
     */
    function _requireTransferAdvancedPermitHashIsRegistered(bytes32 advancedPermitHash) private view {
        if (!_registeredTransferHashes[advancedPermitHash]) {
            revert PermitC__SignatureTransferPermitHashNotRegistered();
        }
    }

    /**
     * @notice Checks if an advanced permit typehash has been registered with PermitC
     * 
     * @dev    Throws when the typehash has not been registered
     * 
     * @param advancedPermitHash  The permit typehash to check
     */
    function _requireOrderAdvancedPermitHashIsRegistered(bytes32 advancedPermitHash) private view {
        if (!_registeredOrderHashes[advancedPermitHash]) {
            revert PermitC__SignatureTransferPermitHashNotRegistered();
        }
    }

    /**
     * @notice  Invalidates an account nonce if it has not been previously used
     * 
     * @dev     Throws when the nonce was previously used
     * 
     * @param account  The account to invalidate the nonce of
     * @param nonce    The nonce to invalidate
     */
    function _checkAndInvalidateNonce(address account, uint256 nonce) private {
        unchecked {
            if (uint256(_unorderedNonces[account][uint248(nonce >> 8)] ^= (ONE << uint8(nonce))) & 
                (ONE << uint8(nonce)) == ZERO) {
                revert PermitC__NonceAlreadyUsedOrRevoked();
            }
        }
    }

    /**
     * @notice Checks an approval to ensure it is sufficient for the `amount` to send
     * 
     * @dev    Throws when the approval is expired
     * @dev    Throws when the approved amount is insufficient
     * 
     * @param owner            The owner of the token
     * @param tokenType        The type of token
     * @param token            The address of the token
     * @param id               The id of the token
     * @param amount           The amount to deduct from the approval
     * @param zeroOutApproval  True if the approval should be set to zero
     * 
     * @return approval  Storage pointer for the approval data
     */
    function _checkAndUpdateApproval(
        address owner,
        uint256 tokenType,
        address token,
        uint256 id,
        uint256 amount,
        bool zeroOutApproval
    ) private returns (PackedApproval storage approval) {
        approval = _getPackedApprovalPtr(_transferApprovals, owner, tokenType, token, id, ZERO_BYTES32, msg.sender);
        
        if (approval.expiration < block.timestamp) {
            revert PermitC__ApprovalTransferPermitExpiredOrUnset();
        }
        if (approval.amount < amount) {
            revert PermitC__ApprovalTransferExceededPermittedAmount();
        }

        if(zeroOutApproval) {
            approval.amount = 0;
        } else if (approval.amount < type(uint200).max) {
            unchecked {
                approval.amount -= uint200(amount);
            }
        }
    }

    /**
     * @notice  Gets the storage pointer for an approval
     * 
     * @param _approvals  The mapping to retrieve the approval from
     * @param account     The account the approval is from
     * @param tokenType   The type of token the approval is for
     * @param token       The address of the token
     * @param id          The id of the token
     * @param orderId     The order id for the approval
     * @param operator    The operator for the approval
     * 
     * @return approval  Storage pointer for the approval data
     */
    function _getPackedApprovalPtr(
        mapping(bytes32 => mapping(address => PackedApproval)) storage _approvals,
        address account, 
        uint256 tokenType,
        address token, 
        uint256 id,
        bytes32 orderId,
        address operator
    ) private view returns (PackedApproval storage approval) {
        approval = _approvals[_getPackedApprovalKey(account, tokenType, token, id, orderId)][operator];
    }

    /**
     * @notice  Gets the storage key for the mapping for a specific approval
     * 
     * @param owner      The owner of the token
     * @param tokenType  The type of token
     * @param token      The address of the token
     * @param id         The id of the token
     * @param orderId    The order id of the approval
     * 
     * @return key  The key value to use to access the approval in the mapping
     */
    function _getPackedApprovalKey(address owner, uint256 tokenType, address token, uint256 id, bytes32 orderId) private view returns (bytes32 key) {
        key = keccak256(abi.encode(owner, tokenType, token, id, orderId, _masterNonces[owner]));
    }

    /**
     * @notice Checks the permit approval for a single use permit without additional data
     * 
     * @dev    Throws when the `nonce` has already been consumed
     * @dev    Throws when the permit amount is less than the transfer amount
     * @dev    Throws when the permit is expired
     * @dev    Throws when the signature is invalid
     * 
     * @param tokenType       The type of token
     * @param token           The address of the token
     * @param id              The id of the token
     * @param permitAmount    The amount authorized by the owner signature
     * @param nonce           The nonce of the permit
     * @param expiration      The time the permit expires
     * @param owner           The owner of the token
     * @param transferAmount  The amount of tokens requested to transfer
     * @param signedPermit    The signature for the permit
     */
    function _checkPermitApproval(
        uint256 tokenType,
        address token,
        uint256 id,
        uint256 permitAmount,
        uint256 nonce,
        uint256 expiration,
        address owner,
        uint256 transferAmount,
        bytes calldata signedPermit
    ) private {
        bytes32 digest = _hashTypedDataV4(
            PermitHash.hashSingleUsePermit(
                tokenType,
                token,
                id,
                permitAmount,
                nonce,
                expiration,
                _masterNonces[owner]
            )
        );

        _checkPermitData(
            nonce,
            expiration,
            transferAmount,
            permitAmount,
            owner,
            digest,
            signedPermit
        );
    }

    /**
     * @notice  Overload of `_checkPermitApprovalWithAdditionalData` to supply TOKEN_TYPE_ERC1155
     * 
     * @dev     Prevents stack too deep in `permitTransferFromWithAdditionalDataERC1155`
     * @dev     Throws when the `nonce` has already been consumed
     * @dev     Throws when the permit amount is less than the transfer amount
     * @dev     Throws when the permit is expired
     * @dev     Throws when the signature is invalid
     * 
     * @param token               The address of the token
     * @param id                  The id of the token
     * @param permitAmount        The amount authorized by the owner signature
     * @param nonce               The nonce of the permit
     * @param expiration          The time the permit expires
     * @param owner               The owner of the token
     * @param transferAmount      The amount of tokens requested to transfer
     * @param signedPermit        The signature for the permit
     * @param additionalData      The additional data to validate with the permit signature
     * @param advancedPermitHash  The typehash of the permit to use for validating the signature
     */
    function _checkPermitApprovalWithAdditionalDataERC1155(
        address token,
        uint256 id,
        uint256 permitAmount,
        uint256 nonce,
        uint256 expiration,
        address owner,
        uint256 transferAmount,
        bytes calldata signedPermit,
        bytes32 additionalData,
        bytes32 advancedPermitHash
    ) private {
        _checkPermitApprovalWithAdditionalData(
            TOKEN_TYPE_ERC1155,
            token,
            id,
            permitAmount,
            nonce,
            expiration,
            owner,
            transferAmount,
            signedPermit,
            additionalData,
            advancedPermitHash
        );
    }

    /**
     * @notice  Overload of `_checkPermitApprovalWithAdditionalData` to supply TOKEN_TYPE_ERC20
     * 
     * @dev     Prevents stack too deep in `permitTransferFromWithAdditionalDataERC220`
     * @dev     Throws when the `nonce` has already been consumed
     * @dev     Throws when the permit amount is less than the transfer amount
     * @dev     Throws when the permit is expired
     * @dev     Throws when the signature is invalid
     * 
     * @param token               The address of the token
     * @param id                  The id of the token
     * @param permitAmount        The amount authorized by the owner signature
     * @param nonce               The nonce of the permit
     * @param expiration          The time the permit expires
     * @param owner               The owner of the token
     * @param transferAmount      The amount of tokens requested to transfer
     * @param signedPermit        The signature for the permit
     * @param additionalData      The additional data to validate with the permit signature
     * @param advancedPermitHash  The typehash of the permit to use for validating the signature
     */
    function _checkPermitApprovalWithAdditionalDataERC20(
        address token,
        uint256 id,
        uint256 permitAmount,
        uint256 nonce,
        uint256 expiration,
        address owner,
        uint256 transferAmount,
        bytes calldata signedPermit,
        bytes32 additionalData,
        bytes32 advancedPermitHash
    ) private {
        _checkPermitApprovalWithAdditionalData(
            TOKEN_TYPE_ERC20,
            token,
            id,
            permitAmount,
            nonce,
            expiration,
            owner,
            transferAmount,
            signedPermit,
            additionalData,
            advancedPermitHash
        );
    }

    /**
     * @notice  Overload of `_checkPermitApprovalWithAdditionalData` to supply TOKEN_TYPE_ERC721
     * 
     * @dev     Prevents stack too deep in `permitTransferFromWithAdditionalDataERC721`
     * @dev     Throws when the `nonce` has already been consumed
     * @dev     Throws when the permit amount is less than the transfer amount
     * @dev     Throws when the permit is expired
     * @dev     Throws when the signature is invalid
     * 
     * @param token               The address of the token
     * @param id                  The id of the token
     * @param permitAmount        The amount authorized by the owner signature
     * @param nonce               The nonce of the permit
     * @param expiration          The time the permit expires
     * @param owner               The owner of the token
     * @param transferAmount      The amount of tokens requested to transfer
     * @param signedPermit        The signature for the permit
     * @param additionalData      The additional data to validate with the permit signature
     * @param advancedPermitHash  The typehash of the permit to use for validating the signature
     */
    function _checkPermitApprovalWithAdditionalDataERC721(
        address token,
        uint256 id,
        uint256 permitAmount,
        uint256 nonce,
        uint256 expiration,
        address owner,
        uint256 transferAmount,
        bytes calldata signedPermit,
        bytes32 additionalData,
        bytes32 advancedPermitHash
    ) private {
        _checkPermitApprovalWithAdditionalData(
            TOKEN_TYPE_ERC721,
            token,
            id,
            permitAmount,
            nonce,
            expiration,
            owner,
            transferAmount,
            signedPermit,
            additionalData,
            advancedPermitHash
        );
    }

    /**
     * @notice Checks the permit approval for a single use permit with additional data
     * 
     * @dev    Throws when the `nonce` has already been consumed
     * @dev    Throws when the permit amount is less than the transfer amount
     * @dev    Throws when the permit is expired
     * @dev    Throws when the signature is invalid
     * 
     * @param tokenType           The type of token
     * @param token               The address of the token
     * @param id                  The id of the token
     * @param permitAmount        The amount authorized by the owner signature
     * @param nonce               The nonce of the permit
     * @param expiration          The time the permit expires
     * @param owner               The owner of the token
     * @param transferAmount      The amount of tokens requested to transfer
     * @param signedPermit        The signature for the permit
     * @param additionalData      The additional data to validate with the permit signature
     * @param advancedPermitHash  The typehash of the permit to use for validating the signature
     */
    function _checkPermitApprovalWithAdditionalData(
        uint256 tokenType,
        address token,
        uint256 id,
        uint256 permitAmount,
        uint256 nonce,
        uint256 expiration,
        address owner,
        uint256 transferAmount,
        bytes calldata signedPermit,
        bytes32 additionalData,
        bytes32 advancedPermitHash
    ) private {
        bytes32 digest = _getAdvancedTypedDataV4PermitHash(
            tokenType,
            token, 
            id, 
            permitAmount, 
            owner,
            nonce, 
            expiration, 
            additionalData, 
            advancedPermitHash
        );        

        _checkPermitData(
            nonce,
            expiration,
            transferAmount,
            permitAmount,
            owner,
            digest,
            signedPermit
        );
    }

    /**
     * @notice  Checks that a single use permit has not expired, was authorized for the amount
     * @notice  being transferred, has a valid nonce and has a valid signature.
     * 
     * @dev    Throws when the `nonce` has already been consumed
     * @dev    Throws when the permit amount is less than the transfer amount
     * @dev    Throws when the permit is expired
     * @dev    Throws when the signature is invalid
     * 
     * @param nonce           The nonce of the permit
     * @param expiration      The time the permit expires
     * @param transferAmount  The amount of tokens requested to transfer
     * @param permitAmount    The amount authorized by the owner signature
     * @param owner           The owner of the token
     * @param digest          The digest that was signed by the owner
     * @param signedPermit    The signature for the permit
     */
    function _checkPermitData(
        uint256 nonce,
        uint256 expiration, 
        uint256 transferAmount, 
        uint256 permitAmount, 
        address owner, 
        bytes32 digest,
        bytes calldata signedPermit
    ) private {
        if (block.timestamp > expiration) {
            revert PermitC__SignatureTransferExceededPermitExpired();
        }

        if (transferAmount > permitAmount) {
            revert PermitC__SignatureTransferExceededPermittedAmount();
        }

        _checkAndInvalidateNonce(owner, nonce);
        _verifyPermitSignature(digest, signedPermit, owner);
    }

    /**
     * @notice  Stores an approval for future use by `operator` to move tokens on behalf of `owner`
     * 
     * @param tokenType           The type of token
     * @param token               The address of the token
     * @param id                  The id of the token
     * @param amount              The amount authorized by the owner
     * @param expiration          The time the permit expires
     * @param owner               The owner of the token
     * @param operator            The account allowed to transfer the tokens
     */
    function _storeApproval(
        uint256 tokenType,
        address token,
        uint256 id,
        uint200 amount,
        uint48 expiration,
        address owner,
        address operator
    ) private {
        PackedApproval storage approval = _getPackedApprovalPtr(_transferApprovals, owner, tokenType, token, id, ZERO_BYTES32, operator);
        
        approval.expiration = expiration;
        approval.amount = amount;

        emit Approval(owner, token, operator, id, amount, expiration);
    }

    /**
     * @notice  Overload of `_checkOrderTransfer` to supply TOKEN_TYPE_ERC1155
     * 
     * @dev     Prevents stack too deep in `fillPermittedOrderERC1155`
     * @dev     Throws when the order start amount is greater than type(uint200).max
     * @dev     Throws when the order status is not open
     * @dev     Throws when the signature is invalid
     * @dev     Throws when the permit is expired
     * 
     * @param signedPermit        The signature for the permit
     * @param orderFillAmounts    A struct containing the order start, requested fill and minimum fill amounts
     * @param token               The address of the token
     * @param id                  The id of the token
     * @param owner               The owner of the token
     * @param salt                The salt value for the permit
     * @param expiration          The time the permit expires
     * @param orderId             The order id for the permit
     * @param advancedPermitHash  The typehash of the permit to use for validating the signature
     * 
     * @return orderStatus  Storage pointer for the approval data
     */
    function _checkOrderTransferERC1155(
        bytes calldata signedPermit,
        OrderFillAmounts calldata orderFillAmounts,
        address token,
        uint256 id,
        address owner,
        uint256 salt,
        uint48 expiration,
        bytes32 orderId,
        bytes32 advancedPermitHash
    ) private returns (PackedApproval storage orderStatus) {
        orderStatus = _checkOrderTransfer(
            signedPermit,
            orderFillAmounts,
            TOKEN_TYPE_ERC1155,
            token,
            id,
            owner,
            salt,
            expiration,
            orderId,
            advancedPermitHash
        );
    }

    /**
     * @notice  Overload of `_checkOrderTransfer` to supply TOKEN_TYPE_ERC20
     * 
     * @dev     Prevents stack too deep in `fillPermittedOrderERC20`
     * @dev     Throws when the order start amount is greater than type(uint200).max
     * @dev     Throws when the order status is not open
     * @dev     Throws when the signature is invalid
     * @dev     Throws when the permit is expired
     * 
     * @param signedPermit        The signature for the permit
     * @param orderFillAmounts    A struct containing the order start, requested fill and minimum fill amounts
     * @param token               The address of the token
     * @param id                  The id of the token
     * @param owner               The owner of the token
     * @param salt                The salt value for the permit
     * @param expiration          The time the permit expires
     * @param orderId             The order id for the permit
     * @param advancedPermitHash  The typehash of the permit to use for validating the signature
     * 
     * @return orderStatus  Storage pointer for the approval data
     */
    function _checkOrderTransferERC20(
        bytes calldata signedPermit,
        OrderFillAmounts calldata orderFillAmounts,
        address token,
        uint256 id,
        address owner,
        uint256 salt,
        uint48 expiration,
        bytes32 orderId,
        bytes32 advancedPermitHash
    ) private returns (PackedApproval storage orderStatus) {
        orderStatus = _checkOrderTransfer(
            signedPermit,
            orderFillAmounts,
            TOKEN_TYPE_ERC20,
            token,
            id,
            owner,
            salt,
            expiration,
            orderId,
            advancedPermitHash
        );
    }

    /**
     * @notice  Validates an order transfer to check order start amount, status, signature if not previously
     * @notice  opened, and expiration.
     * 
     * @dev     Throws when the order start amount is greater than type(uint200).max
     * @dev     Throws when the order status is not open
     * @dev     Throws when the signature is invalid
     * @dev     Throws when the permit is expired
     * 
     * @param signedPermit        The signature for the permit
     * @param orderFillAmounts    A struct containing the order start, requested fill and minimum fill amounts
     * @param tokenType           The type of token
     * @param token               The address of the token
     * @param id                  The id of the token
     * @param owner               The owner of the token
     * @param salt                The salt value for the permit
     * @param expiration          The time the permit expires
     * @param orderId             The order id for the permit
     * @param advancedPermitHash  The typehash of the permit to use for validating the signature
     * 
     * @return orderStatus  Storage pointer for the approval data
     */
    function _checkOrderTransfer(
        bytes calldata signedPermit,
        OrderFillAmounts calldata orderFillAmounts,
        uint256 tokenType,
        address token,
        uint256 id,
        address owner,
        uint256 salt,
        uint48 expiration,
        bytes32 orderId,
        bytes32 advancedPermitHash
    ) private returns (PackedApproval storage orderStatus) {
        if (orderFillAmounts.orderStartAmount > type(uint200).max) {
            revert PermitC__AmountExceedsStorageMaximum();
        }

        orderStatus = _getPackedApprovalPtr(_orderApprovals, owner, tokenType, token, id, orderId, msg.sender);

        if (orderStatus.state == ORDER_STATE_OPEN) {
            if (orderStatus.amount == 0) {
                _verifyPermitSignature(
                    _getAdvancedTypedDataV4PermitHash(
                        tokenType,
                        token, 
                        id, 
                        orderFillAmounts.orderStartAmount,
                        owner,
                        salt, 
                        expiration, 
                        orderId, 
                        advancedPermitHash
                    ), 
                    signedPermit, 
                    owner
                );

                orderStatus.amount = uint200(orderFillAmounts.orderStartAmount);
                orderStatus.expiration = expiration;   
                emit OrderOpened(orderId, owner, msg.sender, orderFillAmounts.orderStartAmount);
            }

            if (block.timestamp > orderStatus.expiration) {
                revert PermitC__SignatureTransferExceededPermitExpired();
            }
        } else {
            revert PermitC__OrderIsEitherCancelledOrFilled();
        }
    }

    /**
     * @notice  Checks the order fill amounts against approval data and transfers tokens, updates
     * @notice  approval if the fill results in the order being closed.
     * 
     * @dev     Throws when the amount to fill is less than the minimum fill amount
     * 
     * @param orderStatus         Storage pointer for the approval data
     * @param orderFillAmounts    A struct containing the order start, requested fill and minimum fill amounts
     * @param token               The address of the token
     * @param id                  The id of the token
     * @param owner               The owner of the token
     * @param to                  The address to send the tokens to
     * @param orderId             The order id for the permit
     * @param _transferFrom       Function pointer of the transfer function to send tokens with
     * 
     * @return quantityFilled     The number of tokens filled in the order
     * @return isError            True if there was an error transferring tokens, false otherwise
     */
    function _orderTransfer(
        PackedApproval storage orderStatus,
        OrderFillAmounts calldata orderFillAmounts,
        address token,
        uint256 id,
        address owner,
        address to,
        bytes32 orderId,
        function (address, address, address, uint256, uint256) internal returns (bool) _transferFrom
    ) private returns (uint256 quantityFilled, bool isError) {
        quantityFilled = orderFillAmounts.requestedFillAmount;
        
        if (quantityFilled > orderStatus.amount) {
            quantityFilled = orderStatus.amount;
        }

        if (quantityFilled < orderFillAmounts.minimumFillAmount) {
            revert PermitC__UnableToFillMinimumRequestedQuantity();
        }

        unchecked {
            orderStatus.amount -= uint200(quantityFilled);
            emit OrderFilled(orderId, owner, msg.sender, quantityFilled);
        }

        if (orderStatus.amount == 0) {
            orderStatus.state = ORDER_STATE_FILLED;
            emit OrderClosed(orderId, owner, msg.sender, false);
        }

        isError = _transferFrom(token, owner, to, id, quantityFilled);
    }

    /**
     * @notice  Restores an account's nonce when a transfer was not successful
     * 
     * @dev     Throws when the nonce was not already consumed
     * 
     * @param account  The account to restore the nonce of
     * @param nonce    The nonce to restore
     */
    function _restoreNonce(address account, uint256 nonce) private {
        unchecked {
            if (uint256(_unorderedNonces[account][uint248(nonce >> 8)] ^= (ONE << uint8(nonce))) & 
                (ONE << uint8(nonce)) != ZERO) {
                revert PermitC__NonceNotUsedOrRevoked();
            }
        }
    }

    /**
     * @notice  Restores an approval amount when a transfer was not successful
     * 
     * @param approval        Storage pointer for the approval data
     * @param owner           The owner of the tokens
     * @param orderId         The order id to restore approval amount on
     * @param unfilledAmount  The amount that was not filled on the order
     * @param isOrderPermit   True if the fill restoration is for an permit order
     */
    function _restoreFillableItems(
        PackedApproval storage approval,
        address owner,
        bytes32 orderId,
        uint256 unfilledAmount,
        bool isOrderPermit
    ) private {
        if (unfilledAmount > 0) {
            if (isOrderPermit) {
                // Order permits always deduct amount and must be restored
                unchecked {
                    approval.amount += uint200(unfilledAmount);
                }

                approval.state = ORDER_STATE_OPEN;
                emit OrderRestored(orderId, owner, unfilledAmount);
            } else if (approval.amount < type(uint200).max) {
                // Stored approvals only deduct amount 
                unchecked {
                    approval.amount += uint200(unfilledAmount);
                }
            }
        }
    }

    function _requireValidTokenType(uint256 tokenType) private pure {
        if(!(
            tokenType == TOKEN_TYPE_ERC721 || 
            tokenType == TOKEN_TYPE_ERC1155 || 
            tokenType == TOKEN_TYPE_ERC20
            )
        ) {
            revert PermitC__InvalidTokenType();
        }
    }

    /**
     * @notice  Generates an EIP-712 digest for a permit
     * 
     * @param tokenType           The type of token
     * @param token               The address of the token
     * @param id                  The id of the token
     * @param amount              The amount authorized by the owner signature
     * @param owner               The owner of the token
     * @param nonce               The nonce for the permit
     * @param expiration          The time the permit expires
     * @param additionalData      The additional data to validate with the permit signature
     * @param advancedPermitHash  The typehash of the permit to use for validating the signature
     * 
     * @return digest  The EIP-712 digest of the permit data
     */
    function _getAdvancedTypedDataV4PermitHash(
        uint256 tokenType,
        address token,
        uint256 id,
        uint256 amount,
        address owner,
        uint256 nonce,
        uint256 expiration,
        bytes32 additionalData,
        bytes32 advancedPermitHash
    ) private view returns (bytes32 digest) {
        // cache masterNonce on stack to avoid stack too deep
        uint256 masterNonce_ = _masterNonces[owner];
        digest = 
            _hashTypedDataV4(
                PermitHash.hashSingleUsePermitWithAdditionalData(
                    tokenType,
                    token, 
                    id, 
                    amount, 
                    nonce, 
                    expiration, 
                    additionalData, 
                    advancedPermitHash, 
                    masterNonce_
                )
            );
    }

    /**
     * @notice  Returns the current allowed amount and expiration for a stored permit
     * 
     * @dev     Returns zero allowed if the permit has expired
     * 
     * @param _approvals  The mapping to retrieve the approval from
     * @param owner       The account the approval is from
     * @param operator    The operator for the approval
     * @param tokenType   The type of token the approval is for
     * @param token       The address of the token
     * @param id          The id of the token
     * @param orderId     The order id for the approval
     * 
     * @return allowedAmount  The amount authorized by the approval, zero if the permit has expired
     * @return expiration     The expiration of the approval
     */
    function _allowance(
        mapping(bytes32 => mapping(address => PackedApproval)) storage _approvals,
        address owner, 
        address operator, 
        uint256 tokenType, 
        address token, 
        uint256 id, 
        bytes32 orderId
    ) private view returns (uint256 allowedAmount, uint256 expiration) {
        PackedApproval storage allowed = _getPackedApprovalPtr(_approvals, owner, tokenType, token, id, orderId, operator);
        allowedAmount = allowed.expiration < block.timestamp ? 0 : allowed.amount;
        expiration = allowed.expiration;
    }

    /**
     * @notice  Allows the owner of the PermitC contract to access pausable admin functions
     * 
     * @dev     May be overriden by an inheriting contract to provide alternative permission structure
     */
    function _requireCallerHasPausePermissions() internal view virtual override {
        _checkOwner();
    }
}
