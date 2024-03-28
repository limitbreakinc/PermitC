// SPDX-License-Identifier: MIT
pragma solidity ^0.8.4;

import "./Errors.sol";
import {IERC20} from "@openzeppelin/contracts/interfaces/IERC20.sol";
import {IERC721} from "@openzeppelin/contracts/interfaces/IERC721.sol";
import {IERC1155} from "@openzeppelin/contracts/interfaces/IERC1155.sol";
import {IERC1271} from "@openzeppelin/contracts/interfaces/IERC1271.sol";
import {EIP712} from "./openzeppelin-optimized/EIP712.sol";
import {
    ZERO_BYTES32,
    ZERO, 
    ONE, 
    ORDER_STATE_OPEN,
    ORDER_STATE_FILLED,
    ORDER_STATE_CANCELLED,
    SINGLE_USE_PERMIT_ADVANCED_TYPEHASH_STUB,
    UPPER_BIT_MASK
} from "./Constants.sol";
import {PackedApproval, OrderFillAmounts} from "./DataTypes.sol";
import {PermitHash} from './libraries/PermitHash.sol';
import {IPermitC} from './interfaces/IPermitC.sol';

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

contract PermitC is EIP712, IPermitC {

    /**
     * @notice Map of approval details for the provided bytes32 hash to allow for multiple accessors
     *
     * @dev    By ID: keccak256(abi.encode(owner, operator, id, masterNonce)) => token => (amount, expiration)
     * @dev    By Operator: keccak256(abi.encode(owner, operator, masterNonce)) => token => (amount, expiration)
     */
    mapping(bytes32 => mapping(address => PackedApproval)) private _approvals;

    /**
     * @notice Map of registered additional data hashes
     *
     * @dev    This is used to prevent someone from providing an invalid EIP712 envelope label
     * @dev    and tricking a user into signing a different message than they expect.
     */
    mapping(bytes32 => bool) private _registeredHashes;

    /// @dev Map of an address to a bitmap (slot => status)
    mapping(address => mapping(uint256 => uint256)) private _unorderedNonces;

    /**
     * @notice Master nonce used to invalidate all outstanding approvals for an owner
     *
     * @dev    owner => masterNonce
     * @dev    This is incremented when the owner calls lockdown()
     */
    mapping(address => uint256) private _masterNonces;

    constructor(string memory name, string memory version) EIP712(name, version) {}

    /**
     * =================================================
     * ================= Modifiers =====================
     * =================================================
     */

    modifier onlyRegisteredAdvancedTypeHash(bytes32 advancedPermitHash) {
        _requireAdvancedPermitHashIsRegistered(advancedPermitHash);
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
     * @param  token      The address of the token contract
     * @param  id         The token ID
     * @param  operator   The address of the operator
     * @param  amount     The amount of tokens to approve
     * @param  expiration The expiration timestamp of the approval
     */
    function approve(
        address token, 
        uint256 id, 
        address operator, 
        uint200 amount, 
        uint48 expiration) external {
        _storeApproval(token, id, amount, expiration, msg.sender, operator);
    }

    /**
     * @notice Use a signed permit to increase the allowance for a provided operator
     * @notice This function is compatible with ERC20, ERC721 and ERC1155
     * @notice To give unlimited approval for ERC20 and ERC1155, set amount to type(uint200).max
     * @notice When approving an ERC721, you MUST set amount to `1`
     * @notice When approving an ERC20, you MUST set id to `0`
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
        _checkAndInvalidateNonce(owner, nonce);
        _verifyPermitSignature(
            _hashTypedDataV4(
                PermitHash.hashOnChainApproval(
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

        _storeApproval(token, id, amount, approvalExpiration, owner, operator);
    }

    /**
     * @notice Returns the amount of allowance an operator has and it's expiration for a specific token and id
     * @notice If the expiration on the allowance has expired, returns 0
     * @notice To retrieve allowance for ERC20, set id to `0`
     * 
     * @param  owner    The owner of the token
     * @param  operator The operator of the token
     * @param  token    The address of the token contract
     * @param  id       The token ID
     *
     * @return allowedAmount The amount of allowance the operator has
     * @return expiration    The expiration timestamp of the allowance
     */
    function allowance(
        address owner, 
        address operator, 
        address token, 
        uint256 id
    ) external view returns (uint256 allowedAmount, uint256 expiration) {
        return _allowance(owner, operator, token, id, ZERO_BYTES32);
    }

    /**
     * =================================================
     * ================ Signed Transfers ===============
     * =================================================
     */

    /**
     * @notice Registers the combination of a provided string with the `SINGLE_USE_PERMIT_ADVANCED_TYPEHASH_STUB` string
     * @notice to create a valid additional data hash
     *
     * @dev    This function prevents malicious actors from changing the label of the EIP712 hash
     * @dev    to a value that would fool an external user into signing a different message.
     *
     * @dev    <h4>Postconditions:</h4>
     * @dev    1. The provided string is combined with the `SINGLE_USE_PERMIT_ADVANCED_TYPEHASH_STUB` string
     * @dev    2. The combined string is hashed using keccak256
     * @dev    3. The resulting hash is added to the `_registeredHashes` mapping
     *
     * @param  additionalDataTypeString The string to register as a valid additional data hash
     */
     function registerAdditionalDataHash(string calldata additionalDataTypeString) external {
        bytes32 advancedPermitHash = 
            keccak256(bytes(string.concat(SINGLE_USE_PERMIT_ADVANCED_TYPEHASH_STUB, additionalDataTypeString)));
        _registeredHashes[advancedPermitHash] = true;
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
        _checkPermitApproval(token, id, ONE, nonce, expiration, owner, ONE, signedPermit);
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
   ) 
    external
    onlyRegisteredAdvancedTypeHash(advancedPermitHash)
    returns (bool isError) {
        _checkPermitApprovalWithAdditionalData(
            token, id, ONE, nonce, expiration, owner, ONE, signedPermit, additionalData, 
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
        _checkPermitApproval(token, id, permitAmount, nonce, expiration, owner, transferAmount, signedPermit);
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
    ) 
    external
    onlyRegisteredAdvancedTypeHash(advancedPermitHash)
    returns (bool isError) {
        _checkPermitApprovalWithAdditionalData(
            token, id, permitAmount, nonce, expiration, owner, transferAmount, signedPermit, additionalData, 
            advancedPermitHash
        );
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
        _checkPermitApproval(token, ZERO, permitAmount, nonce, expiration, owner, transferAmount, signedPermit);
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
    ) external onlyRegisteredAdvancedTypeHash(advancedPermitHash) returns (bool isError) {
        _checkPermitApprovalWithAdditionalData(
            token, ZERO, permitAmount, nonce, expiration, owner, transferAmount, signedPermit, additionalData, 
            advancedPermitHash
        );
        isError = _transferFromERC20(token, owner, to, ZERO, transferAmount);

        if (isError) {
            _restoreNonce(owner, nonce);
        }
    }

    /**
     * @notice Returns true if the provided hash has been registered as a valid additional data hash
     *
     * @param  hash The hash to check
     *
     * @return isRegistered true if the hash is valid, false otherwise
     */
     function isRegisteredAdditionalDataHash(bytes32 hash) external view returns (bool isRegistered) {
        isRegistered = _registeredHashes[hash];
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
     * @param  orderFillAmounts  The amount of tokens to transfer
     * @param  token                The address of the token
     * @param  id                   The ID of the token
     * @param  owner                The owner of the token
     * @param  to                   The address to transfer the tokens to
     * @param  nonce                The nonce of the permit
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
        uint256 nonce,
        uint48 expiration,
        bytes32 orderId,
        bytes32 advancedPermitHash
    ) 
    external
    onlyRegisteredAdvancedTypeHash(advancedPermitHash)
    returns (uint256 quantityFilled, bool isError) {
        bytes32 digest = 
            _getAdvancedTypedDataV4PermitHash(
                token, 
                id, 
                orderFillAmounts.orderStartAmount,
                owner,
                nonce, 
                expiration, 
                orderId, 
                advancedPermitHash);

        (
            quantityFilled,
            isError
        ) = _orderTransfer(
            signedPermit,
            orderFillAmounts,
            token, 
            id, 
            owner, 
            to, 
            expiration,
            orderId,
            digest,
            _transferFromERC1155
        );

        if (isError) {
            _restoreFillableItems(owner, orderId, token, id, quantityFilled);
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
     * @param  nonce                The nonce of the permit
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
        uint256 nonce,
        uint48 expiration,
        bytes32 orderId,
        bytes32 advancedPermitHash
    ) 
    external
    onlyRegisteredAdvancedTypeHash(advancedPermitHash)
    returns (uint256 quantityFilled, bool isError) {
        bytes32 digest = 
            _getAdvancedTypedDataV4PermitHash(
                token, 
                ZERO, 
                orderFillAmounts.orderStartAmount,
                owner,
                nonce, 
                expiration, 
                orderId, 
                advancedPermitHash);

        (
            quantityFilled,
            isError
        ) = _orderTransfer(
            signedPermit,
            orderFillAmounts,
            token, 
            ZERO, 
            owner, 
            to, 
            expiration,
            orderId,
            digest,
            _transferFromERC20
        );

        if (isError) {
            _restoreFillableItems(owner, orderId, token, ZERO, quantityFilled);
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
     * @param  token      The address of the token contract
     * @param  id         The token ID
     * @param  orderId    The order ID
     */
    function closePermittedOrder(
        address owner,
        address token,
        uint256 id,
        bytes32 orderId
    ) external {
        PackedApproval storage orderStatus = _getPackedApprovalPtr(owner, token, id, orderId, msg.sender);
    
        if (orderStatus.state == ORDER_STATE_OPEN) {
            orderStatus.state = ORDER_STATE_CANCELLED;
            orderStatus.amount = 0;
            orderStatus.expiration = 0;
            emit OrderClosed(orderId, owner, msg.sender, true);
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
        address token, 
        uint256 id, 
        bytes32 orderId
    ) external view returns (uint256 allowedAmount, uint256 expiration) {
        return _allowance(owner, operator, token, id, orderId);
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
     * @dev    - Throws if the master nonce is type(uint256).max
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
    function masterNonce(address owner) public view returns (uint256) {
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
        _checkAndUpdateApproval(owner, token, id, ONE, true);
        isError = _transferFromERC721(owner, to, token, id);

        if (isError) {
            _restoreFillableItems(owner, ZERO_BYTES32, token, id, ONE);
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
        _checkAndUpdateApproval(owner, token, id, amount, false);
        isError = _transferFromERC1155(token, owner, to, id, amount);

        if (isError) {
            _restoreFillableItems(owner, ZERO_BYTES32, token, id, amount);
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
        _checkAndUpdateApproval(owner, token, ZERO, amount, false);
        isError = _transferFromERC20(token, owner, to, ZERO, amount);

        if (isError) {
            _restoreFillableItems(owner, ZERO_BYTES32, token, ZERO, amount);
        }
    }

    function _transferFromERC721(
        address owner,
        address to,
        address token,
        uint256 id
    ) internal returns (bool isError) {
        isError = _beforeTransferFrom(token, owner, to, id, ONE);

        if (!isError) {
            try IERC721(token).transferFrom(owner, to, id) {
                isError = _afterTransferFrom(token, owner, to, id, ONE);
            } 
            catch {
                isError = true;
            }
        }
    }

    function _transferFromERC1155(
        address token,
        address owner,
        address to,
        uint256 id,
        uint256 amount
    ) internal returns (bool isError) {
        isError =_beforeTransferFrom(token, owner, to, id, amount);

        if (!isError) {
            try IERC1155(token).safeTransferFrom(owner, to, id, amount, "") {
                isError = _afterTransferFrom(token, owner, to, id, amount);
            } catch {
                isError = true;
            }
        }
    }

    function _transferFromERC20(
        address token,
        address owner,
        address to,
        uint256 /*id*/,
        uint256 amount
      ) internal returns (bool isError) {
        isError = _beforeTransferFrom(token, owner, to, ZERO, amount);

        if (!isError) {
            (bool success, bytes memory data) = token.call(abi.encodeWithSelector(IERC20.transferFrom.selector, owner, to, amount));
            if (!success) {
                isError = true;
            } else if (data.length > 0) {
                isError = abi.decode(data, (bool)) == false;
            }

            if (!isError) {
                isError = _afterTransferFrom(token, owner, to, ZERO, amount);
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
     * @return The domain separator
     */
     /**
     * @notice Returns the domain separator used in the permit signature
     *
     * @return domainSeparator The domain separator
     */
    function domainSeparatorV4() external view returns (bytes32 domainSeparator) {
        domainSeparator = _domainSeparatorV4();
    }

    function _verifyPermitSignature(bytes32 digest, bytes calldata signature, address owner) internal view {
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
            if (owner != _ecdsaRecover(digest, v, r, s)) {
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
            if (owner != _ecdsaRecover(digest, r, vs)) {
                _verifyEIP1271Signature(owner, digest, signature);
            }
        } else {
            _verifyEIP1271Signature(owner, digest, signature);
        }
    }

    function _verifyEIP1271Signature(address signer, bytes32 hash, bytes calldata signature) private view {
        if(signer.code.length == 0) {
            revert PermitC__SignatureTransferInvalidSignature();
        }

        bool isValidSignatureNow;

        try IERC1271(signer).isValidSignature(hash, signature) returns (
            bytes4 magicValue
        ) {
            isValidSignatureNow = magicValue == IERC1271.isValidSignature.selector;
        } catch {}

        if (!isValidSignatureNow) {
            revert PermitC__SignatureTransferInvalidSignature();
        }
    }

    function _ecdsaRecover(bytes32 digest, bytes32 r, bytes32 vs) private pure returns (address signer) {
        bytes32 s = vs & UPPER_BIT_MASK;
        uint8 v = uint8(uint256(vs >> 255)) + 27;

        signer = _ecdsaRecover(digest, v, r, s);
    }

    function _ecdsaRecover(bytes32 digest, uint8 v, bytes32 r, bytes32 s) private pure returns (address signer) {
        if (uint256(s) > 0x7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF5D576E7357A4501DDFE92F46681B20A0) {
            revert PermitC__SignatureTransferInvalidSignature();
        }

        signer = ecrecover(digest, v, r, s);
        if (signer == address(0)) {
            revert PermitC__SignatureTransferInvalidSignature();
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
    function _beforeTransferFrom(address token, address owner, address to, uint256 id, uint256 amount) internal virtual returns (bool isError) {}

    /**
     * @dev    This function is empty by default. Override it to add additional logic after the approval transfer.
     * @dev    The function returns a boolean value instead of reverting to indicate if there is an error for more granular control in inheriting protocols.
     */
    function _afterTransferFrom(address token, address owner, address to, uint256 id, uint256 amount) internal virtual returns (bool isError) {}

    /**
     * =================================================
     * ==================== Internal ===================
     * =================================================
     */

    function _requireAdvancedPermitHashIsRegistered(bytes32 advancedPermitHash) internal view {
        if (!_registeredHashes[advancedPermitHash]) {
            revert PermitC__SignatureTransferPermitHashNotRegistered();
        }
    }

    function _checkAndInvalidateNonce(address account, uint256 nonce) internal {
        unchecked {
            if (uint256(_unorderedNonces[account][uint248(nonce >> 8)] ^= (ONE << uint8(nonce))) & 
                (ONE << uint8(nonce)) == ZERO) {
                revert PermitC__NonceAlreadyUsedOrRevoked();
            }
        }
    }

    function _checkAndUpdateApproval(
        address owner,
        address token,
        uint256 id,
        uint256 amount,
        bool zeroOutApproval
    ) internal {
        PackedApproval storage approval = _getPackedApprovalPtr(owner, token, id, ZERO_BYTES32, msg.sender);
        
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

    function _getPackedApprovalPtr(
        address account, 
        address token, 
        uint256 id,
        bytes32 orderId,
        address operator
    ) internal view returns (PackedApproval storage) {
        return _approvals[_getPackedApprovalKey(account, token, id, orderId)][operator];
    }

    function _getPackedApprovalKey(address owner, address token, uint256 id, bytes32 orderId) internal view returns (bytes32) {
        return keccak256(abi.encode(owner, token, id, orderId, _masterNonces[owner]));
    }

    function _checkPermitApproval(
        address token,
        uint256 id,
        uint256 permitAmount,
        uint256 nonce,
        uint256 expiration,
        address owner,
        uint256 transferAmount,
        bytes calldata signedPermit
    ) internal {
        bytes32 digest = _hashTypedDataV4(
            PermitHash.hashSingleUsePermit(
                token, id, permitAmount, nonce, 
                expiration, _masterNonces[owner]
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

    function _checkPermitApprovalWithAdditionalData(
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
    ) internal {
        bytes32 digest = _getAdvancedTypedDataV4PermitHash(
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

    function _checkPermitData(
        uint256 nonce,
        uint256 expiration, 
        uint256 transferAmount, 
        uint256 permitAmount, 
        address owner, 
        bytes32 digest,
        bytes calldata signedPermit
    ) internal {
        if (block.timestamp > expiration) {
            revert PermitC__SignatureTransferExceededPermitExpired();
        }

        if (transferAmount > permitAmount) {
            revert PermitC__SignatureTransferExceededPermittedAmount();
        }

        _verifyPermitSignature(digest, signedPermit, owner);
        _checkAndInvalidateNonce(owner, nonce);
    }

    function _storeApproval(
        address token,
        uint256 id,
        uint200 amount,
        uint48 expiration,
        address owner,
        address operator
    ) private {
        PackedApproval storage allowed = _getPackedApprovalPtr(owner, token, id, ZERO_BYTES32, operator);
        allowed.expiration = expiration == 0 ? uint48(block.timestamp) : expiration;
        allowed.amount = amount;

        emit Approval({
            owner: owner,
            token: token,
            operator: operator,
            id: id,
            amount: amount,
            expiration: expiration
        });
    }

    function _orderTransfer(
        bytes calldata signedPermit,
        OrderFillAmounts calldata orderFillAmounts,
        address token,
        uint256 id,
        address owner,
        address to,
        uint48 expiration,
        bytes32 orderId,
        bytes32 digest,
        function (address, address, address, uint256, uint256) internal returns (bool) _transferFrom
    ) internal returns (uint256 quantityFilled, bool isError) {
        if (orderFillAmounts.orderStartAmount > type(uint200).max) {
            revert PermitC__AmountExceedsStorageMaximum();
        }

        quantityFilled = orderFillAmounts.requestedFillAmount;
        PackedApproval storage orderStatus = _getPackedApprovalPtr(owner, token, id, orderId, msg.sender);
        
        if (orderStatus.state == ORDER_STATE_OPEN) {
            if (orderStatus.amount == 0) {
                _verifyPermitSignature(digest, signedPermit, owner);

                orderStatus.amount = uint200(orderFillAmounts.orderStartAmount);
                orderStatus.expiration = expiration;   
                emit OrderOpened(orderId, owner, msg.sender, orderFillAmounts.orderStartAmount);
            }

            if (block.timestamp > orderStatus.expiration) {
                revert PermitC__SignatureTransferExceededPermitExpired();
            }

            if (quantityFilled > orderStatus.amount) {
                quantityFilled = orderStatus.amount;
            }

            if (quantityFilled < orderFillAmounts.minimumFillAmount) {
                revert PermitC__UnableToFillMinimumRequestedQuantity();
            }

            unchecked {
                isError = _transferFrom(token, owner, to, id, quantityFilled);
                orderStatus.amount -= uint200(quantityFilled);
                emit OrderFilled(orderId, owner, msg.sender, quantityFilled);
            }

            if (orderStatus.amount == 0) {
                orderStatus.state = ORDER_STATE_FILLED;
                emit OrderClosed(orderId, owner, msg.sender, false);
            }
        } else {
            revert PermitC__OrderIsEitherCancelledOrFilled();
        }
    }

    function _restoreNonce(address account, uint256 nonce) internal {

        unchecked {
            if (uint256(_unorderedNonces[account][uint248(nonce >> 8)] ^= (ONE << uint8(nonce))) & 
                (ONE << uint8(nonce)) != ZERO) {
                revert PermitC__NonceNotUsedOrRevoked();
            }
        }
    }

    function _restoreFillableItems(
        address owner,
        bytes32 orderId,
        address token,
        uint256 id,
        uint256 unfilledAmount
    ) private {
        if (unfilledAmount > 0) {
            PackedApproval storage orderStatus = _getPackedApprovalPtr(owner, token, id, orderId, msg.sender);

            unchecked {
                orderStatus.amount += uint200(unfilledAmount);
            }

            if (orderId != ZERO_BYTES32) {
                orderStatus.state = ORDER_STATE_OPEN;
                emit OrderRestored(orderId, owner, unfilledAmount);
            }
        }
    }

    function _getAdvancedTypedDataV4PermitHash(
        address token,
        uint256 id,
        uint256 amount,
        address owner,
        uint256 nonce,
        uint256 expiration,
        bytes32 additionalData,
        bytes32 advancedPermitHash
    ) internal view returns (bytes32) {
        uint256 masterNonce_ = _masterNonces[owner];
        return 
        _hashTypedDataV4(
            PermitHash.hashSingleUsePermitWithAdditionalData(
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

    function _allowance(
        address owner, 
        address operator, 
        address token, 
        uint256 id, 
        bytes32 orderId
    ) internal view returns (uint256 allowedAmount, uint256 expiration) {
        PackedApproval storage allowed = _getPackedApprovalPtr(owner, token, id, orderId, operator);
        allowedAmount = allowed.expiration < block.timestamp ? 0 : allowed.amount;
        expiration = allowed.expiration;
    }
}
