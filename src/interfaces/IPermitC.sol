// SPDX-License-Identifier: MIT
pragma solidity ^0.8.4;
import {OrderFillAmounts} from "../DataTypes.sol";

interface IPermitC {

    /**
     * =================================================
     * ==================== Events =====================
     * =================================================
     */

    /// @dev Emitted when an approval is stored
    event Approval(
        address indexed owner,
        address indexed token,
        address indexed operator,
        uint256 id,
        uint200 amount,
        uint48 expiration
    );

    /// @dev Emitted when a user increases their master nonce
    event Lockdown(address indexed owner);

    /// @dev Emitted when an order is opened
    event OrderOpened(
        bytes32 indexed orderId,
        address indexed owner,
        address indexed operator,
        uint256 fillableQuantity
    );

    /// @dev Emitted when an order has a fill
    event OrderFilled(
        bytes32 indexed orderId,
        address indexed owner,
        address indexed operator,
        uint256 amount
    );

    /// @dev Emitted when an order has been fully filled or cancelled
    event OrderClosed(
        bytes32 indexed orderId, 
        address indexed owner, 
        address indexed operator, 
        bool wasCancellation);

    /// @dev Emitted when an order has an amount restored due to a failed transfer
    event OrderRestored(
        bytes32 indexed orderId,
        address indexed owner,
        uint256 amountRestoredToOrder
    );

    /**
     * =================================================
     * ============== Approval Transfers ===============
     * =================================================
     */
    function approve(uint256 tokenType, address token, uint256 id, address operator, uint200 amount, uint48 expiration) external;

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
    ) external;

    function allowance(
        address owner, 
        address operator, 
        uint256 tokenType,
        address token, 
        uint256 id
    ) external view returns (uint256 amount, uint256 expiration);

    /**
     * =================================================
     * ================ Signed Transfers ===============
     * =================================================
     */
    function registerAdditionalDataHash(string memory additionalDataTypeString) external;

    function permitTransferFromERC721(
        address token,
        uint256 id,
        uint256 nonce,
        uint256 expiration,
        address owner,
        address to,
        bytes calldata signedPermit
    ) external returns (bool isError);

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
    ) external returns (bool isError);

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
    ) external returns (bool isError);

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
    ) external returns (bool isError);

    function permitTransferFromERC20(
        address token,
        uint256 nonce,
        uint256 permitAmount,
        uint256 expiration,
        address owner,
        address to,
        uint256 transferAmount,
        bytes calldata signedPermit
    ) external returns (bool isError);

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
    ) external returns (bool isError);

    function isRegisteredTransferAdditionalDataHash(bytes32 hash) external view returns (bool isRegistered);

    function isRegisteredOrderAdditionalDataHash(bytes32 hash) external view returns (bool isRegistered);

    /**
     * =================================================
     * =============== Order Transfers =================
     * =================================================
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
    ) external returns (uint256 quantityFilled, bool isError);

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
    ) external returns (uint256 quantityFilled, bool isError);

    function closePermittedOrder(
        address owner,
        address operator,
        uint256 tokenType,
        address token,
        uint256 id,
        bytes32 orderId
    ) external;

    function allowance(
        address owner, 
        address operator, 
        uint256 tokenType,
        address token, 
        uint256 id,
        bytes32 orderId
    ) external view returns (uint256 amount, uint256 expiration);


    /**
     * =================================================
     * ================ Nonce Management ===============
     * =================================================
     */
    function invalidateUnorderedNonce(uint256 nonce) external;

    function isValidUnorderedNonce(address owner, uint256 nonce) external view returns (bool isValid);

    function lockdown() external;

    function masterNonce(address owner) external view returns (uint256);

    /**
     * =================================================
     * ============== Transfer Functions ===============
     * =================================================
     */
    function transferFromERC721(
        address from,
        address to,
        address token,
        uint256 id
    ) external returns (bool isError);

    function transferFromERC1155(
        address from,
        address to,
        address token,
        uint256 id,
        uint256 amount
    ) external returns (bool isError);

    function transferFromERC20(
        address from,
        address to,
        address token,
        uint256 amount
    ) external returns (bool isError);

    /**
     * =================================================
     * ============ Signature Verification =============
     * =================================================
     */
    function domainSeparatorV4() external view returns (bytes32);
}
