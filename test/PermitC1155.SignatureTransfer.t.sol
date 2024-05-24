// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "forge-std/Test.sol";
import "../src/PermitC.sol";
import "../src/libraries/PermitHash.sol";
import "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";

import "./mocks/ERC1155Mock.sol";
import "./mocks/ERC1155Reverter.sol";

contract PermitC1155Test is Test {

    enum OrderProtocols {
        ERC721_FILL_OR_KILL,
        ERC1155_FILL_OR_KILL,
        ERC1155_FILL_PARTIAL
    }

    struct ApprovalTransferDetails {
        // Address to transfer the tokens to
        address to;
        // Amount of tokens to transfer
        uint256 requestedAmount;
    }
    
    struct PermitSignatureDetails {
        // Collection Address
        address token;
        // Token ID
        uint256 id;
        // An random value that can be used to invalidate the permit
        uint256 nonce;
        // Address permitted to transfer the tokens
        address operator;
        // Amount of tokens - For ERC721 this is always 1
        uint200 amount;
        // Expiration time of the permit
        uint48 expiration;
    }

    struct SaleApproval {
        OrderProtocols protocol;
        address seller;
        address marketplace;
        address paymentMethod;
        address tokenAddress;
        uint256 tokenId;
        uint256 amount;
        uint256 itemPrice;
        uint256 expiration;
        uint256 marketplaceFeeNumerator;
        uint256 maxRoyaltyFeeNumerator;
        uint256 nonce;
        uint256 masterNonce;
    }

    PermitC permitC;

    uint256 adminKey;
    uint256 aliceKey;
    uint256 bobKey;
    uint256 carolKey;

    address admin;
    address alice;
    address bob;
    address carol;


    string constant additionalDataTypeString = "SaleApproval approval)SaleApproval(uint8 protocol,address seller,address marketplace,address paymentMethod,address tokenAddress,uint256 tokenId,uint256 amount,uint256 itemPrice,uint256 expiration,uint256 marketplaceFeeNumerator,uint256 maxRoyaltyFeeNumerator,uint256 nonce,uint256 masterNonce)";

    SaleApproval approval;

    function setUp() public {
        (admin, adminKey) = makeAddrAndKey("admin");
        (alice, aliceKey) = makeAddrAndKey("alice");
        (bob, bobKey) = makeAddrAndKey("bob");
        (carol, carolKey) = makeAddrAndKey("carol");

        permitC = new PermitC("PermitC", "1", admin, 5 ether);
    }

    function testPermitSignatureDetails_ERC1155() public {
        address token = _deployNew1155(carol, 1, 0);

        _mint1155(token, alice, 1, 1);

        assertEq(ERC1155(token).balanceOf(alice, 1), 1);

        vm.prank(alice);
        ERC1155(token).setApprovalForAll(address(permitC), true);

        PermitSignatureDetails memory permit = PermitSignatureDetails({
            token: token,
            id: 1,
            amount: 1,
            nonce: 0,
            operator: bob,
            expiration: uint48(block.timestamp + 1000)
        });

        bytes32 digest = ECDSA.toTypedDataHash(
            permitC.domainSeparatorV4(),
            keccak256(
                abi.encode(
                    SINGLE_USE_PERMIT_TYPEHASH,
                    TOKEN_TYPE_ERC1155,
                    permit.token,
                    permit.id,
                    permit.amount,
                    permit.nonce,
                    permit.operator,
                    permit.expiration,
                    0
                )
            )
        );

        (uint8 v, bytes32 r, bytes32 s) = vm.sign(aliceKey, digest);
        bytes memory signedPermit = abi.encodePacked(r, s, v);

        vm.startPrank(bob);
        permitC.permitTransferFromERC1155(permit.token, permit.id, permit.nonce, permit.amount, permit.expiration, alice, bob, 1, signedPermit);
        vm.stopPrank();

        assertEq(ERC1155(token).balanceOf(bob, 1), 1);
    }

    function testPermitSignatureDetails_ERC1155_MoreThanOne() public {
        address token = _deployNew1155(carol, 1, 0);

        _mint1155(token, alice, 1, 10);

        assertEq(ERC1155(token).balanceOf(alice, 1), 10);

        vm.prank(alice);
        ERC1155(token).setApprovalForAll(address(permitC), true);

        PermitSignatureDetails memory permit = PermitSignatureDetails({
            token: token,
            id: 1,
            amount: 2,
            nonce: 0,
            operator: bob,
            expiration: uint48(block.timestamp + 1000)
        });

        bytes32 digest = ECDSA.toTypedDataHash(
            permitC.domainSeparatorV4(),
            keccak256(
                abi.encode(
                    SINGLE_USE_PERMIT_TYPEHASH,
                    TOKEN_TYPE_ERC1155,
                    permit.token,
                    permit.id,
                    permit.amount,
                    permit.nonce,
                    permit.operator,
                    permit.expiration,
                    0
                )
            )
        );

        (uint8 v, bytes32 r, bytes32 s) = vm.sign(aliceKey, digest);
        bytes memory signedPermit = abi.encodePacked(r, s, v);

        vm.startPrank(bob);
        permitC.permitTransferFromERC1155(permit.token, permit.id, permit.nonce, permit.amount, permit.expiration, alice, bob, 2, signedPermit);
        vm.stopPrank();

        assertEq(ERC1155(token).balanceOf(bob, 1), 2);
        assertEq(ERC1155(token).balanceOf(alice, 1), 8);
    }

    function testPermitSignatureDetails_ERC1155_RequestedAmountTooHigh() public {
        address token = _deployNew1155(carol, 1, 0);

        _mint1155(token, alice, 1, 1);

        assertEq(ERC1155(token).balanceOf(alice, 1), 1);

        vm.prank(alice);
        ERC1155(token).setApprovalForAll(address(permitC), true);

        PermitSignatureDetails memory permit = PermitSignatureDetails({
            token: token,
            id: 1,
            amount: 1,
            nonce: 0,
            operator: bob,
            expiration: uint48(block.timestamp + 1000)
        });

        bytes32 digest = ECDSA.toTypedDataHash(
            permitC.domainSeparatorV4(),
            keccak256(
                abi.encode(
                    SINGLE_USE_PERMIT_TYPEHASH,
                    TOKEN_TYPE_ERC1155,
                    permit.token,
                    permit.id,
                    permit.amount,
                    permit.nonce,
                    permit.operator,
                    permit.expiration
                )
            )
        );

        (uint8 v, bytes32 r, bytes32 s) = vm.sign(aliceKey, digest);
        bytes memory signedPermit = abi.encodePacked(r, s, v);

        vm.startPrank(bob);
        vm.expectRevert(PermitC__SignatureTransferExceededPermittedAmount.selector);
        permitC.permitTransferFromERC1155(permit.token, permit.id, permit.nonce, permit.amount, permit.expiration, alice, bob, 2, signedPermit);
        vm.stopPrank();

        assertEq(ERC1155(token).balanceOf(bob, 1), 0);
        assertEq(ERC1155(token).balanceOf(alice, 1), 1);
    }

    function testPermitSignatureDetails_ERC1155_ExpiredPermit() public {
        address token = _deployNew1155(carol, 1, 0);

        _mint1155(token, alice, 1, 1);

        assertEq(ERC1155(token).balanceOf(alice, 1), 1);

        vm.prank(alice);
        ERC1155(token).setApprovalForAll(address(permitC), true);

        PermitSignatureDetails memory permit =
            PermitSignatureDetails({token: token, id: 1, amount: 1, nonce: 0, operator: bob, expiration: uint48(block.timestamp)});

        vm.warp(uint48(block.timestamp + 1000));

        bytes32 digest = ECDSA.toTypedDataHash(
            permitC.domainSeparatorV4(),
            keccak256(
                abi.encode(
                    SINGLE_USE_PERMIT_TYPEHASH,
                    TOKEN_TYPE_ERC1155,
                    permit.token,
                    permit.id,
                    permit.amount,
                    permit.nonce,
                    permit.operator,
                    permit.expiration
                )
            )
        );

        (uint8 v, bytes32 r, bytes32 s) = vm.sign(aliceKey, digest);
        bytes memory signedPermit = abi.encodePacked(r, s, v);

        vm.startPrank(bob);
        vm.expectRevert(PermitC__SignatureTransferExceededPermitExpired.selector);
        permitC.permitTransferFromERC1155(permit.token, permit.id, permit.nonce, permit.amount, permit.expiration, alice, bob, 1, signedPermit);
        vm.stopPrank();

        assertEq(ERC1155(token).balanceOf(bob, 1), 0);
        assertEq(ERC1155(token).balanceOf(alice, 1), 1);
    }

    function testPermitSignatureDetails_ERC1155_WrongOwnerSignature() public {
        address token = _deployNew1155(carol, 1, 0);

        _mint1155(token, alice, 1, 1);

        assertEq(ERC1155(token).balanceOf(alice, 1), 1);

        vm.prank(alice);
        ERC1155(token).setApprovalForAll(address(permitC), true);

        PermitSignatureDetails memory permit = PermitSignatureDetails({
            token: token,
            id: 1,
            amount: 1,
            nonce: 0,
            operator: bob,
            expiration: uint48(block.timestamp + 1000)
        });

        bytes32 digest = ECDSA.toTypedDataHash(
            permitC.domainSeparatorV4(),
            keccak256(
                abi.encode(
                    SINGLE_USE_PERMIT_TYPEHASH,
                    TOKEN_TYPE_ERC1155,
                    permit.token,
                    permit.id,
                    permit.amount,
                    permit.nonce,
                    permit.operator,
                    permit.expiration
                )
            )
        );

        (uint8 v, bytes32 r, bytes32 s) = vm.sign(carolKey, digest);
        bytes memory signedPermit = abi.encodePacked(r, s, v);

        vm.startPrank(bob);
        vm.expectRevert(PermitC__SignatureTransferInvalidSignature.selector);
        permitC.permitTransferFromERC1155(permit.token, permit.id, permit.nonce, permit.amount, permit.expiration, alice, bob, 1, signedPermit);
        vm.stopPrank();

        assertEq(ERC1155(token).balanceOf(bob, 1), 0);
        assertEq(ERC1155(token).balanceOf(alice, 1), 1);
    }

    function testPermitSignatureDetails_ERC1155_UsedNonce() public {
        address token = _deployNew1155(carol, 1, 0);

        _mint1155(token, alice, 1, 1);

        assertEq(ERC1155(token).balanceOf(alice, 1), 1);

        vm.prank(alice);
        ERC1155(token).setApprovalForAll(address(permitC), true);

        PermitSignatureDetails memory permit = PermitSignatureDetails({
            token: token,
            id: 1,
            amount: 1,
            nonce: 0,
            operator: bob,
            expiration: uint48(block.timestamp + 1000)
        });

        bytes32 digest = ECDSA.toTypedDataHash(
            permitC.domainSeparatorV4(),
            keccak256(
                abi.encode(
                    SINGLE_USE_PERMIT_TYPEHASH,
                    TOKEN_TYPE_ERC1155,
                    permit.token,
                    permit.id,
                    permit.amount,
                    permit.nonce,
                    permit.operator,
                    permit.expiration,
                    0
                )
            )
        );

        (uint8 v, bytes32 r, bytes32 s) = vm.sign(aliceKey, digest);
        bytes memory signedPermit = abi.encodePacked(r, s, v);

        vm.startPrank(bob);
        permitC.permitTransferFromERC1155(permit.token, permit.id, permit.nonce, permit.amount, permit.expiration, alice, bob, 1, signedPermit);
        vm.stopPrank();

        assertEq(ERC1155(token).balanceOf(bob, 1), 1);
        assertEq(ERC1155(token).balanceOf(alice, 1), 0);

        vm.prank(bob);
        ERC1155(token).safeTransferFrom(bob, alice, 1, 1, "");

        assertEq(ERC1155(token).balanceOf(bob, 1), 0);
        assertEq(ERC1155(token).balanceOf(alice, 1), 1);

        vm.startPrank(bob);
        vm.expectRevert(PermitC__NonceAlreadyUsedOrRevoked.selector);
        permitC.permitTransferFromERC1155(permit.token, permit.id, permit.nonce, permit.amount, permit.expiration, alice, bob, 1, signedPermit);
        vm.stopPrank();
    }

    function testPermitSignatureDetails_ERC1155_AfterInvalidatedNonce() public {
        address token = _deployNew1155(carol, 1, 0);

        _mint1155(token, alice, 1, 1);

        assertEq(ERC1155(token).balanceOf(alice, 1), 1);

        vm.prank(alice);
        ERC1155(token).setApprovalForAll(address(permitC), true);

        PermitSignatureDetails memory permit = PermitSignatureDetails({
            token: token,
            id: 1,
            amount: 1,
            nonce: 0,
            operator: bob,
            expiration: uint48(block.timestamp + 1000)
        });

        bytes32 digest = ECDSA.toTypedDataHash(
            permitC.domainSeparatorV4(),
            keccak256(
                abi.encode(
                    SINGLE_USE_PERMIT_TYPEHASH,
                    TOKEN_TYPE_ERC1155,
                    permit.token,
                    permit.id,
                    permit.amount,
                    permit.nonce,
                    permit.operator,
                    permit.expiration,
                    0
                )
            )
        );

        (uint8 v, bytes32 r, bytes32 s) = vm.sign(aliceKey, digest);
        bytes memory signedPermit = abi.encodePacked(r, s, v);

        vm.prank(alice);
        permitC.invalidateUnorderedNonce(0);

        vm.startPrank(bob);
        vm.expectRevert(PermitC__NonceAlreadyUsedOrRevoked.selector);
        permitC.permitTransferFromERC1155(permit.token, permit.id, permit.nonce, permit.amount, permit.expiration, alice, bob, 1, signedPermit);
        vm.stopPrank();

        assertEq(ERC1155(token).balanceOf(alice, 1), 1);
    }

    function testPermitSignatureDetails_ERC1155_NonceResetOnRevert() public {
        address token = address(new ERC1155Reverter());

        _mint1155(token, alice, 1, 1);

        assertEq(ERC1155(token).balanceOf(alice, 1), 1);

        vm.prank(alice);
        ERC1155(token).setApprovalForAll(address(permitC), true);

        PermitSignatureDetails memory permit = PermitSignatureDetails({
            token: token,
            id: 1,
            amount: 1,
            nonce: 0,
            operator: bob,
            expiration: uint48(block.timestamp + 1000)
        });

        bytes32 digest = ECDSA.toTypedDataHash(
            permitC.domainSeparatorV4(),
            keccak256(
                abi.encode(
                    SINGLE_USE_PERMIT_TYPEHASH,
                    TOKEN_TYPE_ERC1155,
                    permit.token,
                    permit.id,
                    permit.amount,
                    permit.nonce,
                    permit.operator,
                    permit.expiration,
                    0
                )
            )
        );

        (uint8 v, bytes32 r, bytes32 s) = vm.sign(aliceKey, digest);
        bytes memory signedPermit = abi.encodePacked(r, s, v);

        vm.startPrank(bob);
        bool isError = permitC.permitTransferFromERC1155(permit.token, permit.id, permit.nonce, permit.amount, permit.expiration, alice, bob, 1, signedPermit);
        vm.stopPrank();

        assert(isError);
        assert(permitC.isValidUnorderedNonce(alice, 0));
        assertEq(ERC1155(token).balanceOf(bob, 1), 0);
    }

    function testPermitSignatureDetailsWithAdditionalData_ERC1155_PrecomputedHash_Registered() public {
        address token = address(new ERC1155Reverter());

        _mint1155(token, alice, 1, 1);

        assertEq(ERC1155(token).balanceOf(alice, 1), 1);

        vm.prank(alice);
        ERC1155(token).setApprovalForAll(address(permitC), true);
        approval.tokenAddress = token;
        
        bytes32 additionalData = keccak256(
            abi.encode(
                uint8(0), 
                approval.seller, 
                approval.marketplace, 
                approval.paymentMethod, 
                approval.tokenAddress, 
                approval.tokenId, 
                approval.amount, 
                approval.itemPrice,
                approval.expiration, 
                approval.marketplaceFeeNumerator, 
                approval.maxRoyaltyFeeNumerator, 
                approval.nonce, 
                approval.masterNonce
            )
        );

        PermitSignatureDetails memory permit = PermitSignatureDetails({
            token: token,
            id: 1,
            amount: 1,
            nonce: 0,
            operator: bob,
            expiration: uint48(block.timestamp + 1000)
        });
        bytes32 typeHash = keccak256(
            bytes(
                string.concat(
                    SINGLE_USE_PERMIT_TRANSFER_ADVANCED_TYPEHASH_STUB,
                    additionalDataTypeString
                )
            )
        );
        
        bytes32 digest = ECDSA.toTypedDataHash(
            permitC.domainSeparatorV4(),
            keccak256(
                abi.encode(
                    typeHash,
                    TOKEN_TYPE_ERC1155,
                    permit.token,
                    permit.id,
                    permit.amount,
                    permit.nonce,
                    permit.operator,
                    permit.expiration,
                    0,
                    additionalData
                )
            )
        );
        bytes memory signedPermit;
        {
            (uint8 v, bytes32 r, bytes32 s) = vm.sign(aliceKey, digest);
            signedPermit = abi.encodePacked(r, s, v);
        }
        bytes32 tmpAdditionalData = additionalData;
        bytes32 additionalDataTypeHash = keccak256(bytes(string.concat(SINGLE_USE_PERMIT_TRANSFER_ADVANCED_TYPEHASH_STUB, additionalDataTypeString)));

        permitC.registerAdditionalDataHash(additionalDataTypeString);

        vm.prank(bob);
        (bool isError) = permitC.permitTransferFromWithAdditionalDataERC1155(
            permit.token, permit.id, permit.nonce, permit.amount, permit.expiration, 
            alice, bob, permit.amount, tmpAdditionalData, additionalDataTypeHash, signedPermit
        );

        assert(permitC.isValidUnorderedNonce(alice, permit.nonce));
        assertEq(ERC1155(token).balanceOf(alice, 1), 1);
        assert(isError);
    }

    function _deployNew1155(address creator, uint256 idToMint, uint256 amountToMint)
        internal
        virtual
        returns (address)
    {
        vm.startPrank(creator);
        address token = address(new ERC1155Mock());
        ERC1155Mock(token).mint(creator, idToMint, amountToMint);
        vm.stopPrank();
        return token;
    }

    function _mint1155(address tokenAddress, address to, uint256 tokenId, uint256 amount) internal virtual {
        ERC1155Mock(tokenAddress).mint(to, tokenId, amount);
    }
}
