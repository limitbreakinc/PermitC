// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "forge-std/Test.sol";
import "../src/PermitC.sol";
import "../src/libraries/PermitHash.sol";
import "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import "forge-std/console2.sol";

import "./mocks/ERC721Mock.sol";
import "./mocks/ERC721Reverter.sol";

contract PermitC721Test is Test {

    enum OrderProtocols {
        ERC721_FILL_OR_KILL,
        ERC1155_FILL_OR_KILL,
        ERC1155_FILL_PARTIAL
    }

    struct data {
        address token;
        uint256 id;
        uint200 amount;
        uint256 nonce;
        address owner;
        address operator;
        uint48 expiration;
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
    uint256 constant aliceKey = 1;
    uint256 constant bobKey = 2;
    uint256 constant carolKey = 3;

    address admin;
    address immutable alice;
    address immutable bob;
    address immutable carol;

    string constant additionalDataTypeString = "SaleApproval approval)SaleApproval(uint8 protocol,address seller,address marketplace,address paymentMethod,address tokenAddress,uint256 tokenId,uint256 amount,uint256 itemPrice,uint256 expiration,uint256 marketplaceFeeNumerator,uint256 maxRoyaltyFeeNumerator,uint256 nonce,uint256 masterNonce)";

    SaleApproval approval;

    constructor() {
        alice = vm.addr(aliceKey);
        bob = vm.addr(bobKey);
        carol = vm.addr(carolKey);

        approval = SaleApproval({
        protocol: OrderProtocols.ERC721_FILL_OR_KILL,
        seller: alice,
        marketplace: address(0),
        paymentMethod: address(0),
        tokenAddress: address(0),
        tokenId: 1,
        amount: 1,
        itemPrice: 0,
        expiration: uint48(block.timestamp + 1000),
        marketplaceFeeNumerator: 0,
        maxRoyaltyFeeNumerator: 0,
        nonce: 0,
        masterNonce: 0
    });
    }

    function setUp() public {
        (admin, adminKey) = makeAddrAndKey("admin");

        permitC = new PermitC("PermitC", "1", admin, 5 ether);
    }

    function testPermitSignatureDetails_ERC721_base() public {
        address token = _deployNew721(carol, 0);

        _mint721(token, alice, 1);

        assertEq(ERC721(token).ownerOf(1), alice);

        vm.prank(alice);
        ERC721(token).approve(address(permitC), 1);

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
                    TOKEN_TYPE_ERC721,
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
        permitC.permitTransferFromERC721(permit.token, permit.id, permit.nonce, permit.expiration, alice, bob, signedPermit);
        vm.stopPrank();

        assertEq(ERC721(token).ownerOf(1), bob);
    }

    function testPermitSignatureDetails_ERC721_multipleNonces() public {
        address token = _deployNew721(carol, 0);

        _mint721(token, alice, 1);
        _mint721(token, alice, 2);

        assertEq(ERC721(token).ownerOf(1), alice);

        vm.startPrank(alice);
        ERC721(token).approve(address(permitC), 1);
        ERC721(token).approve(address(permitC), 2);
        vm.stopPrank();

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
                    TOKEN_TYPE_ERC721,
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
        permitC.permitTransferFromERC721(permit.token, permit.id, permit.nonce, permit.expiration, alice, bob, signedPermit);
        vm.stopPrank();

        assertEq(ERC721(token).ownerOf(1), bob);
        assertEq(ERC721(token).ownerOf(2), alice);

        assert(!permitC.isValidUnorderedNonce(alice, 0));
        assert(permitC.isValidUnorderedNonce(alice, 1));

        PermitSignatureDetails memory permit2 = PermitSignatureDetails({
            token: token,
            id: 2,
            amount: 1,
            nonce: 1,
            operator: bob,
            expiration: uint48(block.timestamp + 1000)
        });

        bytes32 digest2 = ECDSA.toTypedDataHash(
            permitC.domainSeparatorV4(),
            keccak256(
                abi.encode(
                    SINGLE_USE_PERMIT_TYPEHASH,
                    TOKEN_TYPE_ERC721,
                    permit2.token,
                    permit2.id,
                    permit2.amount,
                    permit2.nonce,
                    permit2.operator,
                    permit2.expiration,
                    0
                )
            )
        );
        bytes memory signedPermit2;
        {(uint8 v2, bytes32 r2, bytes32 s2) = vm.sign(aliceKey, digest2);
        signedPermit2 = abi.encodePacked(r2, s2, v2);}

        vm.startPrank(bob);
        permitC.permitTransferFromERC721(permit2.token, permit2.id, permit2.nonce, permit2.expiration, alice, bob, signedPermit2);
        vm.stopPrank();

        assertEq(ERC721(token).ownerOf(1), bob);
        assertEq(ERC721(token).ownerOf(2), bob);

        assert(!permitC.isValidUnorderedNonce(alice, 0));
    }

    function testPermitSignatureDetails_ERC721_Expired() public {
        address token = _deployNew721(carol, 0);

        _mint721(token, alice, 1);

        assertEq(ERC721(token).ownerOf(1), alice);

        vm.prank(alice);
        ERC721(token).approve(address(permitC), 1);

        PermitSignatureDetails memory permit =
            PermitSignatureDetails({token: token, id: 1, amount: 1, nonce: 0, operator: bob, expiration: uint48(block.timestamp)});

        vm.warp(uint48(block.timestamp + 1000));

        bytes32 digest = ECDSA.toTypedDataHash(
            permitC.domainSeparatorV4(),
            keccak256(
                abi.encode(
                    SINGLE_USE_PERMIT_TYPEHASH,
                    TOKEN_TYPE_ERC721,
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

        vm.prank(bob);
        vm.expectRevert(PermitC__SignatureTransferExceededPermitExpired.selector);
        permitC.permitTransferFromERC721(permit.token, permit.id, permit.nonce, permit.expiration, alice, bob, signedPermit);

        assertEq(ERC721(token).ownerOf(1), alice);
    }

    function testPermitSignatureDetails_ERC721_UsedNonce() public {
        address token = _deployNew721(carol, 0);

        _mint721(token, alice, 1);

        assertEq(ERC721(token).ownerOf(1), alice);

        vm.prank(alice);
        ERC721(token).approve(address(permitC), 1);

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
                    TOKEN_TYPE_ERC721,
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

        vm.prank(bob);
        permitC.permitTransferFromERC721(permit.token, permit.id, permit.nonce, permit.expiration, alice, bob, signedPermit);

        assertEq(ERC721(token).ownerOf(1), bob);

        vm.prank(bob);
        ERC721(token).transferFrom(bob, alice, 1);

        vm.prank(bob);
        vm.expectRevert(PermitC__NonceAlreadyUsedOrRevoked.selector);
        permitC.permitTransferFromERC721(permit.token, permit.id, permit.nonce, permit.expiration, alice, bob, signedPermit);

        assertEq(ERC721(token).ownerOf(1), alice);
    }

    function testPermitSignatureDetails_ERC721_InvalidatedNonce() public {
        address token = _deployNew721(carol, 0);

        _mint721(token, alice, 1);

        assertEq(ERC721(token).ownerOf(1), alice);

        vm.prank(alice);
        ERC721(token).approve(address(permitC), 1);

        PermitSignatureDetails memory permit = PermitSignatureDetails({
            token: token,
            id: 1,
            amount: 1,
            nonce: 0,
            operator: bob,
            expiration: uint48(block.timestamp + 1000)
        });

        vm.prank(alice);
        permitC.invalidateUnorderedNonce(0);

        bytes32 digest = ECDSA.toTypedDataHash(
            permitC.domainSeparatorV4(),
            keccak256(
                abi.encode(
                    SINGLE_USE_PERMIT_TYPEHASH,
                    TOKEN_TYPE_ERC721,
                    permit.token,
                    permit.id,
                    permit.amount,
                    permit.nonce,
                    permit.operator,
                    permit.expiration,
                    0 // master nonce
                )
            )
        );

        (uint8 v, bytes32 r, bytes32 s) = vm.sign(aliceKey, digest);
        bytes memory signedPermit = abi.encodePacked(r, s, v);

        vm.prank(bob);
        vm.expectRevert(PermitC__NonceAlreadyUsedOrRevoked.selector);
        permitC.permitTransferFromERC721(permit.token, permit.id, permit.nonce, permit.expiration, alice, bob, signedPermit);

        assertEq(ERC721(token).ownerOf(1), alice);
    }

    function testPermitSignatureDetails_ERC721_InvalidSignature() public {
        address token = _deployNew721(carol, 0);

        _mint721(token, alice, 1);

        assertEq(ERC721(token).ownerOf(1), alice);

        vm.prank(alice);
        ERC721(token).approve(address(permitC), 1);

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
                    TOKEN_TYPE_ERC721,
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

        vm.prank(bob);
        vm.expectRevert(PermitC__SignatureTransferInvalidSignature.selector);
        permitC.permitTransferFromERC721(permit.token, permit.id, permit.nonce, permit.expiration, alice, bob, signedPermit);

        assertEq(ERC721(token).ownerOf(1), alice);
    }

    function testPermitSignatureDetails_ERC721_ERC1155Protocol() public {
        address token = _deployNew721(carol, 0);

        _mint721(token, alice, 1);

        assertEq(ERC721(token).ownerOf(1), alice);

        vm.prank(alice);
        ERC721(token).approve(address(permitC), 1);

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
        assertEq(ERC721(token).ownerOf(1), alice);
    }

    function testPermitSignatureDetailsWithAdditionalData_ERC721_PrecomputedHash_NotRegistered() public {
        address token = _deployNew721(carol, 0);

        _mint721(token, alice, 1);

        assertEq(ERC721(token).ownerOf(1), alice);

        vm.prank(alice);
        ERC721(token).approve(address(permitC), 1);
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
                    TOKEN_TYPE_ERC721,
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


        (uint8 v, bytes32 r, bytes32 s) = vm.sign(aliceKey, digest);
        bytes memory signedPermit = abi.encodePacked(r, s, v);
        bytes32 tmpAdditionalData = additionalData;
        bytes32 additionalDataTypeHash = keccak256(abi.encode(additionalDataTypeString));

        vm.prank(bob);
        vm.expectRevert(PermitC__SignatureTransferPermitHashNotRegistered.selector);
        permitC.permitTransferFromWithAdditionalDataERC721(
            permit.token, permit.id, permit.nonce, permit.expiration, 
            alice, bob,  tmpAdditionalData, additionalDataTypeHash, signedPermit
        );
    }

    function testPermitSignatureDetailsWithAdditionalData_ERC721_PrecomputedHash_Registered() public {
        address token = _deployNew721(carol, 0);

        _mint721(token, alice, 1);

        assertEq(ERC721(token).ownerOf(1), alice);

        vm.prank(alice);
        ERC721(token).approve(address(permitC), 1);
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
                    TOKEN_TYPE_ERC721,
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


        (uint8 v, bytes32 r, bytes32 s) = vm.sign(aliceKey, digest);
        bytes memory signedPermit = abi.encodePacked(r, s, v);
        bytes32 tmpAdditionalData = additionalData;
        bytes32 additionalDataTypeHash = keccak256(bytes(string.concat(SINGLE_USE_PERMIT_TRANSFER_ADVANCED_TYPEHASH_STUB, additionalDataTypeString)));

        permitC.registerAdditionalDataHash(additionalDataTypeString);

        vm.prank(bob);
        (bool isError) = permitC.permitTransferFromWithAdditionalDataERC721(
            permit.token, permit.id, permit.nonce, permit.expiration, 
            alice, bob, tmpAdditionalData, additionalDataTypeHash, signedPermit
        );


        assertEq(ERC721(token).ownerOf(1), bob);
        assertFalse(isError);
    }

    function testPermitSignatureDetails_ERC721_NonceStillActiveAfterRevert() public {
        vm.prank(carol);
        address token = address(new ERC721Reverter());

        _mint721(token, alice, 1);

        assertEq(ERC721(token).ownerOf(1), alice);

        vm.prank(alice);
        ERC721(token).approve(address(permitC), 1);

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
                    TOKEN_TYPE_ERC721,
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

        assert(permitC.isValidUnorderedNonce(alice, 0));

        vm.startPrank(bob);
        permitC.permitTransferFromERC721(permit.token, permit.id, permit.nonce, permit.expiration, alice, bob, signedPermit);
        vm.stopPrank();

        assert(permitC.isValidUnorderedNonce(alice, 0));

        assertEq(ERC721(token).ownerOf(1), alice);
    }

    function testPermitSignatureDetailsWithAdditionalData_ERC721_NonceStillActiveAfterRevert() public {
        address token = address(new ERC721Reverter());

        _mint721(token, alice, 1);

        assertEq(ERC721(token).ownerOf(1), alice);

        vm.prank(alice);
        ERC721(token).approve(address(permitC), 1);
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
                    TOKEN_TYPE_ERC721,
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


        (uint8 v, bytes32 r, bytes32 s) = vm.sign(aliceKey, digest);
        bytes memory signedPermit = abi.encodePacked(r, s, v);
        bytes32 tmpAdditionalData = additionalData;
        bytes32 additionalDataTypeHash = keccak256(bytes(string.concat(SINGLE_USE_PERMIT_TRANSFER_ADVANCED_TYPEHASH_STUB, additionalDataTypeString)));

        permitC.registerAdditionalDataHash(additionalDataTypeString);

        vm.prank(bob);
        (bool isError) = permitC.permitTransferFromWithAdditionalDataERC721(
            permit.token, permit.id, permit.nonce, permit.expiration, 
            alice, bob, tmpAdditionalData, additionalDataTypeHash, signedPermit
        );

        assert(permitC.isValidUnorderedNonce(alice, 0));
        assertEq(ERC721(token).ownerOf(1), alice);
        assert(isError);
    }

    function _deployNew721(address creator, uint256 amountToMint) internal virtual returns (address) {
        vm.startPrank(creator);
        address token = address(new ERC721Mock());
        ERC721Mock(token).mint(creator, amountToMint);
        vm.stopPrank();
        return token;
    }

    function _mint721(address tokenAddress, address to, uint256 tokenId) internal virtual {
        ERC721Mock(tokenAddress).mint(to, tokenId);
    }
}
