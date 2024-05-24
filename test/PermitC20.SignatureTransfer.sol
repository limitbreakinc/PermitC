// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "./Base.t.sol";
import "../src/PermitC.sol";
import "../src/libraries/PermitHash.sol";
import "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import "forge-std/console2.sol";

import "./mocks/ERC20Mock.sol";
import "./mocks/ERC20Reverter.sol";

contract PermitC20SignatureTransfer is BaseTest {

    enum OrderProtocols {
        ERC721_FILL_OR_KILL,
        ERC1155_FILL_OR_KILL,
        ERC1155_FILL_PARTIAL
    }

    struct TestData {
        address token;
        address owner;
        address spender;
        uint256 tokenId;
        uint208 amount;
        uint48 expiration;
        bytes32 orderId;
        uint256 nonce;
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

    TestData private testData;

    string constant additionalDataTypeString = "SaleApproval approval)SaleApproval(uint8 protocol,address seller,address marketplace,address paymentMethod,address tokenAddress,uint256 tokenId,uint256 amount,uint256 itemPrice,uint256 expiration,uint256 marketplaceFeeNumerator,uint256 maxRoyaltyFeeNumerator,uint256 nonce,uint256 masterNonce)";

    SaleApproval approval;

    modifier whenExpirationIsInTheFuture(uint48 expiration) {
        testData.expiration = uint48(bound(expiration, block.timestamp, type(uint48).max));
        _;
    }

    modifier whenExpirationIsInThePast(uint48 expiration) {
        vm.assume(block.timestamp > 0);
        testData.expiration = uint48(bound(expiration, type(uint48).min + 1, block.timestamp - 1));
        _;
    }

    modifier whenExpirationIsCurrentTimestamp() {
        testData.expiration = uint48(block.timestamp);
        _;
    }

    modifier whenExpirationIsZero() {
        testData.expiration = uint48(0);
        _;
    }

    modifier whenTokenIsERC20() {
        testData.token = _deployNew20(carol, 0);
        _;
    }

    modifier whenTokenIsReverter() {
        testData.token = address(new ERC20Reverter());
        _;
    }

    modifier whenTokenIsNotAContract(address token) {
        assumeAddressIsNot(token, AddressType.ZeroAddress, AddressType.Precompile, AddressType.ForgeAddress);
        vm.assume(token.code.length == 0);
        testData.token = token;
        _;
    }

    modifier whenTokenIsAnERC1155() {
        testData.token = _deployNew1155(carol, 1, 1);
        _mint1155(testData.token, testData.owner, 1, testData.amount);
        _;
    }

    function setUp() public override {
        super.setUp();

        approval = SaleApproval({
            protocol: OrderProtocols.ERC721_FILL_OR_KILL,
            seller: alice,
            marketplace: address(0),
            paymentMethod: address(0),
            tokenAddress: address(0),
            tokenId: 0,
            amount: 1,
            itemPrice: 0,
            expiration: uint48(block.timestamp + 1000),
            marketplaceFeeNumerator: 0,
            maxRoyaltyFeeNumerator: 0,
            nonce: 0,
            masterNonce: 0
        });

        testData = TestData({
            token: address(0),
            owner: alice,
            spender: bob,
            tokenId: 0,
            amount: 1,
            expiration: uint48(block.timestamp),
            orderId: bytes32(0),
            nonce: 0
        });
    }

    function testPermitSignatureDetails_ERC20_base(uint48 expiration_, bytes32 orderId_) 
      public
      whenExpirationIsInTheFuture(expiration_)
      whenTokenIsERC20() {
        _mint20(testData.token, alice, testData.amount);

        assertEq(ERC20(testData.token).balanceOf(testData.owner), testData.amount);

        changePrank(testData.owner);
        ERC20(testData.token).approve(address(permitC), type(uint256).max);

        bytes32 digest = ECDSA.toTypedDataHash(
            permitC.domainSeparatorV4(),
            keccak256(
                abi.encode(
                    SINGLE_USE_PERMIT_TYPEHASH,
                    TOKEN_TYPE_ERC20,
                    testData.token,
                    testData.tokenId,
                    testData.amount,
                    testData.nonce,
                    testData.spender,
                    testData.expiration,
                    0
                )
            )
        );

        (uint8 v, bytes32 r, bytes32 s) = vm.sign(aliceKey, digest);
        bytes memory signedPermit = abi.encodePacked(r, s, v);

        changePrank(testData.spender);
        permitC.permitTransferFromERC20(
            testData.token, 
            testData.nonce, 
            testData.amount, 
            testData.expiration, 
            testData.owner, 
            testData.spender,
            testData.amount,
            signedPermit
        );
        vm.stopPrank();

        assertEq(ERC20(testData.token).balanceOf(testData.spender), testData.amount);
    }

    function testPermitSignatureDetails_ERC20_multipleNonces(uint48 expiration_) 
      public
      whenExpirationIsInTheFuture(expiration_)
      whenTokenIsERC20() {
        _mint20(testData.token, testData.owner, testData.amount * 2);

        assertEq(ERC20(testData.token).balanceOf(testData.owner), testData.amount * 2);

        changePrank(testData.owner);
        ERC20(testData.token).approve(address(permitC), type(uint256).max);

        bytes32 digest = ECDSA.toTypedDataHash(
            permitC.domainSeparatorV4(),
            keccak256(
                abi.encode(
                    SINGLE_USE_PERMIT_TYPEHASH,
                    TOKEN_TYPE_ERC20,
                    testData.token,
                    testData.tokenId,
                    testData.amount,
                    testData.nonce,
                    testData.spender,
                    testData.expiration,
                    0
                )
            )
        );

        (uint8 v, bytes32 r, bytes32 s) = vm.sign(aliceKey, digest);
        bytes memory signedPermit = abi.encodePacked(r, s, v);

        vm.startPrank(testData.spender);
        permitC.permitTransferFromERC20(
            testData.token, 
            testData.nonce, 
            testData.amount,
            testData.expiration, 
            testData.owner, 
            testData.spender,
            testData.amount,
            signedPermit
        );

        assertEq(ERC20(testData.token).balanceOf(testData.spender), testData.amount);
        assertEq(ERC20(testData.token).balanceOf(testData.owner), testData.amount);

        assert(!permitC.isValidUnorderedNonce(testData.owner, 0));
        assert(permitC.isValidUnorderedNonce(testData.owner, 1));

        bytes32 digest2 = ECDSA.toTypedDataHash(
            permitC.domainSeparatorV4(),
            keccak256(
                abi.encode(
                    SINGLE_USE_PERMIT_TYPEHASH,
                    TOKEN_TYPE_ERC20,
                    testData.token,
                    testData.tokenId,
                    testData.amount,
                    testData.nonce + 1,
                    testData.spender,
                    testData.expiration,
                    0
                )
            )
        );
        bytes memory signedPermit2;
        {(uint8 v2, bytes32 r2, bytes32 s2) = vm.sign(aliceKey, digest2);
        signedPermit2 = abi.encodePacked(r2, s2, v2);}

        permitC.permitTransferFromERC20(
            testData.token, 
            testData.nonce + 1, 
            testData.amount,
            testData.expiration, 
            testData.owner, 
            testData.spender,
            testData.amount,
            signedPermit2
        );

        assertEq(ERC20(testData.token).balanceOf(testData.spender), testData.amount * 2);

        assert(!permitC.isValidUnorderedNonce(alice, 0));
    }

    function testPermitSignatureDetails_ERC20_Expired(uint48 expiration_)
      whenTokenIsERC20()
      whenExpirationIsInThePast(expiration_)
      public {
        _mint20(testData.token, testData.owner, testData.amount);

        assertEq(ERC20(testData.token).balanceOf(testData.owner), testData.amount);

        changePrank(testData.owner);
        ERC20(testData.token).approve(address(permitC), testData.amount);

        bytes32 digest = ECDSA.toTypedDataHash(
            permitC.domainSeparatorV4(),
            keccak256(
                abi.encode(
                    SINGLE_USE_PERMIT_TYPEHASH,
                    TOKEN_TYPE_ERC20,
                    testData.token,
                    testData.tokenId,
                    testData.amount,
                    testData.nonce,
                    testData.spender,
                    testData.expiration,
                    0
                )
            )
        );

        (uint8 v, bytes32 r, bytes32 s) = vm.sign(aliceKey, digest);
        bytes memory signedPermit = abi.encodePacked(r, s, v);

        changePrank(testData.spender);
        vm.expectRevert(PermitC__SignatureTransferExceededPermitExpired.selector);
        permitC.permitTransferFromERC20(
            testData.token, 
            testData.nonce, 
            testData.amount, 
            testData.expiration, 
            testData.owner, 
            testData.spender, 
            testData.amount, 
            signedPermit
        );

        assertEq(ERC20(testData.token).balanceOf(testData.owner), testData.amount);
    }

    function testPermitSignatureDetails_ERC20_UsedNonce(uint48 expiration_)
      whenTokenIsERC20()
      whenExpirationIsInTheFuture(expiration_)
      public {
        _mint20(testData.token, testData.owner, testData.amount);

        assertEq(ERC20(testData.token).balanceOf(testData.owner), testData.amount);

        changePrank(testData.owner);
        ERC20(testData.token).approve(address(permitC), testData.amount);

        bytes32 digest = ECDSA.toTypedDataHash(
            permitC.domainSeparatorV4(),
            keccak256(
                abi.encode(
                    SINGLE_USE_PERMIT_TYPEHASH,
                    TOKEN_TYPE_ERC20,
                    testData.token,
                    testData.tokenId,
                    testData.amount,
                    testData.nonce,
                    testData.spender,
                    testData.expiration,
                    0
                )
            )
        );

        (uint8 v, bytes32 r, bytes32 s) = vm.sign(aliceKey, digest);
        bytes memory signedPermit = abi.encodePacked(r, s, v);

        changePrank(testData.spender);
        permitC.permitTransferFromERC20(
            testData.token, 
            testData.nonce, 
            testData.amount, 
            testData.expiration, 
            testData.owner, 
            testData.spender, 
            testData.amount, 
            signedPermit
        );

        assertEq(ERC20(testData.token).balanceOf(testData.spender), testData.amount);

        changePrank(testData.spender);
        ERC20(testData.token).transfer(testData.owner, testData.amount);

        vm.expectRevert(PermitC__NonceAlreadyUsedOrRevoked.selector);
        permitC.permitTransferFromERC20(
            testData.token, 
            testData.nonce, 
            testData.amount, 
            testData.expiration, 
            testData.owner, 
            testData.spender, 
            testData.amount, 
            signedPermit
        );

        assertEq(ERC20(testData.token).balanceOf(testData.owner), testData.amount);
    }

    function testPermitSignatureDetails_ERC20_InvalidatedNonce(uint48 expiration_)
      whenTokenIsERC20()
      whenExpirationIsInTheFuture(expiration_)
      public {
        _mint20(testData.token, testData.owner, testData.amount);

        assertEq(ERC20(testData.token).balanceOf(testData.owner), testData.amount);

        changePrank(testData.owner);
        ERC20(testData.token).approve(address(permitC), testData.amount);

        changePrank(testData.owner);
        permitC.invalidateUnorderedNonce(0);

        bytes32 digest = ECDSA.toTypedDataHash(
            permitC.domainSeparatorV4(),
            keccak256(
                abi.encode(
                    SINGLE_USE_PERMIT_TYPEHASH,
                    TOKEN_TYPE_ERC20,
                    testData.token,
                    testData.tokenId,
                    testData.amount,
                    testData.nonce,
                    testData.spender,
                    testData.expiration,
                    0 // master nonce
                )
            )
        );

        (uint8 v, bytes32 r, bytes32 s) = vm.sign(aliceKey, digest);
        bytes memory signedPermit = abi.encodePacked(r, s, v);

        changePrank(testData.spender);
        vm.expectRevert(PermitC__NonceAlreadyUsedOrRevoked.selector);
        permitC.permitTransferFromERC20(testData.token, testData.nonce, testData.amount, testData.expiration, testData.owner, testData.spender, testData.amount, signedPermit);

        assertEq(ERC20(testData.token).balanceOf(testData.owner), testData.amount);
    }

    function testPermitSignatureDetails_ERC20_InvalidSignature(uint48 expiration_)
      whenExpirationIsInTheFuture(expiration_)
      whenTokenIsERC20()
      public {
        _mint20(testData.token, testData.owner, testData.amount);

        assertEq(ERC20(testData.token).balanceOf(testData.owner), testData.amount);

        changePrank(testData.owner);
        ERC20(testData.token).approve(address(permitC), testData.amount);

        bytes32 digest = ECDSA.toTypedDataHash(
            permitC.domainSeparatorV4(),
            keccak256(
                abi.encode(
                    SINGLE_USE_PERMIT_TYPEHASH,
                    TOKEN_TYPE_ERC20,
                    testData.token,
                    testData.tokenId,
                    testData.amount,
                    testData.nonce,
                    testData.spender,
                    testData.expiration
                )
            )
        );

        (uint8 v, bytes32 r, bytes32 s) = vm.sign(carolKey, digest);
        bytes memory signedPermit = abi.encodePacked(r, s, v);

        changePrank(testData.spender);
        vm.expectRevert(PermitC__SignatureTransferInvalidSignature.selector);
        permitC.permitTransferFromERC20(
            testData.token, 
            testData.nonce, 
            testData.amount, 
            testData.expiration, 
            testData.owner, 
            testData.spender, 
            testData.amount, 
            signedPermit
        );

        assertEq(ERC20(testData.token).balanceOf(testData.owner), testData.amount);
    }

    function testPermitSignatureDetailsWithAdditionalData_ERC20_PrecomputedHash_NotRegistered()
      whenTokenIsERC20()
      whenExpirationIsInTheFuture(testData.expiration)
      public {
        _mint20(testData.token, testData.owner, testData.amount);

        assertEq(ERC20(testData.token).balanceOf(testData.owner), testData.amount);

        changePrank(testData.owner);
        ERC20(testData.token).approve(address(permitC), testData.amount);
        approval.tokenAddress = testData.token;
        
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
                    TOKEN_TYPE_ERC20,
                    testData.token,
                    testData.tokenId,
                    testData.amount,
                    testData.nonce,
                    testData.spender,
                    testData.expiration,
                    0,
                    additionalData
                )
            )
        );


        (uint8 v, bytes32 r, bytes32 s) = vm.sign(aliceKey, digest);
        bytes memory signedPermit = abi.encodePacked(r, s, v);
        bytes32 tmpAdditionalData = additionalData;
        bytes32 additionalDataTypeHash = keccak256(abi.encode(additionalDataTypeString));

        changePrank(testData.spender);
        vm.expectRevert(PermitC__SignatureTransferPermitHashNotRegistered.selector);
        permitC.permitTransferFromWithAdditionalDataERC20(
            testData.token, testData.amount, testData.nonce, testData.expiration, 
            testData.owner, testData.spender, testData.amount,  tmpAdditionalData, additionalDataTypeHash, signedPermit
        );
    }

    function testPermitSignatureDetailsWithAdditionalData_ERC20_PrecomputedHash_Registered() 
      whenTokenIsERC20()
      whenExpirationIsInTheFuture(testData.expiration)
      public {
        _mint20(testData.token, testData.owner, testData.amount);

        assertEq(ERC20(testData.token).balanceOf(testData.owner), testData.amount);

        changePrank(testData.owner);
        ERC20(testData.token).approve(address(permitC), testData.amount);
        approval.tokenAddress = testData.token;
        
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
                    TOKEN_TYPE_ERC20,
                    testData.token,
                    testData.tokenId,
                    testData.amount,
                    testData.nonce,
                    testData.spender,
                    testData.expiration,
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

        changePrank(testData.spender);
        (bool isError) = permitC.permitTransferFromWithAdditionalDataERC20(
            testData.token, testData.nonce, testData.amount, testData.expiration, 
            testData.owner, testData.spender, testData.amount, tmpAdditionalData, additionalDataTypeHash, signedPermit
        );


        assertEq(ERC20(testData.token).balanceOf(testData.spender), testData.amount);
        assertFalse(isError);
    }

    function testPermitSignatureDetails_ERC20_NonceStillActiveAfterRevert()
      whenTokenIsReverter()
      whenExpirationIsInTheFuture(testData.expiration)
      public {
        _mint20(testData.token, testData.owner, testData.amount);

        assertEq(ERC20(testData.token).balanceOf(testData.owner), testData.amount);

        changePrank(testData.owner);
        ERC20(testData.token).approve(address(permitC), testData.amount);

        bytes32 digest = ECDSA.toTypedDataHash(
            permitC.domainSeparatorV4(),
            keccak256(
                abi.encode(
                    SINGLE_USE_PERMIT_TYPEHASH,
                    TOKEN_TYPE_ERC20,
                    testData.token,
                    testData.tokenId,
                    testData.amount,
                    testData.nonce,
                    testData.spender,
                    testData.expiration,
                    0
                )
            )
        );

        (uint8 v, bytes32 r, bytes32 s) = vm.sign(aliceKey, digest);
        bytes memory signedPermit = abi.encodePacked(r, s, v);

        assert(permitC.isValidUnorderedNonce(alice, 0));

        vm.startPrank(testData.spender);
        permitC.permitTransferFromERC20(testData.token, testData.nonce, testData.amount, testData.expiration, testData.owner, testData.spender, testData.amount, signedPermit);
        vm.stopPrank();

        assert(permitC.isValidUnorderedNonce(alice, 0));

        assertEq(ERC20(testData.token).balanceOf(testData.owner), testData.amount);
    }

    function testPermitSignatureDetailsWithAdditionalData_ERC20_NonceStillActiveAfterRevert()
      whenTokenIsReverter()
      whenExpirationIsInTheFuture(testData.expiration)
      public {
        _mint20(testData.token, testData.owner, testData.amount);

        assertEq(ERC20(testData.token).balanceOf(testData.owner), testData.amount);

        changePrank(testData.owner);
        ERC20(testData.token).approve(address(permitC), testData.amount);
        approval.tokenAddress = testData.token;
        
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
                    TOKEN_TYPE_ERC20,
                    testData.token,
                    testData.tokenId,
                    testData.amount,
                    testData.nonce,
                    testData.spender,
                    testData.expiration,
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

        changePrank(testData.spender);
        (bool isError) = permitC.permitTransferFromWithAdditionalDataERC20(
            testData.token, testData.nonce, testData.amount, testData.expiration, 
            testData.owner, testData.spender, testData.amount, tmpAdditionalData, additionalDataTypeHash, signedPermit
        );

        assert(permitC.isValidUnorderedNonce(alice, 0));
        assertEq(ERC20(testData.token).balanceOf(testData.owner), testData.amount);
        assert(isError);
    }
}
