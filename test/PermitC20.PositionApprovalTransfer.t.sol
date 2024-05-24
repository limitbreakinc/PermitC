pragma solidity ^0.8.24;

import "./Base.t.sol";
import "../src/DataTypes.sol";
import "../src/Constants.sol";
import "./mocks/ERC20Reverter.sol";

import "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";

contract PositionApprovalTransferTest is BaseTest {
    event OrderRestored(
        bytes32 indexed orderId,
        address indexed owner,
        uint256 amountRestoredToOrder
    );

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

    struct SignatureDetails {
        address operator;
        address token;
        uint256 tokenId;
        bytes32 orderId;
        uint208 amount;
        uint256 nonce;
        uint48 approvalExpiration;
        uint48 sigDeadline;
        uint256 tokenOwnerKey;
    }

    TestData private testData;

    string constant FILL_PERMITTED_ORDER_STRING = "bytes32 orderDigest)";
    bytes32 FILL_PERMITTED_ORDER_TYPEHASH = keccak256(bytes(string.concat(PERMIT_ORDER_ADVANCED_TYPEHASH_STUB, FILL_PERMITTED_ORDER_STRING)));
    
    function setUp() public override {
        super.setUp();

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

    modifier whenTokenIsERC1155() {
        testData.token = _deployNew1155(carol, 0, 0);
        _;
    }

    modifier whenOrderIdIsNotZero(bytes32 orderId) {
        vm.assume(orderId != bytes32(0));
        testData.orderId = orderId;
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

    function testFillOrder_ERC20_base(uint48 expiration_, bytes32 orderId_)
     public
     whenExpirationIsInTheFuture(expiration_)
     whenTokenIsERC20()
     whenOrderIdIsNotZero(orderId_) {
        (address token, address owner, address spender, uint256 tokenId, uint208 amount, uint48 expiration, bytes32 orderId, uint256 nonce) = _cacheData();
        _mint20(token, owner, 1);

        changePrank(owner);
        ERC20(testData.token).approve(address(permitC), 1);

        permitC.registerAdditionalDataHash(FILL_PERMITTED_ORDER_STRING);

        bytes memory signedPermit = getSignature(SignatureDetails({
            operator: spender, 
            token: token, 
            tokenId: tokenId, 
            orderId: orderId, 
            amount: amount, 
            nonce: nonce, 
            approvalExpiration: expiration,
            sigDeadline: expiration,
            tokenOwnerKey: aliceKey
        }));

        OrderFillAmounts memory orderFillAmounts = OrderFillAmounts({
            orderStartAmount: uint200(amount),
            requestedFillAmount: uint200(amount),
            minimumFillAmount: uint200(amount)
        });

        changePrank(spender);
        (, bool isError) = permitC.fillPermittedOrderERC20(
            signedPermit, orderFillAmounts, token, owner, spender, nonce, expiration, 
            orderId, FILL_PERMITTED_ORDER_TYPEHASH
        );
  
        assertEq(ERC20(token).balanceOf(bob), 1);
        assertFalse(isError);
    }

    function testFillOrder_ERC20_RevertsAfterOrderCancel(uint48 expiration_, bytes32 orderId_)
     public
     whenExpirationIsInTheFuture(expiration_)
     whenTokenIsERC20()
     whenOrderIdIsNotZero(orderId_) {
        (address token, address owner, address spender, uint256 tokenId, uint208 amount, uint48 expiration, bytes32 orderId, uint256 nonce) = _cacheData();
        _mint20(token, owner, 1);

        changePrank(owner);
        ERC20(testData.token).approve(address(permitC), 1);

        permitC.registerAdditionalDataHash(FILL_PERMITTED_ORDER_STRING);

        bytes memory signedPermit = getSignature(SignatureDetails({
            operator: spender, 
            token: token, 
            tokenId: tokenId, 
            orderId: orderId, 
            amount: amount, 
            nonce: nonce, 
            approvalExpiration: expiration,
            sigDeadline: expiration,
            tokenOwnerKey: aliceKey
        }));

        OrderFillAmounts memory orderFillAmounts = OrderFillAmounts({
            orderStartAmount: uint200(amount),
            requestedFillAmount: uint200(amount),
            minimumFillAmount: uint200(amount)
        });

        changePrank(owner);
        permitC.closePermittedOrder(owner, spender, TOKEN_TYPE_ERC20, token, tokenId, orderId);

        changePrank(spender);
        vm.expectRevert(PermitC__OrderIsEitherCancelledOrFilled.selector);
        (, bool isError) = permitC.fillPermittedOrderERC20(
            signedPermit, orderFillAmounts, token, owner, spender, nonce, expiration, 
            orderId, FILL_PERMITTED_ORDER_TYPEHASH
        );
  
        assertEq(ERC20(token).balanceOf(spender), 0);
    }

    function testClosePermittedOrderRevertsWhenNotOwnerOrOperator(uint48 expiration_, bytes32 orderId_, address maliciousCloser)
     public
     whenExpirationIsInTheFuture(expiration_)
     whenTokenIsERC20()
     whenOrderIdIsNotZero(orderId_) {
        (address token, address owner, address spender, uint256 tokenId, uint208 amount, uint48 expiration, bytes32 orderId, uint256 nonce) = _cacheData();
        _mint20(token, owner, 1);

        vm.assume(maliciousCloser != owner);
        vm.assume(maliciousCloser != spender);

        changePrank(owner);
        ERC20(testData.token).approve(address(permitC), 1);

        permitC.registerAdditionalDataHash(FILL_PERMITTED_ORDER_STRING);

        bytes memory signedPermit = getSignature(SignatureDetails({
            operator: spender, 
            token: token, 
            tokenId: tokenId, 
            orderId: orderId, 
            amount: amount, 
            nonce: nonce, 
            approvalExpiration: expiration,
            sigDeadline: expiration,
            tokenOwnerKey: aliceKey
        }));

        OrderFillAmounts memory orderFillAmounts = OrderFillAmounts({
            orderStartAmount: uint200(amount),
            requestedFillAmount: uint200(amount),
            minimumFillAmount: uint200(amount)
        });

        changePrank(maliciousCloser);
        vm.expectRevert(PermitC__CallerMustBeOwnerOrOperator.selector);
        permitC.closePermittedOrder(owner, spender, TOKEN_TYPE_ERC20, token, tokenId, orderId);
    }

    function testFillOrder_ERC20_AfterMasterNonceIncrease(uint48 expiration_, bytes32 orderId_)
     public
     whenExpirationIsInTheFuture(expiration_)
     whenTokenIsERC20()
     whenOrderIdIsNotZero(orderId_) {
        _mint20(testData.token, testData.owner, 100);

        changePrank(testData.owner);
        ERC20(testData.token).approve(address(permitC), 100);

        permitC.registerAdditionalDataHash(FILL_PERMITTED_ORDER_STRING);

        testData.amount = 100;

        bytes memory signedPermit = getSignature(SignatureDetails({
            operator: testData.spender, 
            token: testData.token, 
            tokenId: testData.tokenId, 
            orderId: testData.orderId, 
            amount: testData.amount, 
            nonce: testData.nonce, 
            approvalExpiration: testData.expiration,
            sigDeadline: testData.expiration,
            tokenOwnerKey: aliceKey
        }));

        OrderFillAmounts memory orderFillAmounts = OrderFillAmounts({
            orderStartAmount: uint200(testData.amount),
            requestedFillAmount: uint200(testData.amount - 50),
            minimumFillAmount: uint200(testData.amount - 50)
        });

        changePrank(testData.spender);
        (, bool isError) = permitC.fillPermittedOrderERC20(
            signedPermit, orderFillAmounts, testData.token, testData.owner, testData.spender, testData.nonce, testData.expiration, 
            testData.orderId, FILL_PERMITTED_ORDER_TYPEHASH
        );
  
        assertEq(ERC20(testData.token).balanceOf(testData.spender), 50);
        assertFalse(isError);

        (uint256 allowance, uint256 expiration) = permitC.allowance(testData.owner, testData.spender, TOKEN_TYPE_ERC20, testData.token, testData.tokenId, testData.orderId);
        assertEq(allowance, 50);
        assertEq(expiration, testData.expiration);

        changePrank(testData.owner);
        permitC.lockdown();

        (uint256 allowanceAfter, uint256 expirationAfter) = permitC.allowance(testData.owner, testData.spender, TOKEN_TYPE_ERC20, testData.token, testData.tokenId, testData.orderId);
        assertEq(allowanceAfter, 0);
        assertEq(expirationAfter, 0);
    }

    function testFillOrder_ERC20_AllowanceAmountResetsAfterRevert(uint48 expiration_, bytes32 orderId_)
     public
     whenExpirationIsInTheFuture(expiration_)
     whenTokenIsReverter()
     whenOrderIdIsNotZero(orderId_) {
        (address token, address owner, address spender, uint256 tokenId, uint208 amount, uint48 expiration, bytes32 orderId, uint256 nonce) = _cacheData();
        _mint20(token, owner, 1);

        changePrank(owner);
        ERC20(token).approve(address(permitC), 1);

        permitC.registerAdditionalDataHash(FILL_PERMITTED_ORDER_STRING);

        bytes memory signedPermit = getSignature(SignatureDetails({
            operator: spender, 
            token: token, 
            tokenId: tokenId, 
            orderId: orderId, 
            amount: amount, 
            nonce: nonce, 
            approvalExpiration: expiration,
            sigDeadline: expiration,
            tokenOwnerKey: aliceKey
        }));

        OrderFillAmounts memory orderFillAmounts = OrderFillAmounts({
            orderStartAmount: uint200(amount),
            requestedFillAmount: uint200(amount),
            minimumFillAmount: uint200(amount)
        });

        changePrank(spender);
        vm.expectEmit(true, true, true, true);
        emit OrderRestored(orderId, owner, amount);
        (, bool isError) = permitC.fillPermittedOrderERC20(
            signedPermit, orderFillAmounts, token, owner, spender, nonce, expiration, 
            orderId, FILL_PERMITTED_ORDER_TYPEHASH
        );
        
        address tmpToken = token;
        uint256 tmpTokenId = tokenId;
        (uint256 allowedAmount, uint256 allowanceExpiration) = permitC.allowance(owner, spender, TOKEN_TYPE_ERC20, tmpToken, tmpTokenId, orderId);
        assertEq(allowedAmount, 1);
        assertEq(expiration, allowanceExpiration);
        assertEq(ERC20(token).balanceOf(alice), 1);
        assert(isError);
    }

    function getSignature(SignatureDetails memory details) internal view returns (bytes memory signedPermit) {
        uint8 v;
        bytes32 r;
        bytes32 s;
        {
            bytes32 tmpOrderId = details.orderId;
            bytes32 digest = ECDSA.toTypedDataHash(
                permitC.domainSeparatorV4(),
                keccak256(
                    abi.encode(
                        FILL_PERMITTED_ORDER_TYPEHASH,
                        TOKEN_TYPE_ERC20,
                        details.token,
                        details.tokenId,
                        details.amount,
                        details.nonce,
                        details.operator,
                        details.approvalExpiration,
                        0,
                        tmpOrderId
                    )
                )
            );

            (v,r,s)= vm.sign(details.tokenOwnerKey, digest);
        }

        signedPermit = abi.encodePacked(r, s, v);
    }

    function _cacheData() internal view returns (address token, address owner, address spender, uint256 tokenId, uint208 amount, uint48 expiration, bytes32 orderId, uint256 nonce) {
        token = testData.token;
        owner = testData.owner;
        spender = testData.spender;
        tokenId = testData.tokenId;
        amount = testData.amount;
        expiration = testData.expiration;
        orderId = testData.orderId;
        nonce = testData.nonce;
    }
}