pragma solidity ^0.8.24;

import "./Base.t.sol";
import "../src/DataTypes.sol";
import "../src/Constants.sol";
import "./mocks/ERC20Reverter.sol";

import "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";

contract PermitC20ApprovalTransferTest is BaseTest {
    struct TestData {
        address token;
        address owner;
        address spender;
        uint208 amount;
        uint48 expiration;
        bytes32 positionId;
    }

    struct SignatureDetails {
        address operator;
        address token;
        uint256 tokenId;
        uint208 amount;
        uint256 nonce;
        uint48 approvalExpiration;
        uint48 sigDeadline;
        uint256 tokenOwnerKey;
    }

    TestData private testData;


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

        testData = TestData({
            token: address(0),
            owner: alice,
            spender: bob,
            amount: 1,
            expiration: uint48(block.timestamp),
            positionId: bytes32(0)
        });
    }

    function testTransferFromWithApprovalOnChain_ERC20_base(uint48 expiration)
     whenExpirationIsInTheFuture(expiration)
     whenTokenIsERC20()
     public {
        _mint20(testData.token, testData.owner, 1);

        assertEq(ERC20(testData.token).balanceOf(testData.owner), 1);

        changePrank(testData.owner);
        ERC20(testData.token).approve(address(permitC), type(uint256).max);
        permitC.approve(TOKEN_TYPE_ERC20, testData.token, 0, testData.spender, 1, uint48(block.timestamp));

        (uint256 allowanceAmount, uint256 allowanceExpiration) = permitC.allowance(testData.owner, testData.spender, TOKEN_TYPE_ERC20, testData.token, 0);
        assertEq(allowanceAmount, 1);
        assertEq(allowanceExpiration, uint48(block.timestamp));

        changePrank(testData.spender);
        permitC.transferFromERC20(testData.owner, testData.spender, testData.token, 1);

        (allowanceAmount,) = permitC.allowance(testData.owner, testData.spender, TOKEN_TYPE_ERC20, testData.token, 0);

        assertEq(ERC20(testData.token).balanceOf(testData.spender), 1);
        assertEq(allowanceAmount, 0);
    }

    function testTransferFromWithApprovalOnChain_ERC20_MaxApprovalCorrectAfterFailedTransfer(uint48 expiration)
     whenExpirationIsInTheFuture(expiration)
     whenTokenIsERC20()
     public {
        _mint20(testData.token, testData.owner, 1000);

        assertEq(ERC20(testData.token).balanceOf(testData.owner), 1000);

        changePrank(testData.owner);
        ERC20(testData.token).approve(address(permitC), type(uint256).max);
        permitC.approve(TOKEN_TYPE_ERC20, testData.token, 0, testData.spender, type(uint200).max, uint48(block.timestamp));

        (uint256 allowanceAmount, uint256 allowanceExpiration) = permitC.allowance(testData.owner, testData.spender, TOKEN_TYPE_ERC20, testData.token, 0);
        assertEq(allowanceAmount, type(uint200).max);
        assertEq(allowanceExpiration, uint48(block.timestamp));

        changePrank(testData.spender);
        bool isError = permitC.transferFromERC20(testData.owner, testData.spender, testData.token, 1500);
        // expect transfer to fail as owner balance is 1000
        assertTrue(isError);

        (allowanceAmount,) = permitC.allowance(testData.owner, testData.spender, TOKEN_TYPE_ERC20, testData.token, 0);

        assertEq(ERC20(testData.token).balanceOf(testData.owner), 1000);
        assertEq(allowanceAmount, type(uint200).max);
    }

    function testTransferFromWithApprovalOnChain_ERC20_RevertsWhenPaused(uint48 expiration)
     whenExpirationIsInTheFuture(expiration)
     whenTokenIsERC20()
     public {
        _mint20(testData.token, testData.owner, 1);

        assertEq(ERC20(testData.token).balanceOf(testData.owner), 1);

        changePrank(testData.owner);
        ERC20(testData.token).approve(address(permitC), type(uint256).max);
        permitC.approve(TOKEN_TYPE_ERC20, testData.token, 0, testData.spender, 1, uint48(block.timestamp));

        (uint256 allowanceAmount, uint256 allowanceExpiration) = permitC.allowance(testData.owner, testData.spender, TOKEN_TYPE_ERC20, testData.token, 0);
        assertEq(allowanceAmount, 1);
        assertEq(allowanceExpiration, uint48(block.timestamp));

        changePrank(admin);
        permitC.pause{value: pausableThreshold + 1}(PAUSABLE_APPROVAL_TRANSFER_FROM_ERC20);

        changePrank(testData.spender);
        vm.expectRevert(CollateralizedPausableFlags.CollateralizedPausableFlags__Paused.selector);
        permitC.transferFromERC20(testData.owner, testData.spender, testData.token, 1);

        (allowanceAmount,) = permitC.allowance(testData.owner, testData.spender, TOKEN_TYPE_ERC20, testData.token, 0);

        assertEq(ERC20(testData.token).balanceOf(testData.spender), 0);
        assertEq(ERC20(testData.token).balanceOf(testData.owner), 1);
        assertEq(allowanceAmount, 1);
    }

    function testTransferFromWithApprovalOnChain_ERC20_SuccessWhenNotPaused(uint48 expiration)
     whenExpirationIsInTheFuture(expiration)
     whenTokenIsERC20()
     public {
        _mint20(testData.token, testData.owner, 1);

        assertEq(ERC20(testData.token).balanceOf(testData.owner), 1);

        changePrank(testData.owner);
        ERC20(testData.token).approve(address(permitC), type(uint256).max);
        permitC.approve(TOKEN_TYPE_ERC20, testData.token, 0, testData.spender, 1, uint48(block.timestamp));

        (uint256 allowanceAmount, uint256 allowanceExpiration) = permitC.allowance(testData.owner, testData.spender, TOKEN_TYPE_ERC20, testData.token, 0);
        assertEq(allowanceAmount, 1);
        assertEq(allowanceExpiration, uint48(block.timestamp));

        changePrank(admin);
        permitC.pause{value: pausableThreshold + 1}(type(uint256).max - PAUSABLE_APPROVAL_TRANSFER_FROM_ERC20);

        changePrank(testData.spender);
        permitC.transferFromERC20(testData.owner, testData.spender, testData.token, 1);

        (allowanceAmount,) = permitC.allowance(testData.owner, testData.spender, TOKEN_TYPE_ERC20, testData.token, 0);

        assertEq(ERC20(testData.token).balanceOf(testData.spender), 1);
        assertEq(ERC20(testData.token).balanceOf(testData.owner), 0);
        assertEq(allowanceAmount, 0);
    }

    function testTransferFromWithApprovalOnChain_ERC20_RevertsWhenPausedAllowedAfterUnpause(uint48 expiration)
     whenExpirationIsInTheFuture(expiration)
     whenTokenIsERC20()
     public {
        _mint20(testData.token, testData.owner, 1);

        assertEq(ERC20(testData.token).balanceOf(testData.owner), 1);

        changePrank(testData.owner);
        ERC20(testData.token).approve(address(permitC), type(uint256).max);
        permitC.approve(TOKEN_TYPE_ERC20, testData.token, 0, testData.spender, 1, uint48(block.timestamp));

        (uint256 allowanceAmount, uint256 allowanceExpiration) = permitC.allowance(testData.owner, testData.spender, TOKEN_TYPE_ERC20, testData.token, 0);
        assertEq(allowanceAmount, 1);
        assertEq(allowanceExpiration, uint48(block.timestamp));

        changePrank(admin);
        permitC.pause{value: pausableThreshold + 1}(PAUSABLE_APPROVAL_TRANSFER_FROM_ERC20);

        changePrank(testData.spender);
        vm.expectRevert(CollateralizedPausableFlags.CollateralizedPausableFlags__Paused.selector);
        permitC.transferFromERC20(testData.owner, testData.spender, testData.token, 1);

        (allowanceAmount,) = permitC.allowance(testData.owner, testData.spender, TOKEN_TYPE_ERC20, testData.token, 0);

        assertEq(ERC20(testData.token).balanceOf(testData.spender), 0);
        assertEq(ERC20(testData.token).balanceOf(testData.owner), 1);
        assertEq(allowanceAmount, 1);

        changePrank(admin);
        permitC.unpause(admin, address(permitC).balance);
        assertEq(address(permitC).balance, 0);

        changePrank(testData.spender);
        permitC.transferFromERC20(testData.owner, testData.spender, testData.token, 1);

        (allowanceAmount,) = permitC.allowance(testData.owner, testData.spender, TOKEN_TYPE_ERC20, testData.token, 0);

        assertEq(ERC20(testData.token).balanceOf(testData.spender), 1);
        assertEq(ERC20(testData.token).balanceOf(testData.owner), 0);
        assertEq(allowanceAmount, 0);
    }

    function testTransferFromWithApprovalOnChain_ERC20_AllowanceAmountRestoredAfterRevert(uint48 expiration)
     whenExpirationIsInTheFuture(expiration)
     whenTokenIsReverter()
     public {
        _mint20(testData.token, testData.owner, 1);

        assertEq(ERC20(testData.token).balanceOf(testData.owner), 1);

        changePrank(testData.owner);
        ERC20(testData.token).approve(address(permitC), type(uint256).max);
        permitC.approve(TOKEN_TYPE_ERC20, testData.token, 0, testData.spender, 1, uint48(block.timestamp));

        (uint256 allowanceAmount, uint256 allowanceExpiration) = permitC.allowance(testData.owner, testData.spender, TOKEN_TYPE_ERC20, testData.token, 0);
        assertEq(allowanceAmount, 1);
        assertEq(allowanceExpiration, uint48(block.timestamp));

        changePrank(testData.spender);
        bool isError = permitC.transferFromERC20(testData.owner, testData.spender, testData.token, 1);

        assert(isError);

        (allowanceAmount,) = permitC.allowance(testData.owner, testData.spender, TOKEN_TYPE_ERC20, testData.token, 0);

        assertEq(ERC20(testData.token).balanceOf(testData.spender), 0);
        assertEq(ERC20(testData.token).balanceOf(testData.owner), 1);
        assertEq(allowanceAmount, 1);
    }

}