pragma solidity >=0.8.4 <=0.8.19;

import "../Base.t.sol";

contract ApproveTest is BaseTest {
    function setUp() public override {
        super.setUp();
    }

    modifier whenExpirationIsZero() {
        _;
    }

    modifier whenExpirationIsNotZero() {
        _;
    }

    function testIncreaseApproveViaOnChainTx_ERC721_base(uint48 expiration) public whenExpirationIsNotZero {
        expiration = uint48(bound(expiration, block.timestamp, type(uint48).max));
        address token = _deployNew721(carol, 0);

        _mint721(token, alice, 1);

        assertEq(ERC721(token).ownerOf(1), alice);

        changePrank(alice);
        ERC721(token).approve(address(permitC), 1);

        vm.expectEmit(true, true, true, true);
        emit Approval(alice, token, bob, 1, 1, expiration);
        permitC.approve(token, 1, bob, 1, expiration);

        (uint256 allowanceBob,) = permitC.allowance(alice, bob, token, 1);
        assertEq(allowanceBob, 1);
        changePrank(admin);
    }

    function testIncreaseApproveViaOnChainTx_ERC721_base() public whenExpirationIsZero {
        address token = _deployNew721(carol, 0);

        _mint721(token, alice, 1);

        assertEq(ERC721(token).ownerOf(1), alice);

        changePrank(alice);
        ERC721(token).approve(address(permitC), 1);

        vm.expectEmit(true, true, true, true);
        emit Approval(alice, token, bob, 1, 1, uint48(block.timestamp));
        permitC.approve(token, 1, bob, 1, uint48(block.timestamp));

        (uint256 allowanceBob,) = permitC.allowance(alice, bob, token, 1);
        assertEq(allowanceBob, 1);
        changePrank(admin);
    }

    function testIncreaseApproveViaOnChainTx_ERC721_ReturnZeroAfterExpiration(uint48 expiration)
        public
        whenExpirationIsNotZero
    {
        expiration = uint48(bound(expiration, 1001, type(uint48).max - 2000));
        address token = _deployNew721(carol, 0);

        _mint721(token, alice, 1);

        assertEq(ERC721(token).ownerOf(1), alice);

        changePrank(alice);
        ERC721(token).approve(address(permitC), 1);

        vm.expectEmit(true, true, true, true);
        emit Approval(alice, token, bob, 1, 1, uint48(expiration));
        permitC.approve(token, 1, bob, 1, uint48(expiration));

        vm.warp(expiration - 500);

        (uint256 allowanceBob, uint256 allowanceExpiration) = permitC.allowance(alice, bob, token, 1);
        assertEq(allowanceBob, 1);
        assertEq(allowanceExpiration, expiration);

        vm.warp(expiration + 1);

        (allowanceBob, allowanceExpiration) = permitC.allowance(alice, bob, token, 1);
        assertEq(allowanceBob, 0);

        changePrank(admin);
    }

    function testIncreaseApproveViaOnChainTx_ERC721_ReturnZeroAfterExpiration() public whenExpirationIsZero {
        address token = _deployNew721(carol, 0);

        _mint721(token, alice, 1);

        assertEq(ERC721(token).ownerOf(1), alice);

        changePrank(alice);
        ERC721(token).approve(address(permitC), 1);

        vm.expectEmit(true, true, true, true);
        emit Approval(alice, token, bob, 1, 1, uint48(block.timestamp));
        permitC.approve(token, 1, bob, 1, uint48(block.timestamp));

        vm.warp(block.timestamp);

        (uint256 allowanceBob,) = permitC.allowance(alice, bob, token, 1);
        assertEq(allowanceBob, 1);

        vm.warp(block.timestamp + 1);

        (allowanceBob,) = permitC.allowance(alice, bob, token, 1);
        assertEq(allowanceBob, 0);
        changePrank(admin);
    }

    function testIncreaseApproveViaOnChainTx_ERC1155_base(uint48 expiration) public whenExpirationIsNotZero {
        expiration = uint48(bound(expiration, block.timestamp, type(uint48).max));
        address token = _deployNew1155(carol, 0, 0);

        _mint1155(token, alice, 1, 1);

        assertEq(ERC1155(token).balanceOf(alice, 1), 1);

        changePrank(alice);
        ERC1155(token).setApprovalForAll(address(permitC), true);

        vm.expectEmit(true, true, true, true);
        emit Approval(alice, token, bob, 1, 1, expiration);
        permitC.approve(token, 1, bob, 1, expiration);

        (uint256 allowanceBob,) = permitC.allowance(alice, bob, token, 1);
        assertEq(allowanceBob, 1);
        changePrank(admin);
    }

    function testIncreaseApproveViaOnChainTx_ERC1155_base() public whenExpirationIsZero {
        address token = _deployNew1155(carol, 0, 0);

        _mint1155(token, alice, 1, 1);

        assertEq(ERC1155(token).balanceOf(alice, 1), 1);

        changePrank(alice);
        ERC1155(token).setApprovalForAll(address(permitC), true);

        vm.expectEmit(true, true, true, true);
        emit Approval(alice, token, bob, 1, 1, uint48(block.timestamp));
        permitC.approve(token, 1, bob, 1, uint48(block.timestamp));

        (uint256 allowanceBob,) = permitC.allowance(alice, bob, token, 1);
        assertEq(allowanceBob, 1);
        changePrank(admin);
    }

    function testIncreaseApproveViaOnChainTx_ERC1155_ReturnZeroAfterExpiration(uint48 expiration)
        public
        whenExpirationIsNotZero
    {
        expiration = uint48(bound(expiration, 1001, type(uint48).max - 2000));
        address token = _deployNew1155(carol, 0, 0);

        _mint1155(token, alice, 1, 1);

        assertEq(ERC1155(token).balanceOf(alice, 1), 1);

        changePrank(alice);
        ERC1155(token).setApprovalForAll(address(permitC), true);

        vm.expectEmit(true, true, true, true);
        emit Approval(alice, token, bob, 1, 1, uint48(expiration));
        permitC.approve(token, 1, bob, 1, uint48(expiration));

        vm.warp(expiration - 500);

        (uint256 allowanceBob,) = permitC.allowance(alice, bob, token, 1);
        assertEq(allowanceBob, 1);

        vm.warp(expiration + 1);

        (allowanceBob,) = permitC.allowance(alice, bob, token, 1);
        assertEq(allowanceBob, 0);
        changePrank(admin);
    }

    function testIncreaseApproveViaOnChainTx_ERC1155_ReturnZeroAfterExpiration() public whenExpirationIsZero {
        address token = _deployNew1155(carol, 0, 0);

        _mint1155(token, alice, 1, 1);

        assertEq(ERC1155(token).balanceOf(alice, 1), 1);

        changePrank(alice);
        ERC1155(token).setApprovalForAll(address(permitC), true);

        vm.expectEmit(true, true, true, true);
        emit Approval(alice, token, bob, 1, 1, uint48(block.timestamp));
        permitC.approve(token, 1, bob, 1, uint48(block.timestamp));

        vm.warp(block.timestamp);

        (uint256 allowanceBob,) = permitC.allowance(alice, bob, token, 1);
        assertEq(allowanceBob, 1);

        vm.warp(block.timestamp + 1);

        (allowanceBob,) = permitC.allowance(alice, bob, token, 1);
        assertEq(allowanceBob, 0);
        changePrank(admin);
    }
}
