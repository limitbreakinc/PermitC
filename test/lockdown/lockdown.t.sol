pragma solidity >=0.8.4 <=0.8.19;

import "../Base.t.sol";

contract lockdownTest is BaseTest {

    function setUp() public override {
        super.setUp();
    }

    function testLockdown_base(address account) public {
        for (uint256 i = 0; i < 100; i++) {
            uint256 previousMasterNonce = permitC.masterNonce(account);
            
            vm.startPrank(account);
            vm.expectEmit(true, false, false, false);
            emit Lockdown(account);
            permitC.lockdown();
            vm.stopPrank();

            uint256 updatedMasterNonce = permitC.masterNonce(account);
            assertEq(updatedMasterNonce - previousMasterNonce, 1);
        }
    }

    function testLockdown_ERC721() public {
        address token = _deployNew721(carol, 0);

        _mint721(token, alice, 1);

        assertEq(ERC721(token).ownerOf(1), alice);

        vm.startPrank(alice);
        ERC721(token).approve(address(permitC), 1);

        permitC.approve(token, 1, bob, 1, uint48(block.timestamp));
        permitC.approve(token, 1, carol, 1, uint48(block.timestamp + 1000));

        vm.expectEmit(true, true, false, false);
        emit Lockdown(alice);
        permitC.lockdown();
        vm.stopPrank();

        (uint256 allowanceBob,) = permitC.allowance(alice, bob, token, 1);
        (uint256 allowanceCarol,) = permitC.allowance(alice, carol, token, 1);

        assertEq(allowanceBob, 0);
        assertEq(allowanceCarol, 0);

        vm.prank(bob);
        vm.expectRevert(PermitC__ApprovalTransferPermitExpiredOrUnset.selector);
        permitC.transferFromERC721(alice, bob, token, 1);

        assertEq(ERC721(token).ownerOf(1), alice);
    }

    function testLockdown_ERC1155() public {
        address token = _deployNew1155(carol, 0, 0);

        _mint1155(token, alice, 1, 1);

        assertEq(ERC1155(token).balanceOf(alice, 1), 1);

        vm.startPrank(alice);
        ERC1155(token).setApprovalForAll(address(permitC), true);

        permitC.approve(token, 1, bob, 1, uint48(block.timestamp));
        permitC.approve(token, 1, carol, 1, uint48(block.timestamp + 1000));

        vm.expectEmit(true, true, false, false);
        emit Lockdown(alice);
        permitC.lockdown();
        vm.stopPrank();

        (uint256 allowanceBob,) = permitC.allowance(alice, bob, token, 1);
        (uint256 allowanceCarol,) = permitC.allowance(alice, carol, token, 1);
        assertEq(allowanceBob, 0);
        assertEq(allowanceCarol, 0);

        vm.prank(bob);
        vm.expectRevert(PermitC__ApprovalTransferPermitExpiredOrUnset.selector);
        permitC.transferFromERC1155(alice, bob, token, 1, 1);

        assertEq(ERC1155(token).balanceOf(alice, 1), 1);
    }
}
