pragma solidity >=0.8.4 <=0.8.19;

import "../Base.t.sol";

contract invalidateUnorderedApprovalNonceTest is BaseTest {
    event UnorderedApprovalNonceInvalidation(address indexed owner, uint256 nonce);

    function setUp() public override {
        super.setUp();
    }

    modifier whenNonceIsValid() {
        _;
    }

    modifier whenNonceIsInvalid() {
        _;
    }

    function testinvalidateUnorderedApprovalNonce() whenNonceIsValid public {
        assertEq(permitC.isValidUnorderedNonce(alice, 0), true);

        vm.prank(alice);
        permitC.invalidateUnorderedNonce(0);

        assertEq(permitC.isValidUnorderedNonce(alice, 0), false);
    }

    function testinvalidateUnorderedApprovalNonce_InvalidNonce() public whenNonceIsInvalid {
        vm.prank(alice);
        permitC.invalidateUnorderedNonce(0);
        
        assertEq(permitC.isValidUnorderedNonce(alice, 0), false);

        vm.prank(alice);
        vm.expectRevert(PermitC__NonceAlreadyUsedOrRevoked.selector);
        permitC.invalidateUnorderedNonce(0);

        assertEq(permitC.isValidUnorderedNonce(alice, 0), false);
    }   

    function testinvalidateUnorderedApprovalNonce_MultipleSpaced() public whenNonceIsValid {
        for (uint256 i = 0; i <= 512; i++) {
            assertEq(permitC.isValidUnorderedNonce(alice, i), true);
        }

        vm.startPrank(alice);
        permitC.invalidateUnorderedNonce(0);
        permitC.invalidateUnorderedNonce(2);
        permitC.invalidateUnorderedNonce(257);
        permitC.invalidateUnorderedNonce(280);
        vm.stopPrank();

        for (uint256 i = 0; i <= 512; i++) {
            assertEq(permitC.isValidUnorderedNonce(alice, i), i == 0 ? false : i == 2 ? false : i == 257 ? false : i == 280 ? false : true);
        }
    }
}
