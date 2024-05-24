// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "forge-std/Test.sol";
import "../src/PermitC.sol";
import "../src/libraries/PermitHash.sol";
import "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";

import "./mocks/ERC721Mock.sol";
import "./mocks/ERC1271ContractSignerMock.sol";
import "./mocks/ERC1271InvalidContractSignerMock.sol";
import "./mocks/ERC721Reverter.sol";

contract PermitC721Test is Test {
    event Approval(
        address indexed owner,
        address indexed token,
        address indexed operator,
        uint256 id,
        uint200 amount,
        uint48 expiration
    );
    event Lockdown(address indexed owner);

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

    PermitC permitC;

    uint256 adminKey;
    uint256 aliceKey;
    uint256 bobKey;
    uint256 carolKey;

    address admin;
    address alice;
    address bob;
    address carol;

    function setUp() public {
        (admin, adminKey) = makeAddrAndKey("admin");
        (alice, aliceKey) = makeAddrAndKey("alice");
        (bob, bobKey) = makeAddrAndKey("bob");
        (carol, carolKey) = makeAddrAndKey("carol");

        permitC = new PermitC("PermitC", "1", admin, 5 ether);
    }

    function testTransferFromWithApprovalOnChain_ERC721_base() public {
        address token = _deployNew721(carol, 0);

        _mint721(token, alice, 1);

        assertEq(ERC721(token).ownerOf(1), alice);

        vm.prank(alice);
        ERC721(token).approve(address(permitC), 1);

        vm.prank(alice);
        permitC.approve(TOKEN_TYPE_ERC721, token, 1, bob, 1, uint48(block.timestamp));

        (uint256 allowanceAmount, uint256 allowanceExpiration) = permitC.allowance(alice, bob, TOKEN_TYPE_ERC721, token, 1);
        assertEq(allowanceAmount, 1);
        assertEq(allowanceExpiration, uint48(block.timestamp));

        vm.prank(bob);
        permitC.transferFromERC721(alice, bob, token, 1);

        (allowanceAmount,) = permitC.allowance(alice, bob, TOKEN_TYPE_ERC721, token, 1);

        assertEq(ERC721(token).ownerOf(1), bob);
        assertEq(allowanceAmount, 0);
    }

    function testTransferFromWithApprovalOnChain_ERC721_noApproval() public {
        address token = _deployNew721(carol, 0);

        _mint721(token, alice, 1);

        assertEq(ERC721(token).ownerOf(1), alice);

        vm.prank(alice);
        ERC721(token).approve(address(permitC), 1);

        vm.prank(alice);
        permitC.approve(TOKEN_TYPE_ERC721, token, 1, carol, 1, uint48(block.timestamp));

        (uint256 allowanceCarol,) = permitC.allowance(alice, carol, TOKEN_TYPE_ERC721, token, 1);
        (uint256 allowanceBob,) = permitC.allowance(alice, bob, TOKEN_TYPE_ERC721, token, 1);
        assertEq(allowanceCarol, 1);
        assertEq(allowanceBob, 0);

        vm.prank(bob);
        vm.expectRevert(PermitC__ApprovalTransferPermitExpiredOrUnset.selector);
        permitC.transferFromERC721(alice, bob, token, 1);

        (allowanceCarol,) = permitC.allowance(alice, carol, TOKEN_TYPE_ERC721, token, 1);
        (allowanceBob,) = permitC.allowance(alice, bob, TOKEN_TYPE_ERC721, token, 1);
        assertEq(ERC721(token).ownerOf(1), alice);
        assertEq(allowanceCarol, 1);
        assertEq(allowanceBob, 0);
    }

    function testTransferFromWithApprovalOnChain_ERC721_expiredApproval() public {
        address token = _deployNew721(carol, 0);

        _mint721(token, alice, 1);

        assertEq(ERC721(token).ownerOf(1), alice);

        vm.prank(alice);
        ERC721(token).approve(address(permitC), 1);

        vm.prank(alice);
        permitC.approve(TOKEN_TYPE_ERC721, token, 1, bob, 1, uint48(block.timestamp));

        vm.prank(alice);
        permitC.approve(TOKEN_TYPE_ERC721, token, 1, carol, 1, uint48(block.timestamp + 1));

        vm.warp(block.timestamp + 1);

        (uint256 allowanceBob,) = permitC.allowance(alice, bob, TOKEN_TYPE_ERC721, token, 1);
        (uint256 allowanceCarol,) = permitC.allowance(alice, carol, TOKEN_TYPE_ERC721, token, 1);

        assertEq(allowanceBob, 0);
        assertEq(allowanceCarol, 1);

        vm.prank(bob);
        vm.expectRevert(PermitC__ApprovalTransferPermitExpiredOrUnset.selector);
        permitC.transferFromERC721(alice, bob, token, 1);

        assertEq(ERC721(token).ownerOf(1), alice);
    }

    function testTransferFromWithApprovalOnChain_ERC721_AfterMasterNonceIncrement() public {
        address token = _deployNew721(carol, 0);

        _mint721(token, alice, 1);

        assertEq(ERC721(token).ownerOf(1), alice);

        vm.prank(alice);
        ERC721(token).approve(address(permitC), 1);

        vm.startPrank(alice);
        permitC.approve(TOKEN_TYPE_ERC721, token, 1, bob, 1, uint48(block.timestamp));
        permitC.approve(TOKEN_TYPE_ERC721, token, 1, carol, 1, uint48(block.timestamp + 1000));

        vm.expectEmit(true, true, false, false);
        emit Lockdown(alice);
        permitC.lockdown();
        vm.stopPrank();

        (uint256 allowanceBob,) = permitC.allowance(alice, bob, TOKEN_TYPE_ERC721, token, 1);
        (uint256 allowanceCarol,) = permitC.allowance(alice, carol, TOKEN_TYPE_ERC721, token, 1);
        assertEq(allowanceBob, 0);
        assertEq(allowanceCarol, 0);

        vm.prank(bob);
        vm.expectRevert(PermitC__ApprovalTransferPermitExpiredOrUnset.selector);
        permitC.transferFromERC721(alice, bob, token, 1);

        assertEq(ERC721(token).ownerOf(1), alice);
    }

    function testTransferFromWithApprovalOnChain_ERC721_Replay() public {
        address token = _deployNew721(carol, 0);

        _mint721(token, alice, 1);
        _mint721(token, alice, 2);

        assertEq(ERC721(token).ownerOf(1), alice);

        vm.prank(alice);
        ERC721(token).approve(address(permitC), 1);

        vm.prank(alice);
        permitC.approve(TOKEN_TYPE_ERC721, token, 1, bob, 100, uint48(block.timestamp + 1000));

        (uint256 allowanceBob,) = permitC.allowance(alice, bob, TOKEN_TYPE_ERC721, token, 1);
        assertEq(allowanceBob, 100);

        vm.prank(bob);
        permitC.transferFromERC721(alice, bob, token, 1);

        (allowanceBob,) = permitC.allowance(alice, bob, TOKEN_TYPE_ERC721, token, 1);
        assertEq(ERC721(token).ownerOf(1), bob);
        assertEq(allowanceBob, 0);

        vm.prank(bob);
        ERC721(token).transferFrom(bob, alice, 1);

        vm.prank(bob);
        vm.expectRevert(PermitC__ApprovalTransferExceededPermittedAmount.selector);
        permitC.transferFromERC721(alice, bob, token, 1);
    }

    function testSetApprovalViaSignature_ERC721_base() public {
        address token = _deployNew721(carol, 0);

        _mint721(token, alice, 1);

        vm.prank(alice);
        ERC721(token).setApprovalForAll(address(permitC), true);

        assertEq(ERC721(token).ownerOf(1), alice);

        PermitSignatureDetails memory permit = PermitSignatureDetails({
            operator: bob,
            token: token,
            id: 1,
            amount: 1,
            nonce: 0,
            expiration: uint48(block.timestamp + 1000)
        });

        bytes32 digest = ECDSA.toTypedDataHash(
            permitC.domainSeparatorV4(),
            keccak256(
                abi.encode(
                    UPDATE_APPROVAL_TYPEHASH,
                    TOKEN_TYPE_ERC721,
                    permit.token,
                    permit.id,
                    permit.amount,
                    permit.nonce,
                    permit.operator,
                    permit.expiration,
                    permit.expiration,
                    0
                )
            )
        );

        (uint8 v, bytes32 r, bytes32 s) = vm.sign(aliceKey, digest);

        bytes memory signedPermit = abi.encodePacked(r, s, v);

        vm.prank(bob);
        vm.expectEmit(true, true, true, true);
        emit Approval(alice, token, bob, 1, 1, uint48(block.timestamp + 1000));
        permitC.updateApprovalBySignature(TOKEN_TYPE_ERC721, permit.token, permit.id, permit.nonce, permit.amount, permit.operator, permit.expiration, permit.expiration, alice, signedPermit);

        (uint256 allowanceBob,) = permitC.allowance(alice, bob, TOKEN_TYPE_ERC721, token, 1);
        assertEq(allowanceBob, 1);

        vm.prank(bob);
        permitC.transferFromERC721(alice, bob, token, 1);

        (allowanceBob,) = permitC.allowance(alice, bob, TOKEN_TYPE_ERC721, token, 1);
        assertEq(ERC721(token).ownerOf(1), bob);
        assertEq(allowanceBob, 0);
    }

    function testSetApprovalViaSignature_ERC721_SmartContractSigner() public {
        ERC1271ContractSignerMock signer = new ERC1271ContractSignerMock();

        address token = _deployNew721(carol, 0);

        _mint721(token, alice, 1);

        vm.prank(alice);
        ERC721(token).setApprovalForAll(address(signer), true);

        assertEq(ERC721(token).ownerOf(1), alice);

        PermitSignatureDetails memory permit = PermitSignatureDetails({
            operator: bob,
            token: token,
            id: 1,
            amount: 1,
            nonce: 0,
            expiration: uint48(block.timestamp + 1000)
        });

        bytes32 digest = ECDSA.toTypedDataHash(
            permitC.domainSeparatorV4(),
            keccak256(
                abi.encode(
                    UPDATE_APPROVAL_TYPEHASH,
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

        address tmpSigner = address(signer);

        vm.prank(bob);
        vm.expectEmit(true, true, true, true);
        emit Approval(tmpSigner, token, bob, 1, 1, uint48(block.timestamp + 1000));
        permitC.updateApprovalBySignature(TOKEN_TYPE_ERC721, permit.token, permit.id, permit.nonce, permit.amount, permit.operator, permit.expiration, permit.expiration, tmpSigner, signedPermit);
    }

    function testSetApprovalViaSignature_ERC721_InvalidSmartContractSigner() public {
        ERC1271InvalidContractSignerMock signer = new ERC1271InvalidContractSignerMock();

        address token = _deployNew721(carol, 0);

        _mint721(token, alice, 1);

        vm.prank(alice);
        ERC721(token).setApprovalForAll(address(signer), true);

        assertEq(ERC721(token).ownerOf(1), alice);

        PermitSignatureDetails memory permit = PermitSignatureDetails({
            operator: bob,
            token: token,
            id: 1,
            amount: 1,
            nonce: 0,
            expiration: uint48(block.timestamp + 1000)
        });

        bytes32 digest = ECDSA.toTypedDataHash(
            permitC.domainSeparatorV4(),
            keccak256(
                abi.encode(
                    UPDATE_APPROVAL_TYPEHASH,
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

        address tmpSigner = address(signer);

        vm.prank(bob);
        vm.expectRevert(PermitC__SignatureTransferInvalidSignature.selector);
        permitC.updateApprovalBySignature(TOKEN_TYPE_ERC721, permit.token, permit.id, permit.nonce, permit.amount, permit.operator, permit.expiration, permit.expiration, tmpSigner, signedPermit);
    }

    function testSetApprovalViaSignature_ERC721_WrongToken(address badToken) public {
        address token = _deployNew721(carol, 0);
        vm.assume(badToken != token);

        _mint721(token, alice, 1);

        vm.prank(alice);
        ERC721(token).setApprovalForAll(address(permitC), true);

        assertEq(ERC721(token).ownerOf(1), alice);

        PermitSignatureDetails memory permit = PermitSignatureDetails({
            operator: bob,
            token: badToken,
            id: 1,
            amount: 1,
            nonce: 0,
            expiration: uint48(block.timestamp + 1000)
        });

        bytes32 digest = ECDSA.toTypedDataHash(
            permitC.domainSeparatorV4(),
            keccak256(
                abi.encode(
                    UPDATE_APPROVAL_TYPEHASH,
                    TOKEN_TYPE_ERC721,
                    token,
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
        vm.expectRevert(PermitC__SignatureTransferInvalidSignature.selector);
        permitC.updateApprovalBySignature(TOKEN_TYPE_ERC721, permit.token, permit.id, permit.nonce, permit.amount, permit.operator, permit.expiration, permit.expiration, alice, signedPermit);

        (uint256 allowanceBob,) = permitC.allowance(alice, bob, TOKEN_TYPE_ERC721, token, 1);
        assertEq(allowanceBob, 0);
    }

    function testSetApprovalViaSignature_ERC721_WrongAmounts() public {
        address token = _deployNew721(carol, 0);

        _mint721(token, alice, 1);

        vm.prank(alice);
        ERC721(token).setApprovalForAll(address(permitC), true);

        assertEq(ERC721(token).ownerOf(1), alice);

        PermitSignatureDetails memory permit = PermitSignatureDetails({
            operator: bob,
            token: token,
            id: 1,
            amount: 2,
            nonce: 0,
            expiration: uint48(block.timestamp + 1000)
        });

        bytes32 digest = ECDSA.toTypedDataHash(
            permitC.domainSeparatorV4(),
            keccak256(
                abi.encode(
                    UPDATE_APPROVAL_TYPEHASH,
                    TOKEN_TYPE_ERC721,
                    permit.token,
                    permit.id,
                    1,
                    permit.nonce,
                    permit.operator,
                    permit.expiration
                )
            )
        );

        (uint8 v, bytes32 r, bytes32 s) = vm.sign(aliceKey, digest);

        bytes memory signedPermit = abi.encodePacked(r, s, v);
        console.log(signedPermit.length);

        vm.prank(bob);
        vm.expectRevert(PermitC__SignatureTransferInvalidSignature.selector);
        permitC.updateApprovalBySignature(TOKEN_TYPE_ERC721, permit.token, permit.id, permit.nonce, permit.amount, permit.operator, permit.expiration, permit.expiration, alice, signedPermit);

        (uint256 allowanceBob,) = permitC.allowance(alice, bob, TOKEN_TYPE_ERC721, token, 1);
        assertEq(allowanceBob, 0);
    }

    function testSetApprovalViaSignature_ERC721_ExpiredSignature() public {
        address token = _deployNew721(carol, 0);

        _mint721(token, alice, 1);

        vm.prank(alice);
        ERC721(token).setApprovalForAll(address(permitC), true);

        assertEq(ERC721(token).ownerOf(1), alice);

        PermitSignatureDetails memory permit = PermitSignatureDetails({
            operator: bob,
            token: token,
            id: 1,
            amount: 1,
            nonce: 0,
            expiration: uint48(block.timestamp + 1000)
        });

        bytes32 digest = ECDSA.toTypedDataHash(
            permitC.domainSeparatorV4(),
            keccak256(
                abi.encode(
                    UPDATE_APPROVAL_TYPEHASH,
                    TOKEN_TYPE_ERC721,
                    permit.token,
                    permit.id,
                    1,
                    permit.nonce,
                    permit.operator,
                    permit.expiration
                )
            )
        );

        (uint8 v, bytes32 r, bytes32 s) = vm.sign(aliceKey, digest);

        bytes memory signedPermit = abi.encodePacked(r, s, v);

        vm.warp(block.timestamp + 1001);

        vm.prank(bob);
        vm.expectRevert(PermitC__ApprovalTransferPermitExpiredOrUnset.selector);
        permitC.updateApprovalBySignature(TOKEN_TYPE_ERC721, permit.token, permit.id, permit.nonce, permit.amount, permit.operator, permit.expiration, permit.expiration, alice, signedPermit);

        (uint256 allowanceBob,) = permitC.allowance(alice, bob, TOKEN_TYPE_ERC721, token, 1);
        assertEq(allowanceBob, 0);
    }

    function testSetApprovalViaSignature_ERC721_UsedNonce() public {
        address token = _deployNew721(carol, 0);

        _mint721(token, alice, 1);

        vm.prank(alice);
        ERC721(token).setApprovalForAll(address(permitC), true);

        assertEq(ERC721(token).ownerOf(1), alice);

        PermitSignatureDetails memory permit = PermitSignatureDetails({
            operator: bob,
            token: token,
            id: 1,
            amount: 1,
            nonce: 0,
            expiration: uint48(block.timestamp + 1000)
        });

        bytes32 digest = ECDSA.toTypedDataHash(
            permitC.domainSeparatorV4(),
            keccak256(
                abi.encode(
                    UPDATE_APPROVAL_TYPEHASH,
                    TOKEN_TYPE_ERC721,
                    permit.token,
                    permit.id,
                    1,
                    permit.nonce,
                    permit.operator,
                    permit.expiration,
                    permit.expiration,
                    0
                )
            )
        );

        (uint8 v, bytes32 r, bytes32 s) = vm.sign(aliceKey, digest);

        bytes memory signedPermit = abi.encodePacked(r, s, v);

        vm.prank(bob);
        permitC.updateApprovalBySignature(TOKEN_TYPE_ERC721, permit.token, permit.id, permit.nonce, permit.amount, permit.operator, permit.expiration, permit.expiration, alice, signedPermit);

        (uint256 allowanceBob,) = permitC.allowance(alice, bob, TOKEN_TYPE_ERC721, token, 1);
        assertEq(allowanceBob, 1);

        vm.prank(bob);
        vm.expectRevert(PermitC__NonceAlreadyUsedOrRevoked.selector);
        permitC.updateApprovalBySignature(TOKEN_TYPE_ERC721, permit.token, permit.id, permit.nonce, permit.amount, permit.operator, permit.expiration, permit.expiration, alice, signedPermit);

        (allowanceBob,) = permitC.allowance(alice, bob, TOKEN_TYPE_ERC721, token, 1);
        assertEq(allowanceBob, 1);
    }

    function testSetApprovalViaSignature_ERC721_WrongOwnerProvided() public {
        address token = _deployNew721(carol, 0);

        _mint721(token, alice, 1);

        vm.prank(alice);
        ERC721(token).setApprovalForAll(address(permitC), true);

        assertEq(ERC721(token).ownerOf(1), alice);

        PermitSignatureDetails memory permit = PermitSignatureDetails({
            operator: bob,
            token: token,
            id: 1,
            amount: 1,
            nonce: 0,
            expiration: uint48(block.timestamp + 1000)
        });

        bytes32 digest = ECDSA.toTypedDataHash(
            permitC.domainSeparatorV4(),
            keccak256(
                abi.encode(
                    UPDATE_APPROVAL_TYPEHASH,
                    TOKEN_TYPE_ERC721,
                    permit.token,
                    permit.id,
                    1,
                    permit.nonce,
                    permit.operator,
                    permit.expiration
                )
            )
        );

        (uint8 v, bytes32 r, bytes32 s) = vm.sign(aliceKey, digest);

        bytes memory signedPermit = abi.encodePacked(r, s, v);

        vm.prank(bob);
        vm.expectRevert(PermitC__SignatureTransferInvalidSignature.selector);
        permitC.updateApprovalBySignature(TOKEN_TYPE_ERC721, permit.token, permit.id, permit.nonce, permit.amount, permit.operator, permit.expiration, permit.expiration, carol, signedPermit);

        (uint256 allowanceBob,) = permitC.allowance(alice, bob, TOKEN_TYPE_ERC721, token, 1);
        assertEq(allowanceBob, 0);
    }

    function testSetApprovalViaSignature_ERC721_InvalidatedNonce() public {
        address token = _deployNew721(carol, 0);

        _mint721(token, alice, 1);

        vm.prank(alice);
        ERC721(token).setApprovalForAll(address(permitC), true);

        assertEq(ERC721(token).ownerOf(1), alice);

        PermitSignatureDetails memory permit = PermitSignatureDetails({
            operator: bob,
            token: token,
            id: 1,
            amount: 1,
            nonce: 0,
            expiration: uint48(block.timestamp + 1000)
        });

        bytes32 digest = ECDSA.toTypedDataHash(
            permitC.domainSeparatorV4(),
            keccak256(
                abi.encode(
                    UPDATE_APPROVAL_TYPEHASH,
                    TOKEN_TYPE_ERC721,
                    permit.token,
                    permit.id,
                    1,
                    permit.nonce,
                    permit.operator,
                    permit.expiration
                )
            )
        );

        (uint8 v, bytes32 r, bytes32 s) = vm.sign(aliceKey, digest);

        bytes memory signedPermit = abi.encodePacked(r, s, v);

        vm.prank(alice);
        permitC.invalidateUnorderedNonce(0);

        vm.prank(bob);
        vm.expectRevert(PermitC__NonceAlreadyUsedOrRevoked.selector);
        permitC.updateApprovalBySignature(TOKEN_TYPE_ERC721, permit.token, permit.id, permit.nonce, permit.amount, permit.operator, permit.expiration, permit.expiration, alice, signedPermit);

        vm.prank(alice);
        vm.expectRevert(PermitC__NonceAlreadyUsedOrRevoked.selector);
        permitC.invalidateUnorderedNonce(0);

        vm.prank(bob);
        vm.expectRevert(PermitC__NonceAlreadyUsedOrRevoked.selector);
        permitC.updateApprovalBySignature(TOKEN_TYPE_ERC721, permit.token, permit.id, permit.nonce, permit.amount, permit.operator, permit.expiration, permit.expiration, alice, signedPermit);

        (uint256 allowanceBob,) = permitC.allowance(alice, bob, TOKEN_TYPE_ERC721, token, 1);
        assertEq(allowanceBob, 0);
    }

    function testTransferFromWithApprovalOnChain_ERC721_AllowanceAmountRestoredAfterRevert() public {
        vm.prank(carol);
        address token = address(new ERC721Reverter());

        _mint721(token, alice, 1);

        vm.prank(alice);
        ERC721(token).setApprovalForAll(address(permitC), true);

        assertEq(ERC721(token).ownerOf(1), alice);

        PermitSignatureDetails memory permit = PermitSignatureDetails({
            operator: bob,
            token: token,
            id: 1,
            amount: 1,
            nonce: 0,
            expiration: uint48(block.timestamp + 1000)
        });

        bytes32 digest = ECDSA.toTypedDataHash(
            permitC.domainSeparatorV4(),
            keccak256(
                abi.encode(
                    UPDATE_APPROVAL_TYPEHASH,
                    TOKEN_TYPE_ERC721,
                    permit.token,
                    permit.id,
                    permit.amount,
                    permit.nonce,
                    permit.operator,
                    permit.expiration,
                    permit.expiration,
                    0
                )
            )
        );

        (uint8 v, bytes32 r, bytes32 s) = vm.sign(aliceKey, digest);

        bytes memory signedPermit = abi.encodePacked(r, s, v);

        vm.prank(bob);
        vm.expectEmit(true, true, true, true);
        emit Approval(alice, token, bob, 1, 1, uint48(block.timestamp + 1000));
        permitC.updateApprovalBySignature(TOKEN_TYPE_ERC721, permit.token, permit.id, permit.nonce, permit.amount, permit.operator, permit.expiration, permit.expiration, alice, signedPermit);

        (uint256 allowanceBob,) = permitC.allowance(alice, bob, TOKEN_TYPE_ERC721, token, 1);
        assertEq(allowanceBob, 1);

        vm.prank(bob);
        permitC.transferFromERC721(alice, bob, token, 1);

        (allowanceBob,) = permitC.allowance(alice, bob, TOKEN_TYPE_ERC721, token, 1);
        assertEq(ERC721(token).ownerOf(1), alice);
        assertEq(allowanceBob, 1);
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
