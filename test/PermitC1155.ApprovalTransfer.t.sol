// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "forge-std/Test.sol";
import "../src/PermitC.sol";
import "../src/libraries/PermitHash.sol";

import "./mocks/ERC1155Mock.sol";
import "./mocks/ERC1155Reverter.sol";
import "./mocks/ERC1271ContractSignerMock.sol";
import "./mocks/ERC1271InvalidContractSignerMock.sol";
import "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";

contract PermitC1155Test is Test {
    event Lockdown(address indexed owner);
    event Approval(
        address indexed owner,
        address indexed token,
        address indexed operator,
        uint256 id,
        uint200 amount,
        uint48 expiration
    );

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

    function testIncreaseApproveViaOnChainTx_ERC1155_base() public {
        address token = _deployNew1155(alice, 1, 100);
        _mint1155(token, alice, 2, 100);

        vm.startPrank(alice);
        permitC.approve(TOKEN_TYPE_ERC1155, token, 1, bob, 50, uint48(block.timestamp + 1000));
        permitC.approve(TOKEN_TYPE_ERC1155, token, 2, bob, 25, uint48(block.timestamp + 1000));
        vm.stopPrank();

        assertEq(ERC1155Mock(token).balanceOf(alice, 1), 100);
        assertEq(ERC1155Mock(token).balanceOf(alice, 2), 100);

        (uint256 allowanceBobId1,) = permitC.allowance(alice, bob, TOKEN_TYPE_ERC1155, token, 1);
        (uint256 allowanceBobId2,) = permitC.allowance(alice, bob, TOKEN_TYPE_ERC1155, token, 2);
        assertEq(allowanceBobId1, 50);
        assertEq(allowanceBobId2, 25);
    }

    function testIncreaseApproveViaOnChainTx_ERC1155_Fuzzed(uint200 amount) public {
        address token = _deployNew1155(alice, 1, 100);
        _mint1155(token, alice, 2, 100);

        vm.startPrank(alice);
        permitC.approve(TOKEN_TYPE_ERC1155, token, 1, bob, amount, uint48(block.timestamp + 1000));
        permitC.approve(TOKEN_TYPE_ERC1155, token, 2, bob, amount, uint48(block.timestamp + 1000));
        vm.stopPrank();

        assertEq(ERC1155Mock(token).balanceOf(alice, 1), 100);
        assertEq(ERC1155Mock(token).balanceOf(alice, 2), 100);

        (uint256 allowanceBobId1,) = permitC.allowance(alice, bob, TOKEN_TYPE_ERC1155, token, 1);
        (uint256 allowanceBobId2,) = permitC.allowance(alice, bob, TOKEN_TYPE_ERC1155, token, 2);
        assertEq(allowanceBobId1, amount);
        assertEq(allowanceBobId2, amount);
    }

    function testIncreaseApproveViaOnChainTx_ERC1155_ReturnZeroAfterExpiration() public {
        address token = _deployNew1155(carol, 1, 0);

        _mint1155(token, alice, 2, 100);
        _mint1155(token, alice, 3, 100);

        vm.startPrank(alice);
        permitC.approve(TOKEN_TYPE_ERC1155, token, 2, bob, 50, uint48(block.timestamp + 1000));
        permitC.approve(TOKEN_TYPE_ERC1155, token, 3, bob, 25, uint48(block.timestamp + 1001));
        vm.stopPrank();

        vm.warp(block.timestamp + 1000);
        
        (uint256 allowanceBobId2,) = permitC.allowance(alice, bob, TOKEN_TYPE_ERC1155, token, 2);
        (uint256 allowanceBobId3,) = permitC.allowance(alice, bob, TOKEN_TYPE_ERC1155, token, 3);
        assertEq(allowanceBobId2, 50);
        assertEq(allowanceBobId3, 25);

        vm.warp(block.timestamp + 1);
        (allowanceBobId2,) = permitC.allowance(alice, bob, TOKEN_TYPE_ERC1155, token, 2);
        (allowanceBobId3,) = permitC.allowance(alice, bob, TOKEN_TYPE_ERC1155, token, 3);
        assertEq(allowanceBobId2, 0);
        assertEq(allowanceBobId3, 25);

        vm.warp(block.timestamp + 1);
        (allowanceBobId2,) = permitC.allowance(alice, bob, TOKEN_TYPE_ERC1155, token, 2);
        (allowanceBobId3,) = permitC.allowance(alice, bob, TOKEN_TYPE_ERC1155, token, 3);
        assertEq(allowanceBobId2, 0);
        assertEq(allowanceBobId3, 0);
    }

    function testTransferFromWithApprovalOnChain_ERC1155_base() public {
        address token = _deployNew1155(carol, 1, 0);

        _mint1155(token, alice, 2, 100);
        _mint1155(token, alice, 3, 100);

        vm.prank(alice);
        ERC1155(token).setApprovalForAll(address(permitC), true);

        vm.startPrank(alice);
        permitC.approve(TOKEN_TYPE_ERC1155, token, 2, bob, 50, uint48(block.timestamp + 1000));
        permitC.approve(TOKEN_TYPE_ERC1155, token, 3, bob, 25, uint48(block.timestamp + 1000));
        vm.stopPrank();

        (uint256 allowanceBobId2,) = permitC.allowance(alice, bob, TOKEN_TYPE_ERC1155, token, 2);
        assertEq(allowanceBobId2, 50);

        vm.startPrank(bob);
        permitC.transferFromERC1155(alice, bob, token, 2, 20);

        (allowanceBobId2,) = permitC.allowance(alice, bob, TOKEN_TYPE_ERC1155, token, 2);
        assertEq(allowanceBobId2, 30);
        assertEq(ERC1155Mock(token).balanceOf(alice, 2), 80);
        assertEq(ERC1155Mock(token).balanceOf(bob, 2), 20);
    }

    function testTransferFromWithApprovalOnChain_ERC1155_fuzzed(uint200 amount) public {
        address token = _deployNew1155(carol, 1, 0);

        _mint1155(token, alice, 2, type(uint200).max);
        _mint1155(token, alice, 3, type(uint200).max);

        vm.prank(alice);
        ERC1155(token).setApprovalForAll(address(permitC), true);

        vm.startPrank(alice);
        permitC.approve(TOKEN_TYPE_ERC1155, token, 2, bob, amount, uint48(block.timestamp + 1000));
        permitC.approve(TOKEN_TYPE_ERC1155, token, 3, bob, amount, uint48(block.timestamp + 1000));
        vm.stopPrank();

        (uint256 allowanceBobId2,) = permitC.allowance(alice, bob, TOKEN_TYPE_ERC1155, token, 2);
        assertEq(allowanceBobId2, amount);

        vm.startPrank(bob);
        permitC.transferFromERC1155(alice, bob, token, 2, amount);

        (allowanceBobId2,) = permitC.allowance(alice, bob, TOKEN_TYPE_ERC1155, token, 2);
        if (amount == type(uint200).max) {
            assertEq(allowanceBobId2, type(uint200).max);
        } else {
            assertEq(allowanceBobId2, 0);
        }
        assertEq(ERC1155Mock(token).balanceOf(alice, 2), type(uint200).max - amount);
        assertEq(ERC1155Mock(token).balanceOf(bob, 2), amount);
    }

    function testTransferFromWithApprovalOnChain_ERC1155_noApproval() public {
        address token = _deployNew1155(carol, 1, 0);

        _mint1155(token, alice, 2, 100);
        _mint1155(token, alice, 3, 100);

        vm.prank(alice);
        ERC1155(token).setApprovalForAll(address(permitC), true);

        (uint256 allowanceBobId2,) = permitC.allowance(alice, bob, TOKEN_TYPE_ERC1155, token, 2);
        assertEq(allowanceBobId2, 0);

        vm.startPrank(bob);
        vm.expectRevert(PermitC__ApprovalTransferPermitExpiredOrUnset.selector);
        permitC.transferFromERC1155(alice, bob, token, 2, 20);

        (allowanceBobId2,) = permitC.allowance(alice, bob, TOKEN_TYPE_ERC1155, token, 2);
        assertEq(allowanceBobId2, 0);
        assertEq(ERC1155Mock(token).balanceOf(alice, 2), 100);
        assertEq(ERC1155Mock(token).balanceOf(bob, 2), 0);
    }

    function testTransferFromWithApprovalOnChain_ERC1155_expiredApproval(uint200 amount) public {
        address token = _deployNew1155(carol, 1, 0);

        _mint1155(token, alice, 2, type(uint200).max);
        _mint1155(token, alice, 3, type(uint200).max);

        vm.prank(alice);
        ERC1155(token).setApprovalForAll(address(permitC), true);

        vm.startPrank(alice);
        permitC.approve(TOKEN_TYPE_ERC1155, token, 2, bob, amount, uint48(block.timestamp + 1000));
        permitC.approve(TOKEN_TYPE_ERC1155, token, 3, bob, amount, uint48(block.timestamp + 1000));
        vm.stopPrank();

        (uint256 allowanceBobId2,) = permitC.allowance(alice, bob, TOKEN_TYPE_ERC1155, token, 2);
        assertEq(allowanceBobId2, amount);

        vm.warp(block.timestamp + 1001);

        (allowanceBobId2,) = permitC.allowance(alice, bob, TOKEN_TYPE_ERC1155, token, 2);
        assertEq(allowanceBobId2, 0);

        vm.startPrank(bob);
        vm.expectRevert(PermitC__ApprovalTransferPermitExpiredOrUnset.selector);
        permitC.transferFromERC1155(alice, bob, token, 2, amount);

        assertEq(ERC1155Mock(token).balanceOf(alice, 2), type(uint200).max);
        assertEq(ERC1155Mock(token).balanceOf(bob, 2), 0);
    }

    function testTransferFromWithApprovalOnChain_ERC1155_AfterMasterNonceIncrement(uint200 amount) public {
        address token = _deployNew1155(carol, 1, 0);

        _mint1155(token, alice, 2, type(uint200).max);
        _mint1155(token, alice, 3, type(uint200).max);

        vm.prank(alice);
        ERC1155(token).setApprovalForAll(address(permitC), true);

        vm.startPrank(alice);
        permitC.approve(TOKEN_TYPE_ERC1155, token, 1, bob, amount, uint48(block.timestamp));
        permitC.approve(TOKEN_TYPE_ERC1155, token, 1, carol, amount, uint48(block.timestamp + 1000));

        vm.expectEmit(true, true, false, false);
        emit Lockdown(alice);
        permitC.lockdown();
        vm.stopPrank();

        (uint256 allowanceBobId1,) = permitC.allowance(alice, bob, TOKEN_TYPE_ERC1155, token, 1);
        (uint256 allowanceCarolId1,) = permitC.allowance(alice, carol, TOKEN_TYPE_ERC1155, token, 1);
        assertEq(allowanceBobId1, 0);
        assertEq(allowanceCarolId1, 0);

        vm.prank(bob);
        vm.expectRevert(PermitC__ApprovalTransferPermitExpiredOrUnset.selector);
        permitC.transferFromERC1155(alice, bob, token, 1, 1);

        assertEq(ERC1155(token).balanceOf(alice, 2), type(uint200).max);
        assertEq(ERC1155(token).balanceOf(bob, 2), 0);
    }

    function testSetApprovalViaSignature_ERC1155_base() public {
        address token = _deployNew1155(carol, 1, 0);

        _mint1155(token, alice, 1, 100);

        vm.prank(alice);
        ERC1155(token).setApprovalForAll(address(permitC), true);

        PermitSignatureDetails memory permit = PermitSignatureDetails({
            operator: bob,
            token: token,
            id: 1,
            amount: 50,
            nonce: 0,
            expiration: uint48(block.timestamp + 1000)
        });

        bytes32 digest = ECDSA.toTypedDataHash(
            permitC.domainSeparatorV4(),
            keccak256(
                abi.encode(
                    UPDATE_APPROVAL_TYPEHASH,
                    TOKEN_TYPE_ERC1155,
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
        emit Approval(alice, token, bob, 1, 50, uint48(block.timestamp + 1000));
        permitC.updateApprovalBySignature(TOKEN_TYPE_ERC1155, permit.token, permit.id, permit.nonce, permit.amount, permit.operator, permit.expiration, permit.expiration, alice, signedPermit);

        (uint256 allowanceBobId1,) = permitC.allowance(alice, bob, TOKEN_TYPE_ERC1155, token, 1);
        assertEq(allowanceBobId1, 50);

        vm.prank(bob);
        permitC.transferFromERC1155(alice, bob, token, 1, 1);

        assertEq(ERC1155(token).balanceOf(bob, 1), 1);
        assertEq(ERC1155(token).balanceOf(alice, 1), 99);

        (allowanceBobId1,) = permitC.allowance(alice, bob, TOKEN_TYPE_ERC1155, token, 1);
        assertEq(allowanceBobId1, 49);
    }

    function testSetApprovalViaSignature_ERC1155_SmartContractSigner() public {
        ERC1271ContractSignerMock signer = new ERC1271ContractSignerMock();

        address token = _deployNew1155(carol, 1, 0);

        _mint1155(token, alice, 1, 100);

        vm.prank(alice);
        ERC1155(token).setApprovalForAll(address(signer), true);

        assertEq(ERC1155(token).balanceOf(alice, 1), 100);

        PermitSignatureDetails memory permit = PermitSignatureDetails({
            operator: bob,
            token: token,
            id: 1,
            amount: 75,
            nonce: 0,
            expiration: uint48(block.timestamp + 1000)
        });

        bytes32 digest = ECDSA.toTypedDataHash(
            permitC.domainSeparatorV4(),
            keccak256(
                abi.encode(
                    UPDATE_APPROVAL_TYPEHASH,
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
        emit Approval(address(signer), token, bob, 1, 75, uint48(block.timestamp + 1000));
        permitC.updateApprovalBySignature(TOKEN_TYPE_ERC1155, permit.token, permit.id, permit.nonce, permit.amount, permit.operator, permit.expiration, permit.expiration, tmpSigner, signedPermit);

        (uint256 allowanceBobId1,) = permitC.allowance(address(signer), bob, TOKEN_TYPE_ERC1155, token, 1);
        assertEq(allowanceBobId1, 75);
    }

    function testSetApprovalViaSignature_ERC1155_InvalidSmartContractSigner() public {
        ERC1271InvalidContractSignerMock signer = new ERC1271InvalidContractSignerMock();

        address token = _deployNew1155(carol, 1, 0);

        _mint1155(token, alice, 1, 100);

        vm.prank(alice);
        ERC1155(token).setApprovalForAll(address(signer), true);

        assertEq(ERC1155(token).balanceOf(alice, 1), 100);

        PermitSignatureDetails memory permit = PermitSignatureDetails({
            operator: bob,
            token: token,
            id: 1,
            amount: 20,
            nonce: 0,
            expiration: uint48(block.timestamp + 1000)
        });

        bytes32 digest = ECDSA.toTypedDataHash(
            permitC.domainSeparatorV4(),
            keccak256(
                abi.encode(
                    UPDATE_APPROVAL_TYPEHASH,
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
        permitC.updateApprovalBySignature(TOKEN_TYPE_ERC1155, permit.token, permit.id, permit.nonce, permit.amount, permit.operator, permit.expiration, permit.expiration, tmpSigner, signedPermit);

        (uint256 allowanceBobId1,) = permitC.allowance(address(signer), bob, TOKEN_TYPE_ERC1155, token, 1);
        assertEq(allowanceBobId1, 0);
    }

    function testSetApprovalViaSignature_ERC1155_WrongToken(address badToken) public {
        address token = _deployNew1155(carol, 1, 0);
        vm.assume(badToken != token);

        _mint1155(token, alice, 1, 100);

        vm.prank(alice);
        ERC1155(token).setApprovalForAll(address(permitC), true);

        assertEq(ERC1155(token).balanceOf(alice, 1), 100);

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
        permitC.updateApprovalBySignature(TOKEN_TYPE_ERC1155, permit.token, permit.id, permit.nonce, permit.amount, permit.operator, permit.expiration, permit.expiration, alice, signedPermit);

        (uint256 allowanceBobId1,) = permitC.allowance(alice, bob, TOKEN_TYPE_ERC1155, token, 1);
        assertEq(allowanceBobId1, 0);
    }

    function testSetApprovalViaSignature_ERC1155_WrongAmounts() public {
        address token = _deployNew1155(carol, 1, 0);

        _mint1155(token, alice, 1, 100);

        vm.prank(alice);
        ERC1155(token).setApprovalForAll(address(permitC), true);

        assertEq(ERC1155(token).balanceOf(alice, 1), 100);

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
        permitC.updateApprovalBySignature(TOKEN_TYPE_ERC1155, permit.token, permit.id, permit.nonce, permit.amount, permit.operator, permit.expiration, permit.expiration, alice, signedPermit);

        (uint256 allowanceBobId1,) = permitC.allowance(alice, bob, TOKEN_TYPE_ERC1155, token, 1);
        assertEq(allowanceBobId1, 0);
    }

    function testSetApprovalViaSignature_ERC1155_ExpiredSignature() public {
        address token = _deployNew1155(carol, 1, 0);

        _mint1155(token, alice, 1, 100);

        vm.prank(alice);
        ERC1155(token).setApprovalForAll(address(permitC), true);

        assertEq(ERC1155(token).balanceOf(alice, 1), 100);

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
        permitC.updateApprovalBySignature(TOKEN_TYPE_ERC1155, permit.token, permit.id, permit.nonce, permit.amount, permit.operator, permit.expiration, permit.expiration, alice, signedPermit);

        (uint256 allowanceBobId1,) = permitC.allowance(alice, bob, TOKEN_TYPE_ERC1155, token, 1);
        assertEq(allowanceBobId1, 0);
    }

    function testSetApprovalViaSignature_ERC1155_UsedNonce() public {
        address token = _deployNew1155(carol, 1, 0);

        _mint1155(token, alice, 1, 100);

        vm.prank(alice);
        ERC1155(token).setApprovalForAll(address(permitC), true);

        assertEq(ERC1155(token).balanceOf(alice, 1), 100);

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
                    TOKEN_TYPE_ERC1155,
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
        permitC.updateApprovalBySignature(TOKEN_TYPE_ERC1155, permit.token, permit.id, permit.nonce, permit.amount, permit.operator, permit.expiration, permit.expiration, alice, signedPermit);

        (uint256 allowanceBobId1,) = permitC.allowance(alice, bob, TOKEN_TYPE_ERC1155, token, 1);
        assertEq(allowanceBobId1, 1);

        vm.prank(bob);
        vm.expectRevert(PermitC__NonceAlreadyUsedOrRevoked.selector);
        permitC.updateApprovalBySignature(TOKEN_TYPE_ERC1155, permit.token, permit.id, permit.nonce, permit.amount, permit.operator, permit.expiration, permit.expiration, alice, signedPermit);

        (allowanceBobId1,) = permitC.allowance(alice, bob, TOKEN_TYPE_ERC1155, token, 1);
        assertEq(allowanceBobId1, 1);
    }

    function testSetApprovalViaSignature_ERC1155_WrongOwnerProvided() public {
        address token = _deployNew1155(carol, 1, 0);

        _mint1155(token, alice, 1, 100);

        vm.prank(alice);
        ERC1155(token).setApprovalForAll(address(permitC), true);

        assertEq(ERC1155(token).balanceOf(alice, 1), 100);

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
                    TOKEN_TYPE_ERC1155,
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
        permitC.updateApprovalBySignature(TOKEN_TYPE_ERC1155, permit.token, permit.id, permit.nonce, permit.amount, permit.operator, permit.expiration, permit.expiration, carol, signedPermit);

        (uint256 allowanceBobId1,) = permitC.allowance(alice, bob, TOKEN_TYPE_ERC1155, token, 1);
        assertEq(allowanceBobId1, 0);
    }

    function testSetApprovalViaSignature_ERC1155_InvalidatedNonce() public {
        address token = _deployNew1155(carol, 1, 0);

        _mint1155(token, alice, 1, 100);

        vm.prank(alice);
        ERC1155(token).setApprovalForAll(address(permitC), true);

        assertEq(ERC1155(token).balanceOf(alice, 1), 100);

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
        permitC.updateApprovalBySignature(TOKEN_TYPE_ERC1155, permit.token, permit.id, permit.nonce, permit.amount, permit.operator, permit.expiration, permit.expiration, alice, signedPermit);

        vm.prank(alice);
        vm.expectRevert(PermitC__NonceAlreadyUsedOrRevoked.selector);
        permitC.invalidateUnorderedNonce(0);

        vm.prank(bob);
        vm.expectRevert(PermitC__NonceAlreadyUsedOrRevoked.selector);
        permitC.updateApprovalBySignature(TOKEN_TYPE_ERC1155, permit.token, permit.id, permit.nonce, permit.amount, permit.operator, permit.expiration, permit.expiration, alice, signedPermit);

        (uint256 allowanceBobId1,) = permitC.allowance(alice, bob, TOKEN_TYPE_ERC1155, token, 1);
        assertEq(allowanceBobId1, 0);
    }

    function testTransferFromWithApprovalOnChain_ERC1155_AllowanceAmountRestoredAfterRevert(uint200 amount) public {
        amount = uint200(bound(amount, 2, type(uint200).max));
        uint200 approveAmount = uint200(amount / 2);
        address token = address(new ERC1155Reverter());

        _mint1155(token, alice, 2, amount);
        _mint1155(token, alice, 3, amount);

        vm.prank(alice);
        ERC1155(token).setApprovalForAll(address(permitC), true);

        vm.startPrank(alice);
        permitC.approve(TOKEN_TYPE_ERC1155, token, 2, bob, approveAmount, uint48(block.timestamp + 1000));
        permitC.approve(TOKEN_TYPE_ERC1155, token, 3, bob, approveAmount, uint48(block.timestamp + 1000));
        vm.stopPrank();

        (uint256 allowanceBobId2,) = permitC.allowance(alice, bob, TOKEN_TYPE_ERC1155, token, 2);
        assertEq(allowanceBobId2, approveAmount);

        vm.startPrank(bob);
        bool isError = permitC.transferFromERC1155(alice, bob, token, 2, approveAmount);
        assertEq(isError, true);

        (allowanceBobId2,) = permitC.allowance(alice, bob, TOKEN_TYPE_ERC1155, token, 2);
        assertEq(allowanceBobId2, approveAmount);
        assertEq(ERC1155Mock(token).balanceOf(alice, 2), amount);
        assertEq(ERC1155Mock(token).balanceOf(bob, 2), 0);
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
