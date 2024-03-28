pragma solidity ^0.8.9;

import "forge-std/StdCheats.sol";
import "forge-std/StdAssertions.sol";
import "forge-std/StdUtils.sol";
import {TestBase} from "forge-std/Base.sol";

import "src/PermitC.sol";

import "./mocks/ERC721Mock.sol";
import "./mocks/ERC1155Mock.sol";
import "./mocks/ERC20Mock.sol";

import "forge-std/console.sol";

contract BaseTest is TestBase, StdAssertions, StdCheats, StdUtils {
    event Approval(
        address indexed owner,
        address indexed token,
        address indexed operator,
        uint256 id,
        uint200 amount,
        uint48 expiration
    );
    event Lockdown(address indexed owner);

    PermitC permitC;

    uint256 adminKey;
    uint256 aliceKey;
    uint256 bobKey;
    uint256 carolKey;

    address admin;
    address alice;
    address bob;
    address carol;

    function setUp() public virtual {
        permitC = new PermitC("PermitC", "1");

        (admin, adminKey) = makeAddrAndKey("admin");
        (alice, aliceKey) = makeAddrAndKey("alice");
        (bob, bobKey) = makeAddrAndKey("bob");
        (carol, carolKey) = makeAddrAndKey("carol");

        // Warp to a more realistic timestamp
        vm.warp(1703688340);
    }

    function _deployNew721(address creator, uint256 amountToMint) internal virtual returns (address) {
        vm.startPrank(creator);
        address token = address(new ERC721Mock());
        ERC721Mock(token).mint(creator, amountToMint);
        changePrank(admin);
        return token;
    }

    function _deployNew1155(address creator, uint256 idToMint, uint256 amountToMint)
        internal
        virtual
        returns (address)
    {
        vm.startPrank(creator);
        address token = address(new ERC1155Mock());
        ERC1155Mock(token).mint(creator, idToMint, amountToMint);
        changePrank(admin);
        return token;
    }

    function _deployNew20(address creator, uint256 amountToMint) internal virtual returns (address) {
        vm.startPrank(creator);
        address token = address(new ERC20Mock());
        ERC20Mock(token).mint(creator, amountToMint);
        changePrank(admin);
        return token;
    }

    function _mint721(address tokenAddress, address to, uint256 tokenId) internal virtual {
        ERC721Mock(tokenAddress).mint(to, tokenId);
    }

    function _mint20(address tokenAddress, address to, uint256 amount) internal virtual {
        ERC20Mock(tokenAddress).mint(to, amount);
    }

    function _mint1155(address tokenAddress, address to, uint256 tokenId, uint256 amount) internal virtual {
        ERC1155Mock(tokenAddress).mint(to, tokenId, amount);
    }

    function changePrank(address msgSender) internal virtual override {
        vm.stopPrank();
        vm.startPrank(msgSender);
    }
}
