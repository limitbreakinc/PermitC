// SPDX-License-Identifier: MIT

pragma solidity ^0.8.9;

contract ERC1271InvalidContractSignerMock {
    // bytes4(keccak256("isValidSignature(bytes32,bytes)")
    bytes4 internal constant MAGICVALUE = 0x1626ba7e;

    /**
     * @dev Should return whether the signature provided is valid for the provided hash
     *
     * MUST return the bytes4 magic value 0x1626ba7e when function passes.
     * MUST NOT modify state (using STATICCALL for solc < 0.5, view modifier for solc > 0.5)
     * MUST allow external calls
     */
    function isValidSignature(bytes32, /*_hash*/ bytes memory /*_signature*/ )
        public
        pure
        returns (bytes4 magicValue)
    {
        return 0x00000000;
    }
}
