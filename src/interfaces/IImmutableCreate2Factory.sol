pragma solidity 0.8.19;


/**
 * @title Immutable Create2 Contract Factory
 * @author 0age
 * @notice This contract provides a safeCreate2 function that takes a salt value
 * and a block of initialization code as arguments and passes them into inline
 * assembly. The contract prevents redeploys by maintaining a mapping of all
 * contracts that have already been deployed, and prevents frontrunning or other
 * collisions by requiring that the first 20 bytes of the salt are equal to the
 * address of the caller (this can be bypassed by setting the first 20 bytes to
 * the null address). There is also a view function that computes the address of
 * the contract that will be created when submitting a given salt or nonce along
 * with a given block of initialization code.
 * @dev This contract has not yet been fully tested or audited - proceed with
 * caution and please share any exploits or optimizations you discover.
 */
interface IImmutableCreate2Factory {

  function safeCreate2(bytes32 salt, bytes calldata initializationCode) external payable returns (address deploymentAddress);

  function findCreate2Address(bytes32 salt, bytes calldata initCode) external view returns (address deploymentAddress);

  function findCreate2AddressViaHash(bytes32 salt, bytes32 initCodeHash) external view returns (address deploymentAddress);

  function hasBeenDeployed(address deploymentAddress) external view returns (bool);
}