## PermitC

**Advanced approval system for ERC20, ERC721 and ERC1155**

PermitC extends the Uniswap Permit2 system for ERC20, ERC721 and ERC1155 tokens. This is an advanced approval system which allows for easier and more secure approvals across applications. Abstracting the approval process and adding in expirations allows users to be more insulated from the advanced logic of protocols which are more likely to be exploited.


To learn more about the system this is modeled after visit the [permit2 github](https://github.com/Uniswap/permit2) and the great explainer on approval abstraction [here](https://github.com/dragonfly-xyz/useful-solidity-patterns/tree/main/patterns/permit2).

## Features
- **Time Bound Approvals:** Approvals via PermitC include an expiration timestamp, allowing for an approval to be only set for a specific period of time.  If it’s used past the expiration timestamp, it will be invalid.
- **One Click Approval Revoke:** To quickly revoke all approvals, you can call a single function `lockdown` which will invalidate all outstanding approvals.
- **Signature Based Approvals:** Signatures can be provided for operators to increase approval on chain for multi-use approvals, or permit transfer for one off signatures.
- **Additional Data Validation:** Signatures can use the `permitTransferFromWithAdditionalData` calls to append additional validation logic, such as approving only a specific order or set of orders without opening approvals to other functions on the operator contract.
- **Unordered Execution:** Nonces retain the same functionality as Permit2, meaning they can be approved and executed in any order and prevent replay.
- **Order Based Approvals:** Reusable signatures scoped to a specific order ID to allow for partial trades / fills allowing for gasless outstanding orders to be leveraged.  Useful in ERC1155 sales and ERC20 limit orders.


## Usage
PermitC is designed to be directly queried in your contracts, and acts as an intermediary between the user and the protocol. An example implementation would be:

```
pragma solidity ^0.8.4;

import {SignatureECDSA} from "@permitC/DataTypes.sol";
import "@permitC/interfaces/IPermitC.sol";

contract ExampleContract {

    // ... constructuor logic ...

    function executeOrder(OrderDetails details, uint256 permitNonce, uint48 permitExpiration, uint8 v, bytes32 r, bytes32 s) public {
        // ... order validation and execution ...

        SignatureECDSA signedPermit = ({v: v, r: r, s: s});
        permitC.permitTransferFromERC721(details.token, details.id, permitNonce, permitExpiration,  details.from, details.to signedPermit);

        // ... post transfer logic ...
    }
}
```

## Backwards Compatability
To implement PermitC with an existing protocol, a router contract would need to be launched which can act as the middleware for PermitC and the destination protocol. An example workflow is:

1. Protocol develops a router which acts as a proxy between PermitC and the base protocol. This router takes a permit signature to transfer a token from the user to itself, then acts on behalf of the user.
2. User sets base approval on PermitC - this abstracts the approvals from protocols and will only transfer tokens if valid signed messages are provided.
3. User signs a message with `permitTransferWithAdditionalData` including details on their transaction.
4. Router executes transaction and returns output to user


## Deployment
PermitC is designed to be deployable by anyone to any EVM chain at a deterministic address to match all other chains. We have simplified this process into a shell script which will check for all dependencies, deploy them if they do not exist and then deploy PermitC. Follow the below steps to complete deployment:

1. Fund a personal account.  We'll be potentially deploying 4 contracts, so make sure to have sufficient ETH (or chain equivalent native funds) to cover the expenses.
2. Run the command `cp example.env.secrets .env.secrets`
3. Fill in the RPC for the chain you're deploying to, the private and public key for the address you funded and the ETHERSCAN_API_KEY if applicable.
4. Run the command `./script/1-deploy-deterministic-PermitC.sh --gas-price {} --priority-gas-price {}` - NOTE: gas price and priority gas price are in human readble numbers, they are converted to the correct units within the script.
5. Confirm the input is as expected on your terminal and type `yes` to deploy.