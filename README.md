# CreatorClaimRegistry

Inspired by [ERC-7015](https://eips.ethereum.org/EIPS/eip-7015), allows owners of smart contracts to emit an event that associates the contract with a "creator." This allows signature-based "creator" verification to work with existing smart contracts that do not implement ERC-7015.

`CreatorClaimRegistry.claimAsCreator` takes a `struct CreatorClaim` and a `bytes signature` to validate that the account claimed as the owner is the actual owner of the contract.

Only the owner of the contract can call `CreatorClaimRegistry.claimAsCreator`, but the owner may submit a claim on behalf of any account, provided they have a valid signature.
