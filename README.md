# CreatorClaimRegistry

Allows owners of smart contracts to emit an event that associates the contract with a "creator."

`CreatorClaimRegistry.claimAsCreator` takes a `struct CreatorClaim` and a `bytes signature` to validate that the account claimed as the owner is the actual owner of the contract.

Only the owner of the contract can call `CreatorClaimRegistry.claimAsCreator`, but the owner may submit a claim on behalf of any account, provided they have a valid signature.
