# CreatorClaimValidator

Inspired by [ERC-7015](https://eips.ethereum.org/EIPS/eip-7015), CreatorClaimValidator allows owners of smart contracts to emit an event that associates the contract with a "creator." This allows backwards compatibility for existing smart contracts for "owners" to actively affirm their ownership of a smart contract, and for signature-based "creator" verification for accounts that are not the literal `owner` of the contract.

`CreatorClaimValidator.claimSelfAsCreator` takes an `address contractAddress` parameter and emits a `CreatorClaimed` event with the `msg.sender` as the "creator" of the contract if the `msg.sender` is the `owner` of the contract.

`CreatorClaimValidator.claimAsCreator` takes a `struct CreatorClaim` and a `bytes signature` to validate that the account claimed as the "creator" has actively consented to being designated as such, by providing their signature.

Only the owner of the contract can call `CreatorClaimValidator.claimAsCreator`, but the `owner` may submit a claim on behalf of any account, provided they have a valid signature.
