// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

struct CreatorClaim {
    ///@notice the account claiming ownership of the contract
    address creator;
    ///@notice the contract address to claim ownership of
    address contractAddress;
    ///@notice the timestamp from which this claim is valid
    uint256 timestamp;
    ///@notice the lifespan of this claim. If 0 is specified, defaults
    ///        to MAX_LIFESPAN
    uint256 lifespan;
}

interface ICreatorClaimValidator {
    ///@notice emitted when a signed claim is submitted
    event ClaimAsCreator(
        address indexed creator, address indexed contractAddress
    );
    ///@notice emitted when revokeAsCreator is called.
    event RevokeAsCreator(
        address indexed creator, address indexed contractAddress
    );

    error NotOwner();
    error TimestampExpired();
    error TimestampInFuture();
    error InvalidLifespan();
    error DigestAlreadyUsed();
    error InvalidSignature();

    /**
     * @notice The EIP712 typehash for the CreatorClaim struct
     */
    function CREATOR_CLAIM_TYPEHASH() external view returns (bytes32);
    /**
     * @notice The EIP712 domain typehash for this contract
     */
    function EIP712_DOMAIN_TYPEHASH() external view returns (bytes32);
    /**
     * @notice The maximum lifespan of a claim in seconds
     */
    function MAX_LIFESPAN() external view returns (uint256);

    /**
     * @notice Submit a claim as the "creator" of a contract.
     *         The caller must be the owner of the contract, but may submit a
     *         claim on behalf of any address. The claim and  the signature must
     *         both be valid.
     * @param claim The claim struct
     * @param signature The signature
     */
    function claimAsCreator(
        CreatorClaim calldata claim,
        bytes calldata signature
    ) external;

    /**
     * @notice Submit a claim as the "creator" of a contract using a compact
     *         signature.  The caller must  be the owner of the contract,
     *         but may submit a claim on behalf of any address. The claim and
     *         the signature must both be valid. Note that only  EOAs can
     *         produce compact signatures. Smart contract wallets must use
     *         the other claimAsCreator function.
     * @param claim The claim struct
     * @param r The r component of the signature
     * @param vs The s and v components of the signature
     */
    function claimAsCreator(CreatorClaim calldata claim, bytes32 r, bytes32 vs)
        external;

    /**
     * @notice Emit an event to revoke a creator role for a contract. Performs
     *         no checks, and is callable by anyone. Indexers must decide
     *         if the emitted event is useful.
     */
    function revokeAsCreator(address contractAddress) external;

    /**
     * @notice The name of this contract, used by EIP712
     */
    function name() external pure returns (string memory);

    /**
     * @notice Get or derive the EIP712 domain separator for this contract.
     */
    function domainSeparator() external view returns (bytes32);

    /**
     * @notice Helper method to derive a digest from a claim struct
     * @param claim The claim struct
     */
    function deriveDigest(CreatorClaim calldata claim)
        external
        view
        returns (bytes32 digest);
}
