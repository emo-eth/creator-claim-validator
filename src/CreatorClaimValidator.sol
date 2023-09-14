// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import {ECDSA} from "solady/utils/ECDSA.sol";
import {IERC1271} from "./interfaces/IERC1271.sol";
import {IOwnable} from "./interfaces/IOwnable.sol";

import {
    ICreatorClaimValidator,
    CreatorClaim
} from "./interfaces/ICreatorClaimValidator.sol";

contract CreatorClaimValidator is ICreatorClaimValidator {
    /**
     * @inheritdoc ICreatorClaimValidator
     */
    bytes32 public constant CREATOR_CLAIM_TYPEHASH = keccak256(
        "CreatorClaim(address creator,address contractAddress,uint256 "
        "timestamp,uint256 lifespan)"
    );
    /**
     * @inheritdoc ICreatorClaimValidator
     */
    bytes32 public constant EIP712_DOMAIN_TYPEHASH = keccak256(
        "EIP712Domain(string name,uint256 chainId,address verifyingContract)"
    );
    /**
     * @inheritdoc ICreatorClaimValidator
     */
    uint256 public immutable MAX_LIFESPAN;

    bytes4 internal constant ERC1271_MAGIC_VALUE = 0x1626ba7e;

    bytes32 internal immutable DOMAIN_SEPARATOR;
    uint256 internal immutable DEPLOYED_CHAIN_ID = block.chainid;

    mapping(bytes32 digest => bool claimed) internal claimedDigests;

    constructor(uint256 maxLifespan) {
        MAX_LIFESPAN = maxLifespan;
        DEPLOYED_CHAIN_ID = block.chainid;
        DOMAIN_SEPARATOR = deriveDomainSeparator();
    }

    /**
     * @inheritdoc ICreatorClaimValidator
     */
    function name() public pure returns (string memory) {
        return "ContractCreatorClaimValidator";
    }

    /**
     * @inheritdoc ICreatorClaimValidator
     */
    function claimSelfAsCreator(address contractAddress) public {
        validateCallFromOwner(contractAddress);
        emit ClaimAsCreator(msg.sender, contractAddress);
    }

    /**
     * @inheritdoc ICreatorClaimValidator
     */
    function claimAsCreator(
        CreatorClaim calldata claim,
        bytes calldata signature
    ) public {
        // checks
        validateCallFromOwner(claim.contractAddress);
        validateTimestamp(claim.timestamp, claim.lifespan);
        bytes32 digest = validateDigest(claim);
        address claimingCreator = claim.creator;
        validateSigner(claimingCreator, digest, signature);
        // effects
        updateDigestAndEmit(claimingCreator, claim.contractAddress, digest);
    }

    /**
     * @inheritdoc ICreatorClaimValidator
     */
    function claimAsCreator(CreatorClaim calldata claim, bytes32 r, bytes32 vs)
        public
    {
        // checks
        validateCallFromOwner(claim.contractAddress);
        validateTimestamp(claim.timestamp, claim.lifespan);
        bytes32 digest = validateDigest(claim);
        address claimingCreator = claim.creator;
        validateSignerCompact(claimingCreator, digest, r, vs);
        // effects
        updateDigestAndEmit(claimingCreator, claim.contractAddress, digest);
    }

    /**
     * @inheritdoc ICreatorClaimValidator
     */
    function revokeAsCreator(address contractAddress) public {
        emit RevokeAsCreator(msg.sender, contractAddress);
    }

    /**
     * @inheritdoc ICreatorClaimValidator
     */
    function domainSeparator() public view returns (bytes32) {
        if (block.chainid != DEPLOYED_CHAIN_ID) {
            return deriveDomainSeparator();
        } else {
            return DOMAIN_SEPARATOR;
        }
    }

    /**
     * @inheritdoc ICreatorClaimValidator
     */
    function deriveDigest(CreatorClaim calldata claim)
        public
        view
        returns (bytes32 digest)
    {
        bytes32 claimHash = hashContractOwnershipClaim(claim);
        digest = deriveDigestFromClaimHash(claimHash);
    }

    function validateCallFromOwner(address contractAddress) internal view {
        address contractOwner = IOwnable(contractAddress).owner();
        // only the contract owner can submit a claim, but the claim may be for
        // any address, as long as the signature is valid
        if (msg.sender != contractOwner) {
            revert NotOwner();
        }
    }

    function validateTimestamp(uint256 timestamp, uint256 lifespan)
        internal
        view
    {
        if (lifespan == 0) {
            lifespan = MAX_LIFESPAN;
        }
        if (lifespan > MAX_LIFESPAN) {
            revert InvalidLifespan();
        } else if (timestamp < block.timestamp - lifespan) {
            revert TimestampExpired();
        } else if (timestamp > block.timestamp) {
            revert TimestampInFuture();
        }
    }

    function validateDigest(CreatorClaim calldata claim)
        internal
        view
        returns (bytes32)
    {
        bytes32 digest = deriveDigest(claim);
        if (claimedDigests[digest]) {
            revert DigestAlreadyUsed();
        }
        return digest;
    }

    function validateSigner(
        address claimingCreator,
        bytes32 digest,
        bytes calldata signature
    ) internal view {
        // try to recover with ECDSA first if normal signature length

        if (signature.length == 65) {
            address recovered =
                ECDSA.recover({hash: digest, signature: signature});
            if (recovered == claimingCreator) {
                return;
            }
        }
        // if not normal signature length, try ERC1271
        // compact signatures should use other method
        if (claimingCreator.code.length != 0) {
            // otherwise try ERC1271
            if (!tryERC1271(claimingCreator, digest, signature)) {
                revert InvalidSignature();
            }
        } else {
            revert InvalidSignature();
        }
    }

    function tryERC1271(
        address claimingCreator,
        bytes32 digest,
        bytes calldata signature
    ) internal view returns (bool) {
        return IERC1271(claimingCreator).isValidSignature(digest, signature)
            == ERC1271_MAGIC_VALUE;
    }

    function validateSignerCompact(
        address claimingCreator,
        bytes32 digest,
        bytes32 r,
        bytes32 vs
    ) internal view {
        address recovered = ECDSA.recover({hash: digest, r: r, vs: vs});
        if (recovered != claimingCreator) {
            revert InvalidSignature();
        }
    }

    function updateDigestAndEmit(
        address claimingCreator,
        address contractAddress,
        bytes32 digest
    ) internal {
        claimedDigests[digest] = true;
        emit ClaimAsCreator(claimingCreator, contractAddress);
    }

    function deriveDigestFromClaimHash(bytes32 claimHash)
        internal
        view
        returns (bytes32 digest)
    {
        digest = keccak256(
            abi.encodePacked("\x19\x01", domainSeparator(), claimHash)
        );
    }

    function hashContractOwnershipClaim(CreatorClaim calldata claim)
        internal
        pure
        returns (bytes32)
    {
        return keccak256(
            abi.encode(
                CREATOR_CLAIM_TYPEHASH,
                claim.creator,
                claim.contractAddress,
                claim.timestamp,
                claim.lifespan
            )
        );
    }

    function deriveDomainSeparator() internal view returns (bytes32) {
        return keccak256(
            abi.encode(
                EIP712_DOMAIN_TYPEHASH,
                keccak256(bytes(name())),
                block.chainid,
                address(this)
            )
        );
    }
}
