// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import {ECDSA} from "solady/utils/ECDSA.sol";

struct ContractCreatorClaim {
    address creator;
    address contractAddress;
    uint256 timestamp;
    uint256 lifespan;
}

interface Ownable {
    function owner() external view returns (address);
}

contract ContractCreatorClaimRegistry {
    event ClaimAsCreator(
        address indexed creator, address indexed contractAddress
    );
    event RevokeAsCreator(
        address indexed creator, address indexed contractAddress
    );

    error NotOwner();
    error TimestampExpired();
    error TimestampInFuture();
    error InvalidLifespan();
    error InvalidSigner();
    error DigestAlreadyUsed();

    bytes32 public constant CONTRACT_OWNERSHIP_TYPEHASH = keccak256(
        "ContractOwnershipClaim(address creator,address contractAddress,uint256 "
        "timestamp,uint256 lifespan)"
    );
    bytes32 public constant EIP712_DOMAIN_TYPEHASH = keccak256(
        "EIP712Domain(string name,uint256 chainId,address verifyingContract)"
    );
    uint256 public immutable MAX_LIFESPAN;

    bytes32 internal immutable DOMAIN_SEPARATOR;
    uint256 internal immutable DEPLOYED_CHAIN_ID = block.chainid;

    mapping(bytes32 digest => bool claimed) public claimedDigests;

    constructor(uint256 maxLifespan) {
        MAX_LIFESPAN = maxLifespan;
        DEPLOYED_CHAIN_ID = block.chainid;
        DOMAIN_SEPARATOR = deriveDomainSeparator();
    }

    function name() public pure returns (string memory) {
        return "ContractCreatorClaimRegistry";
    }

    function claimAsCreator(
        ContractCreatorClaim calldata claim,
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

    function claimAsCreator(
        ContractCreatorClaim calldata claim,
        bytes32 r,
        bytes32 vs
    ) public {
        // checks
        validateCallFromOwner(claim.contractAddress);
        validateTimestamp(claim.timestamp, claim.lifespan);
        bytes32 digest = validateDigest(claim);
        address claimingCreator = claim.creator;
        validateSignerCompact(claimingCreator, digest, r, vs);
        // effects
        updateDigestAndEmit(claimingCreator, claim.contractAddress, digest);
    }

    function revokeAsCreator(address contractAddress) public {
        emit RevokeAsCreator(msg.sender, contractAddress);
    }

    function domainSeparator() public view returns (bytes32) {
        if (block.chainid != DEPLOYED_CHAIN_ID) {
            return deriveDomainSeparator();
        } else {
            return DOMAIN_SEPARATOR;
        }
    }

    function deriveDigest(ContractCreatorClaim calldata claim)
        public
        view
        returns (bytes32 digest)
    {
        bytes32 claimHash = hashContractOwnershipClaim(claim);
        digest = deriveDigestFromClaimHash(claimHash);
    }

    function validateCallFromOwner(address contractAddress) internal view {
        address contractOwner = Ownable(contractAddress).owner();
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

    function validateDigest(ContractCreatorClaim calldata claim)
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
        address recovered = ECDSA.recover(digest, signature);
        if (recovered != claimingCreator) {
            revert InvalidSigner();
        }
    }

    function validateSignerCompact(
        address claimingCreator,
        bytes32 digest,
        bytes32 r,
        bytes32 vs
    ) internal view {
        address recovered = ECDSA.recover({hash: digest, r: r, vs: vs});
        if (recovered != claimingCreator) {
            revert InvalidSigner();
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

    function hashContractOwnershipClaim(ContractCreatorClaim calldata claim)
        internal
        pure
        returns (bytes32)
    {
        return keccak256(
            abi.encode(
                CONTRACT_OWNERSHIP_TYPEHASH,
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
