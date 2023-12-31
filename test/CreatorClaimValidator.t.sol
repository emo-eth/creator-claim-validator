// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import {Test} from "forge-std/Test.sol";
import {
    CreatorClaimValidator,
    ICreatorClaimValidator,
    CreatorClaim
} from "../src/CreatorClaimValidator.sol";

contract Ownable {
    address public owner;

    constructor(address _owner) {
        owner = _owner;
    }

    function setOwner(address _owner) public {
        owner = _owner;
    }
}

contract CreatorClaimValidatorTest is Test {
    CreatorClaimValidator test;
    Ownable ownable;

    event ClaimAsCreator(
        address indexed owner, address indexed contractAddress
    );
    event RevokeAsCreator(
        address indexed creator, address indexed contractAddress
    );

    function setUp() public {
        test = new CreatorClaimValidator(7 days);
        ownable = new Ownable(address(this));
    }

    function testDomainSeparator(uint64 newChainId) public {
        bool shouldEq = newChainId == this.chainId();
        bytes32 existingDomainSeparator = test.domainSeparator();

        vm.chainId(newChainId);
        bytes32 newDomainSeparator = test.domainSeparator();
        if (shouldEq) {
            assertEq(newDomainSeparator, existingDomainSeparator);
        } else {
            assertNotEq(newDomainSeparator, existingDomainSeparator);
        }
    }

    function chainId() external view returns (uint256) {
        return block.chainid;
    }

    function testClaimOwnership_notFromOwner() public {
        ownable.setOwner(makeAddr("not this"));
        CreatorClaim memory claim = CreatorClaim({
            creator: address(this),
            contractAddress: address(ownable),
            timestamp: block.timestamp,
            lifespan: 0
        });
        vm.expectRevert(ICreatorClaimValidator.NotOwner.selector);
        test.claimAsCreator(claim, new bytes(0));
    }

    function testClaimOwnership_InvalidLifespan(uint64 lifespanDelta) public {
        CreatorClaim memory claim = CreatorClaim({
            creator: address(this),
            contractAddress: address(ownable),
            timestamp: block.timestamp,
            lifespan: test.MAX_LIFESPAN() + 1 + uint256(lifespanDelta)
        });
        vm.expectRevert(ICreatorClaimValidator.InvalidLifespan.selector);
        test.claimAsCreator(claim, new bytes(0));
    }

    function testClaimOwnership_LifespanZeroDefault() public {
        CreatorClaim memory claim = CreatorClaim({
            creator: address(this),
            contractAddress: address(ownable),
            timestamp: block.timestamp,
            lifespan: 0
        });
        vm.warp(block.timestamp + test.MAX_LIFESPAN() + 1);
        vm.expectRevert(ICreatorClaimValidator.TimestampExpired.selector);
        test.claimAsCreator(claim, new bytes(0));
    }

    function testClaimOwnership_TimestampExpired(
        uint256 lifespan,
        uint256 timestamp,
        uint256 timestampLifespanDelta
    ) public {
        lifespan = bound(lifespan, 1, test.MAX_LIFESPAN());
        timestamp = bound(timestamp, 1, 2 ** 64 - 1);
        timestampLifespanDelta = bound(timestampLifespanDelta, 1, 2 ** 64 - 1);
        vm.warp(timestamp + lifespan + timestampLifespanDelta);
        CreatorClaim memory claim = CreatorClaim({
            creator: address(this),
            contractAddress: address(ownable),
            timestamp: timestamp,
            lifespan: lifespan
        });
        vm.expectRevert(ICreatorClaimValidator.TimestampExpired.selector);
        test.claimAsCreator(claim, new bytes(0));
    }

    function testClaimOwnership_TimestampInFuture(
        uint256 currentTimestamp,
        uint256 signatureTimestamp
    ) public {
        currentTimestamp =
            bound(currentTimestamp, test.MAX_LIFESPAN(), 2 ** 64 - 1);
        signatureTimestamp =
            bound(signatureTimestamp, currentTimestamp + 1, 2 ** 256 - 1);

        vm.warp(currentTimestamp);
        CreatorClaim memory claim = CreatorClaim({
            creator: address(this),
            contractAddress: address(ownable),
            timestamp: signatureTimestamp,
            lifespan: test.MAX_LIFESPAN()
        });
        vm.expectRevert(ICreatorClaimValidator.TimestampInFuture.selector);
        test.claimAsCreator(claim, new bytes(0));
    }

    function testClaimOwnership_InvalidSignature() public {
        vm.warp(test.MAX_LIFESPAN());
        Account memory signer = makeAccount("signer");

        CreatorClaim memory claim = CreatorClaim({
            creator: makeAddr("no code"),
            contractAddress: address(ownable),
            timestamp: block.timestamp,
            lifespan: test.MAX_LIFESPAN()
        });
        bytes32 digest = test.deriveDigest(claim);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(signer.key, digest);
        bytes memory signature = abi.encodePacked(r, s, v);

        vm.expectRevert(ICreatorClaimValidator.InvalidSignature.selector);
        test.claimAsCreator(claim, signature);
    }

    function testClaimOwnership() public {
        vm.warp(test.MAX_LIFESPAN());
        Account memory signer = makeAccount("signer");

        CreatorClaim memory claim = CreatorClaim({
            creator: signer.addr,
            contractAddress: address(ownable),
            timestamp: block.timestamp,
            lifespan: test.MAX_LIFESPAN()
        });
        bytes32 digest = test.deriveDigest(claim);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(signer.key, digest);
        bytes memory signature = abi.encodePacked(r, s, v);
        vm.expectEmit(true, true, false, false, address(test));
        emit ClaimAsCreator(signer.addr, address(ownable));
        test.claimAsCreator(claim, signature);
    }

    function testClaimOwnership_DigestAlreadyUsed() public {
        vm.warp(test.MAX_LIFESPAN());
        Account memory signer = makeAccount("signer");

        CreatorClaim memory claim = CreatorClaim({
            creator: signer.addr,
            contractAddress: address(ownable),
            timestamp: block.timestamp,
            lifespan: test.MAX_LIFESPAN()
        });
        bytes32 digest = test.deriveDigest(claim);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(signer.key, digest);
        bytes memory signature = abi.encodePacked(r, s, v);

        vm.expectEmit(true, true, false, false, address(test));
        emit ClaimAsCreator(signer.addr, address(ownable));
        test.claimAsCreator(claim, signature);
        vm.expectRevert(ICreatorClaimValidator.DigestAlreadyUsed.selector);
        test.claimAsCreator(claim, signature);
    }

    function testClaimOwnership_2098Compact() public {
        vm.warp(test.MAX_LIFESPAN());
        Account memory signer = makeAccount("signer");

        CreatorClaim memory claim = CreatorClaim({
            creator: signer.addr,
            contractAddress: address(ownable),
            timestamp: block.timestamp,
            lifespan: test.MAX_LIFESPAN()
        });
        bytes32 digest = test.deriveDigest(claim);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(signer.key, digest);
        bytes32 vs = bytes32(uint256(((v == 28) ? 1 : 0)) << 255 | uint256(s));
        vm.expectEmit(true, true, false, false, address(test));
        emit ClaimAsCreator(signer.addr, address(ownable));
        test.claimAsCreator(claim, r, vs);
    }

    function testClaimOwnership_2098Compact_InvalidSignature() public {
        vm.warp(test.MAX_LIFESPAN());
        Account memory signer = makeAccount("signer");

        CreatorClaim memory claim = CreatorClaim({
            creator: address(this),
            contractAddress: address(ownable),
            timestamp: block.timestamp,
            lifespan: test.MAX_LIFESPAN()
        });
        bytes32 digest = test.deriveDigest(claim);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(signer.key, digest);
        bytes32 vs = bytes32(uint256(((v == 28) ? 1 : 0)) << 255 | uint256(s));
        vm.expectRevert(ICreatorClaimValidator.InvalidSignature.selector);
        test.claimAsCreator(claim, r, vs);
    }

    function testClaimOwnership_2098Compact_NonMalleable() public {
        vm.warp(test.MAX_LIFESPAN());
        Account memory signer = makeAccount("signer");

        CreatorClaim memory claim = CreatorClaim({
            creator: signer.addr,
            contractAddress: address(ownable),
            timestamp: block.timestamp,
            lifespan: test.MAX_LIFESPAN()
        });
        bytes32 digest = test.deriveDigest(claim);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(signer.key, digest);
        bytes32 vs = bytes32(uint256(((v == 28) ? 1 : 0)) << 255 | uint256(s));
        bytes memory signature = abi.encodePacked(r, s, v);
        vm.expectEmit(true, true, false, false, address(test));
        emit ClaimAsCreator(signer.addr, address(ownable));
        test.claimAsCreator(claim, r, vs);
        vm.expectRevert(ICreatorClaimValidator.DigestAlreadyUsed.selector);
        test.claimAsCreator(claim, signature);
    }

    function testRevokeAsCreator(address caller, address target) public {
        vm.expectEmit(true, true, false, false, address(test));
        emit RevokeAsCreator(caller, target);
        vm.prank(caller);
        test.revokeAsCreator(target);
    }

    function testClaimSelfAsOwner_NotOwner() public {
        ownable.setOwner(makeAddr("not this"));
        vm.expectRevert(ICreatorClaimValidator.NotOwner.selector);
        test.claimSelfAsCreator(address(ownable));
    }

    function testClaimSelfAsOwner() public {
        vm.expectEmit(true, true, false, false, address(test));
        emit ClaimAsCreator(address(this), address(ownable));
        test.claimSelfAsCreator(address(ownable));
    }
}
