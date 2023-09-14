// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import {Test, console2} from "forge-std/Test.sol";
import {
    ContractCreatorClaimRegistry,
    ContractCreatorClaim
} from "../src/ContractCreatorClaimRegistry.sol";
import {ECDSA} from "solady/utils/ECDSA.sol";

contract Ownable {
    address public owner;

    constructor(address _owner) {
        owner = _owner;
    }

    function setOwner(address _owner) public {
        owner = _owner;
    }
}

contract ContractCreatorClaimRegistryTest is Test {
    ContractCreatorClaimRegistry test;
    Ownable ownable;

    event ClaimAsCreator(
        address indexed owner, address indexed contractAddress
    );
    event RevokeAsCreator(
        address indexed creator, address indexed contractAddress
    );

    function setUp() public {
        test = new ContractCreatorClaimRegistry(7 days);
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
        ContractCreatorClaim memory claim = ContractCreatorClaim({
            creator: address(this),
            contractAddress: address(ownable),
            timestamp: block.timestamp,
            lifespan: 0
        });
        vm.expectRevert(ContractCreatorClaimRegistry.NotOwner.selector);
        test.claimAsCreator(claim, new bytes(0));
    }

    function testClaimOwnership_InvalidLifespan(uint64 lifespanDelta) public {
        ContractCreatorClaim memory claim = ContractCreatorClaim({
            creator: address(this),
            contractAddress: address(ownable),
            timestamp: block.timestamp,
            lifespan: test.MAX_LIFESPAN() + 1 + uint256(lifespanDelta)
        });
        vm.expectRevert(ContractCreatorClaimRegistry.InvalidLifespan.selector);
        test.claimAsCreator(claim, new bytes(0));
    }

    function testClaimOwnership_LifespanZeroDefault() public {
        ContractCreatorClaim memory claim = ContractCreatorClaim({
            creator: address(this),
            contractAddress: address(ownable),
            timestamp: block.timestamp,
            lifespan: 0
        });
        vm.warp(block.timestamp + test.MAX_LIFESPAN() + 1);
        vm.expectRevert(ContractCreatorClaimRegistry.TimestampExpired.selector);
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
        ContractCreatorClaim memory claim = ContractCreatorClaim({
            creator: address(this),
            contractAddress: address(ownable),
            timestamp: timestamp,
            lifespan: lifespan
        });
        vm.expectRevert(ContractCreatorClaimRegistry.TimestampExpired.selector);
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
        ContractCreatorClaim memory claim = ContractCreatorClaim({
            creator: address(this),
            contractAddress: address(ownable),
            timestamp: signatureTimestamp,
            lifespan: test.MAX_LIFESPAN()
        });
        vm.expectRevert(ContractCreatorClaimRegistry.TimestampInFuture.selector);
        test.claimAsCreator(claim, new bytes(0));
    }

    function testClaimOwnership_InvalidSigner() public {
        vm.warp(test.MAX_LIFESPAN());
        Account memory signer = makeAccount("signer");

        ContractCreatorClaim memory claim = ContractCreatorClaim({
            creator: address(this),
            contractAddress: address(ownable),
            timestamp: block.timestamp,
            lifespan: test.MAX_LIFESPAN()
        });
        bytes32 digest = test.deriveDigest(claim);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(signer.key, digest);
        bytes memory signature = abi.encodePacked(r, s, v);

        vm.expectRevert(ContractCreatorClaimRegistry.InvalidSigner.selector);
        test.claimAsCreator(claim, signature);
    }

    function testClaimOwnership() public {
        vm.warp(test.MAX_LIFESPAN());
        Account memory signer = makeAccount("signer");

        ContractCreatorClaim memory claim = ContractCreatorClaim({
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

        ContractCreatorClaim memory claim = ContractCreatorClaim({
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
        vm.expectRevert(ContractCreatorClaimRegistry.DigestAlreadyUsed.selector);
        test.claimAsCreator(claim, signature);
    }

    function testClaimOwnership_2098Compact() public {
        vm.warp(test.MAX_LIFESPAN());
        Account memory signer = makeAccount("signer");

        ContractCreatorClaim memory claim = ContractCreatorClaim({
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

    function testClaimOwnership_2098Compact_InvalidSigner() public {
        vm.warp(test.MAX_LIFESPAN());
        Account memory signer = makeAccount("signer");

        ContractCreatorClaim memory claim = ContractCreatorClaim({
            creator: address(this),
            contractAddress: address(ownable),
            timestamp: block.timestamp,
            lifespan: test.MAX_LIFESPAN()
        });
        bytes32 digest = test.deriveDigest(claim);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(signer.key, digest);
        bytes32 vs = bytes32(uint256(((v == 28) ? 1 : 0)) << 255 | uint256(s));
        vm.expectRevert(ContractCreatorClaimRegistry.InvalidSigner.selector);
        test.claimAsCreator(claim, r, vs);
    }

    function testClaimOwnership_2098Compact_NonMalleable() public {
        vm.warp(test.MAX_LIFESPAN());
        Account memory signer = makeAccount("signer");

        ContractCreatorClaim memory claim = ContractCreatorClaim({
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
        vm.expectRevert(ContractCreatorClaimRegistry.DigestAlreadyUsed.selector);
        test.claimAsCreator(claim, signature);
    }

    function testRevokeAsCreator(address caller, address target) public {
        vm.expectEmit(true, true, false, false, address(test));
        emit RevokeAsCreator(caller, target);
        vm.prank(caller);
        test.revokeAsCreator(target);
    }

    // function testFuzz_SetNumber(uint256 x) public {}
}
