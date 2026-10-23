// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import "forge-std/Test.sol";
import "../src/ComplianceRegistry.sol";
import "../src/IComplianceRegistry.sol";

contract ComplianceRegistryTest is Test {
    ComplianceRegistry public registry;

    address public owner = address(0xAAAA);
    address public user1 = address(0x1111);
    address public user2 = address(0x2222);
    address public sanctionedUser = address(0x9999);
    address public dummyRouter = address(0xDEADBEEF);
    bytes32 public donId = bytes32("fun-ethereum-sepolia-1");
    uint64 public subscriptionId = 1234;
    string public jsSource = "return Functions.encodeString('ok');";

    event EligibilityUpdated(address indexed account, bool isEligible, string providerOrReason);
    event EligibilityRevoked(address indexed account, string reason);
    event ProviderConfigUpdated(string provider, bool enabled);

    function setUp() public {
        // Mock chain id to Anvil 31337 for mockFulfill testing
        vm.chainId(31337);

        vm.prank(owner);
        registry = new ComplianceRegistry(
            dummyRouter,
            donId,
            subscriptionId,
            jsSource
        );
    }

    function test_InitialState() public view {
        assertEq(registry.owner(), owner);
        assertEq(registry.donId(), donId);
        assertEq(registry.subscriptionId(), subscriptionId);
        assertEq(registry.callbackGasLimit(), 300_000);
        assertEq(registry.jsSource(), jsSource);

        // Check blocked countries: 408 (North Korea), 792 (Turkey), 104 (Myanmar)
        assertTrue(registry.isBlockedCountry(408));
        assertTrue(registry.isBlockedCountry(792));
        assertTrue(registry.isBlockedCountry(104));
        assertFalse(registry.isBlockedCountry(840)); // USA not blocked by default

        // Check supported providers
        assertTrue(registry.isSupportedProvider("POLYGON_ID"));
        assertTrue(registry.isSupportedProvider("WORLD_ID"));
        assertTrue(registry.isSupportedProvider("EXCHANGE_KYC"));
        assertFalse(registry.isSupportedProvider("UNREGISTERED_VASP"));
    }

    function test_OwnerConfig() public {
        address newOwner = address(0xBBBB);

        // Non-owner cannot update owner
        vm.prank(user1);
        vm.expectRevert(ComplianceRegistry.Unauthorized.selector);
        registry.setOwner(newOwner);

        // Owner can update
        vm.prank(owner);
        registry.setOwner(newOwner);
        assertEq(registry.owner(), newOwner);

        // Update DON ID and subscription ID
        vm.prank(newOwner);
        registry.setDonId(bytes32("new-don-id"));
        assertEq(registry.donId(), bytes32("new-don-id"));

        vm.prank(newOwner);
        registry.setSubscriptionId(5678);
        assertEq(registry.subscriptionId(), 5678);

        vm.prank(newOwner);
        registry.setCallbackGasLimit(400_000);
        assertEq(registry.callbackGasLimit(), 400_000);
    }

    function test_CountryBlocklistManagement() public {
        uint16 testCountryCode = 500;
        assertFalse(registry.isBlockedCountry(testCountryCode));

        // Owner adds country to blocklist
        vm.prank(owner);
        registry.setCountryBlocked(testCountryCode, true);
        assertTrue(registry.isBlockedCountry(testCountryCode));

        // Owner removes country
        vm.prank(owner);
        registry.setCountryBlocked(testCountryCode, false);
        assertFalse(registry.isBlockedCountry(testCountryCode));

        // Non-owner revert
        vm.prank(user1);
        vm.expectRevert(ComplianceRegistry.Unauthorized.selector);
        registry.setCountryBlocked(testCountryCode, true);
    }

    function test_SupportedProviderManagement() public {
        string memory customProvider = "CITIZEN_ID";
        assertFalse(registry.isSupportedProvider(customProvider));

        // Owner enables provider
        vm.prank(owner);
        registry.setSupportedProvider(customProvider, true);
        assertTrue(registry.isSupportedProvider(customProvider));

        // Owner disables provider
        vm.prank(owner);
        registry.setSupportedProvider(customProvider, false);
        assertFalse(registry.isSupportedProvider(customProvider));

        // Non-owner revert
        vm.prank(user1);
        vm.expectRevert(ComplianceRegistry.Unauthorized.selector);
        registry.setSupportedProvider(customProvider, true);
    }

    function test_MockFulfill_Eligible() public {
        assertFalse(registry.isEligible(user1));

        // Fulfill compliance verification for user1 (Country: 840 USA, Provider: POLYGON_ID)
        vm.prank(owner);
        registry.mockFulfill(user1, true, 840, "POLYGON_ID");

        assertTrue(registry.isEligible(user1));

        IComplianceRegistry.IdentityRecord memory record = registry.getIdentityRecord(user1);
        assertTrue(record.isEligible);
        assertEq(record.nationalityCountryCode, 840);
        assertEq(record.provider, "POLYGON_ID");
        assertEq(record.verifiedAt, block.timestamp);
        assertEq(record.expiresAt, block.timestamp + 365 days);
    }

    function test_MockFulfill_BlockedCountryOverridesEligible() public {
        // Attempt to fulfill as eligible for a blocked country (408 PRK)
        vm.prank(owner);
        registry.mockFulfill(user1, true, 408, "WORLD_ID");

        // Fail-closed enforcement: country blocklist overrides provider eligibility
        assertFalse(registry.isEligible(user1));

        IComplianceRegistry.IdentityRecord memory record = registry.getIdentityRecord(user1);
        assertFalse(record.isEligible);
        assertEq(record.nationalityCountryCode, 408);
    }

    function test_MockFulfill_UnsupportedProviderReverts() public {
        vm.prank(owner);
        vm.expectRevert(abi.encodeWithSelector(ComplianceRegistry.UnsupportedProvider.selector, "SHADY_KYC"));
        registry.mockFulfill(user1, true, 840, "SHADY_KYC");
    }

    function test_MockFulfill_DisabledOnLiveNetwork() public {
        // Simulate Ethereum Mainnet (Chain ID 1)
        vm.chainId(1);

        vm.prank(owner);
        vm.expectRevert(ComplianceRegistry.MockDisabledOnLiveNetwork.selector);
        registry.mockFulfill(user1, true, 840, "POLYGON_ID");
    }

    function test_Revocation() public {
        // Verify user1 first
        vm.prank(owner);
        registry.mockFulfill(user1, true, 840, "EXCHANGE_KYC");
        assertTrue(registry.isEligible(user1));

        // Owner revokes compliance
        vm.prank(owner);
        registry.revoke(user1, "OFAC SDN sanction designation");

        assertFalse(registry.isEligible(user1));

        IComplianceRegistry.IdentityRecord memory record = registry.getIdentityRecord(user1);
        assertFalse(record.isEligible);

        // Non-owner cannot revoke
        vm.prank(user2);
        vm.expectRevert(ComplianceRegistry.Unauthorized.selector);
        registry.revoke(user1, "Unauthorized revoke attempt");
    }

    function test_ExpirationTimeDecay() public {
        vm.prank(owner);
        registry.mockFulfill(user1, true, 840, "POLYGON_ID");
        assertTrue(registry.isEligible(user1));

        // Advance time by 364 days (still active)
        vm.warp(block.timestamp + 364 days);
        assertTrue(registry.isEligible(user1));

        // Advance time past 365 days (expired)
        vm.warp(block.timestamp + 2 days);
        assertFalse(registry.isEligible(user1));
    }
}
