// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import "forge-std/Test.sol";
import "../src/ComplianceRegistry.sol";
import "../src/ComplianceGatedService.sol";

contract ComplianceGatedServiceTest is Test {
    ComplianceRegistry public registry;
    ComplianceGatedService public service;

    address public owner = address(0xAAAA);
    address public compliantUser = address(0x1111);
    address public nonCompliantUser = address(0x2222);
    address public dummyRouter = address(0xDEADBEEF);

    function setUp() public {
        vm.chainId(31337);

        vm.startPrank(owner);
        registry = new ComplianceRegistry(
            dummyRouter,
            bytes32("don-id"),
            100,
            "return Functions.encodeString('ok');"
        );
        service = new ComplianceGatedService(address(registry));

        // Grant compliant credential to compliantUser
        registry.mockFulfill(compliantUser, true, 840, "POLYGON_ID");
        vm.stopPrank();

        // Fund accounts
        vm.deal(compliantUser, 10 ether);
        vm.deal(nonCompliantUser, 10 ether);
    }

    function test_NonCompliantUserBlockedFromRegister() public {
        vm.prank(nonCompliantUser);
        vm.expectRevert("Not eligible: sender lacks verified compliance credential");
        service.register();
    }

    function test_CompliantUserCanRegister() public {
        vm.prank(compliantUser);
        service.register();
        assertTrue(service.isRegistered(compliantUser));
    }

    function test_NonCompliantUserBlockedFromDeposit() public {
        vm.prank(nonCompliantUser);
        vm.expectRevert("Not eligible: sender lacks verified compliance credential");
        service.deposit{value: 1 ether}();
    }

    function test_CompliantUserDepositAndWithdraw() public {
        vm.startPrank(compliantUser);
        service.deposit{value: 2 ether}();
        assertEq(service.userBalances(compliantUser), 2 ether);
        assertEq(address(service).balance, 2 ether);

        // Withdraw 1 ether
        service.withdraw(1 ether);
        assertEq(service.userBalances(compliantUser), 1 ether);
        assertEq(address(service).balance, 1 ether);
        vm.stopPrank();
    }

    function test_RevocationImmediatelyBlocksSubsequentActions() public {
        // User deposits 2 ether while compliant
        vm.prank(compliantUser);
        service.deposit{value: 2 ether}();

        // Regulatory revocation occurs
        vm.prank(owner);
        registry.revoke(compliantUser, "Sanctions match detected");

        // Next deposit or withdrawal attempt is blocked fail-closed
        vm.prank(compliantUser);
        vm.expectRevert("Not eligible: sender lacks verified compliance credential");
        service.deposit{value: 1 ether}();

        vm.prank(compliantUser);
        vm.expectRevert("Not eligible: sender lacks verified compliance credential");
        service.withdraw(1 ether);
    }

    function test_PauseUnpause() public {
        vm.prank(owner);
        service.pause();
        assertTrue(service.paused());

        // Even compliant user is blocked when paused
        vm.prank(compliantUser);
        vm.expectRevert(ComplianceGatedService.ContractPaused.selector);
        service.deposit{value: 1 ether}();

        // Unpause restores operations
        vm.prank(owner);
        service.unpause();
        assertFalse(service.paused());

        vm.prank(compliantUser);
        service.deposit{value: 1 ether}();
        assertEq(service.userBalances(compliantUser), 1 ether);
    }
}
