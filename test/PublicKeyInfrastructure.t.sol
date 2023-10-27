// SPDX-License-Identifier: UNLICENSED
pragma solidity >=0.8.19 <0.9.0;

import { PRBTest } from "@prb/test/PRBTest.sol";
import { StdCheats } from "forge-std/StdCheats.sol";
import { Safe } from "safe-contracts/Safe.sol";
import { SafeProxy } from "safe-contracts/proxies/SafeProxy.sol";

import { PublicKeyInfrastructure } from "../src/PublicKeyInfrastructure.sol";

contract PublicKeyInfrastructureTest is PRBTest, StdCheats {
    PublicKeyInfrastructure internal pki;
    Safe internal safeSingleton;

    function setUp() public virtual {
        pki = new PublicKeyInfrastructure();
        safeSingleton = new Safe();
    }

    /// @dev Test that the factory can deploy a new IdentityFallbackHandler matching the counterfactual address
    function test_createWallet_success() external {
        address[] memory owners = new address[](1);
        owners[0] = address(0xdEAD);
        address counterfactual = pki.computeWalletAddress(address(safeSingleton), owners, 0);
        SafeProxy materialized = pki.createWallet(address(safeSingleton), owners, 0);
        assertEq(counterfactual, address(materialized), "Invalid counterfactual or materialized address");
    }
}
