// SPDX-License-Identifier: UNLICENSED
pragma solidity >=0.8.19 <0.9.0;

import { PRBTest } from "@prb/test/PRBTest.sol";
import { StdCheats } from "forge-std/StdCheats.sol";

import { IdentityFallbackHandler } from "../src/IdentityFallbackHandler.sol";
import { IdentityFallbackHandlerFactory } from "../src/IdentityFallbackHandlerFactory.sol";

contract MockIdentityFallbackHandlerFactory is IdentityFallbackHandlerFactory {
    function createIdentityFallbackHandler(
        address pki,
        address[] memory owners,
        uint256 saltNonce
    )
        external
        returns (IdentityFallbackHandler)
    {
        return _createIdentityFallbackHandler(pki, owners, saltNonce);
    }
}

contract IdentityFallbackHandlerFactoryTest is PRBTest, StdCheats {
    MockIdentityFallbackHandlerFactory internal identityFallbackHandlerFactory;

    function setUp() public virtual {
        identityFallbackHandlerFactory = new MockIdentityFallbackHandlerFactory();
    }

    /// @dev Test that the factory can deploy a new IdentityFallbackHandler matching the counterfactual address
    function test_computeIdentityFallBackHandler() external {
        address[] memory owners = new address[](1);
        owners[0] = address(0xdEAD);
        address counterfactual = identityFallbackHandlerFactory.computeIdentityFallBackHandler(address(this), owners, 0);
        IdentityFallbackHandler materialized =
            identityFallbackHandlerFactory.createIdentityFallbackHandler(address(this), owners, 0);
        assertEq(counterfactual, address(materialized), "Invalid counterfactual or materialized address");
    }
}
