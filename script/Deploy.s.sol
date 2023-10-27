// SPDX-License-Identifier: UNLICENSED
pragma solidity >=0.8.19 <0.9.0;

import { PublicKeyInfrastructure } from "../src/PublicKeyInfrastructure.sol";

import { BaseScript } from "./Base.s.sol";

/// @dev See the Solidity Scripting tutorial: https://book.getfoundry.sh/tutorials/solidity-scripting
contract Deploy is BaseScript {
    function run() public broadcast returns (PublicKeyInfrastructure foo) {
        foo = new PublicKeyInfrastructure();
    }
}
