// SPDX-License-Identifier: MIT
pragma solidity >=0.8.19;

import { IdentityFallbackHandler, DidVerificationMethod } from "./IdentityFallbackHandler.sol";

/**
 * @title IdentityFallbackHandler - A contract that adds a DID document to a Safe using EIP-3886
 * @dev This contract is deployed to the Safe and is called by the Safe when a DID document is requested
 * @dev Decouples the DID document from the Safe contract. And
 */
contract IdentityFallbackHandlerFactory {
    /*//////////////////////////////////////////////////////////////////////////
                                   PUBLIC STORAGE
    //////////////////////////////////////////////////////////////////////////*/

    DidVerificationMethod public constant DEFAULT_VERIFICATION_METHOD = DidVerificationMethod.DELEGATE;

    /*//////////////////////////////////////////////////////////////////////////
                                    READ FUNCTIONS
    //////////////////////////////////////////////////////////////////////////*/

    function computeIdentityFallBackHandler(
        address pki,
        address[] memory owners,
        uint256 saltNonce
    )
        public
        view
        returns (address)
    {
        return _computeIdentityFallbackHandler(pki, owners, saltNonce);
    }

    /*//////////////////////////////////////////////////////////////////////////
                                   WRITE FUNCTIONS
    //////////////////////////////////////////////////////////////////////////*/

    function _computeIdentityFallbackHandler(
        address pki,
        address[] memory owners,
        uint256 saltNonce
    )
        internal
        view
        returns (address)
    {
        bytes32 salt = keccak256(abi.encodePacked(pki, owners, saltNonce));

        // By default we set the authority to the first owner of the Safe and
        // delegate authority to sign a valid DID document
        bytes memory deploymentData = abi.encodePacked(
            type(IdentityFallbackHandler).creationCode,
            uint256(uint160(address(pki))),
            uint256(DEFAULT_VERIFICATION_METHOD),
            uint256(uint160(address(owners[0])))
        );
        bytes32 hash = keccak256(abi.encodePacked(bytes1(0xff), address(this), salt, keccak256(deploymentData)));

        // NOTE: cast last 20 bytes of hash to address
        return address(uint160(uint256(hash)));
    }

    function _createIdentityFallbackHandler(
        address pki,
        address[] memory owners,
        uint256 saltNonce
    )
        internal
        returns (IdentityFallbackHandler identityFallbackHandler)
    {
        bytes32 salt = keccak256(abi.encodePacked(pki, owners, saltNonce));
        bytes memory deploymentData = abi.encodePacked(
            type(IdentityFallbackHandler).creationCode,
            uint256(uint160(pki)),
            uint256(DEFAULT_VERIFICATION_METHOD),
            uint256(uint160(address(owners[0])))
        );
        // solhint-disable-next-line no-inline-assembly
        assembly {
            identityFallbackHandler := create2(0x0, add(0x20, deploymentData), mload(deploymentData), salt)
        }
        require(address(identityFallbackHandler) != address(0), "Create2 call failed");

        return IdentityFallbackHandler(identityFallbackHandler);
    }
}
