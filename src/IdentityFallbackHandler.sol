// SPDX-License-Identifier: MIT
pragma solidity >=0.8.19;

interface IPKI {
    function urls() external view returns (string[] memory);
}

/// @notice Method options to verify the DID document
enum DidVerificationMethod {
    DELEGATE, // EOA can sign messages offchain i.e. free to update.
    SAFE, // Safe message signature i.e. requires a Safe transaction to update.
    EIP1271 // Contract that implements EIP-1271 to sign messages offchain i.e.
}

/**
 * @title IdentityFallbackHandler - A contract that adds a DID document to a Safe using EIP-3886
 * @dev This contract is deployed to the Safe and is called by the Safe when a DID document is requested
 * @dev Decouples the DID document from the Safe contract. And
 */
contract IdentityFallbackHandler {
    /*//////////////////////////////////////////////////////////////////////////
                                   PUBLIC STORAGE
    //////////////////////////////////////////////////////////////////////////*/

    /// @notice Public key infrastructure contract that manages resolving the DID document
    /// @dev Can be set to address(0) to designate the Safe as root authority
    address internal _pki;

    /// @notice Authority to update and sign the DID document
    address internal _authority;

    /// @notice Urls to fetch the DID document.
    string[] private _urls;

    /// @notice Parent Safe address that owns this contract
    address internal _owner;

    /// @notice Method to verify the DID document
    DidVerificationMethod internal _verificationMethod;

    /*//////////////////////////////////////////////////////////////////////////
                                    ERRORS
    //////////////////////////////////////////////////////////////////////////*/
    error OffchainLookup(address sender, string[] urls, bytes callData, bytes4 callbackFunction, bytes extraData);

    /*//////////////////////////////////////////////////////////////////////////
                                    CONSTRUCTOR
    //////////////////////////////////////////////////////////////////////////*/

    constructor(address __pki, DidVerificationMethod __verificationMethod, address __authority) {
        _pki = __pki;
        _verificationMethod = __verificationMethod;
        _authority = __authority;
    }

    /*//////////////////////////////////////////////////////////////////////////
                                    READ FUNCTIONS
    //////////////////////////////////////////////////////////////////////////*/

    /**
     * @notice Returns the urls that resolve the DID document.
     * @dev If no urls are set, the PKI contract is queried for the urls.
     * @dev The safe can override the urls to migrate to a new DID document manager.
     * @return string[] memory
     */
    function urls() external view returns (string[] memory) {
        if (_urls.length == 0) {
            return IPKI(_pki).urls();
        }
        return _urls;
    }
    /**
     * @notice Resolves a DID document using CCIP (EIP-3886) standard.
     * @dev Used when a Safe was not deployed by a PKI contract and the Safe owner wants to add a DID document.
     * @dev The DID document would use address(0) in the PKI section of the identifier.
     * @dev For example the DID document would look like this: did:dis:0x0000...0000:0xdEAD...bEef
     */

    function did() external view {
        bytes memory callData = abi.encodePacked(address(this));
        revert OffchainLookup(
            address(this), _urls, callData, this.document.selector, abi.encodePacked(address(this), address(this))
        );
    }

    /**
     * @notice Validates and returns a DID document requested from the `did` method.
     */
    function document(bytes calldata response, bytes calldata) external view virtual returns (string memory DID) {
        bytes memory msgSignature = bytes(response[0:65]);
        bytes memory didHex = bytes(response[65:]);
        bytes32 msgHash2 = keccak256(abi.encodePacked(string(didHex)));
        // TODO: Verify signature was from a Safe owner or signed by the Safe using EIP-1271
        return string(didHex);
    }

    /*//////////////////////////////////////////////////////////////////////////
                                   WRITE FUNCTIONS
    //////////////////////////////////////////////////////////////////////////*/

    function initOwner(address __owner) external {
        require(_owner == address(0), "IdentityFallbackHandler:not-pki");
        require(msg.sender == _pki, "IdentityFallbackHandler:not-pki");
        _owner = __owner;
    }

    function initUrls(string[] memory __urls) external {
        require(_urls.length == 0, "IdentityFallbackHandler:not-pki");
        require(msg.sender == _pki, "IdentityFallbackHandler:not-pki");
        for (uint256 i = 0; i < __urls.length; i++) {
            _urls.push(__urls[i]);
        }
    }

    function setVerificationMethod(DidVerificationMethod __verificationMethod) external {
        require(msg.sender == _owner, "IdentityFallbackHandler:not-owner");
        _verificationMethod = __verificationMethod;
    }

    function setUrls(string[] memory __urls) external {
        require(msg.sender == _owner, "IdentityFallbackHandler:not-owner");
        // Clear existing URLs
        while (_urls.length > 0) {
            _urls.pop();
        }

        // Add new URLs
        for (uint256 i = 0; i < __urls.length; i++) {
            _urls.push(__urls[i]);
        }
    }
}
