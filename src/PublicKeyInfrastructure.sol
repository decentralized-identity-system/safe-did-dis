// SPDX-License-Identifier: MIT
pragma solidity >=0.8.19;

import { Safe } from "safe-contracts/Safe.sol";
import { SafeProxy } from "safe-contracts/proxies/SafeProxy.sol";
import { SafeProxyFactory } from "safe-contracts/proxies/SafeProxyFactory.sol";
import { IdentityFallbackHandler } from "./IdentityFallbackHandler.sol";
import { IdentityFallbackHandlerFactory } from "./IdentityFallbackHandlerFactory.sol";
import { Utilities } from "./Utilities.sol";

contract PublicKeyInfrastructure is Utilities, IdentityFallbackHandlerFactory, SafeProxyFactory {
    /*//////////////////////////////////////////////////////////////////////////
                                   PUBLIC STORAGE
    //////////////////////////////////////////////////////////////////////////*/
    string[] public urls;
    address internal ENTRYPOINT;

    /*//////////////////////////////////////////////////////////////////////////
                                    ERROR EVENTS
    //////////////////////////////////////////////////////////////////////////*/
    error InvalidOperation();
    error OffchainLookup(address sender, string[] urls, bytes callData, bytes4 callbackFunction, bytes extraData);

    /*//////////////////////////////////////////////////////////////////////////
                                    READ FUNCTIONS
    //////////////////////////////////////////////////////////////////////////*/

    /* ---------------------------------------------------------------------- */
    /* Public Key Infrastructure                                              */
    /* ---------------------------------------------------------------------- */

    /**
     * @notice Returns the DID document associated decentralized identifier.
     * @dev Use an offchain lookup to retrieve the DID document using EIP-3886
     * @dev Will instruct the client to call the `document` method with the response from the offchain lookup.
     * @param id Decentralized Identifier i.e. did:dis:[PKI]:[Wallet]
     */
    function did(string calldata id) external view {
        address pki = _stringToAddress(id[11:53]);
        address wallet = _stringToAddress(id[54:96]);
        bytes memory callData = abi.encodePacked(wallet);
        require(pki == address(this), "PKI: The DID document is not managed by this resolver");
        if (!_isWallet(wallet)) {
            revert OffchainLookup(address(this), urls, callData, this.document.selector, abi.encodePacked(pki, wallet));
        } else {
            SafeProxy _wallet = SafeProxy(payable(wallet));
            bytes memory callData = abi.encodeWithSignature("did()");
            string[] memory __urls = IdentityFallbackHandler(address(_wallet)).urls();
            revert OffchainLookup(address(this), __urls, callData, this.resolve.selector, abi.encodePacked(pki, wallet));
        }
    }

    /**
     * @notice Returns the DID document associated decentralized identifier.
     * @dev Use an offchain lookup to retrieve the DID document using EIP-3886
     * @param response bytes - The response from the offchain lookup
     * @param extraData bytes - The extradata passed from the `did` method
     * @return DID DID document associated to a given DID.
     */
    function document(
        bytes calldata response,
        bytes calldata extraData
    )
        external
        view
        virtual
        returns (string memory DID)
    {
        // Stateful Response from the `did` method
        bytes memory pki = extraData[0:20];
        bytes memory wallet = extraData[20:40];

        // Reponse from Offchain Data Storage
        // bytes memory saltBytes = response[0:32];
        // bytes memory walletSignature = response[32:97];
        // bytes memory didSiganture = response[97:162];
        // bytes memory didHex = response[162:];
        bytes memory saltBytes = response[0:32];
        address recoveryAddress = _bytesToAddress(response[32:52]);
        bytes memory walletSignature = response[52:117];
        bytes memory didSiganture = response[117:182];
        bytes memory didHex = response[182:];

        // Hash the DID and the counterfactual Smart Wallet
        bytes32 didMsg = keccak256(abi.encodePacked(string(didHex)));
        address didSigner = _recoverSigner(didMsg, didSiganture);

        // Hash the entry point, the DID signer (counterfactual smart wallet owner) and the salt.
        bytes32 walletMsg = keccak256(abi.encodePacked(pki, recoveryAddress, didSigner, saltBytes));

        // Recover the signer of the counterfactual Smart Wallet
        address walletSigner = _recoverSigner(walletMsg, walletSignature);

        // Check that the same signer signed both the DID and the counterfactual Smart Wallet
        // address walletComputed = computeAddress(recoveryAddress, didSigner, _bytesToUint256(saltBytes));
        // require(walletComputed == _bytesToAddress(wallet), "INVALID WALLET ADDRESS");

        // Check that the signer of the Smart Wallet is the same as the signer of the DID
        require(walletSigner == didSigner, "INVALID SIGNATURE");
        return string(didHex);
    }

    function resolve(
        bytes calldata response,
        bytes calldata extraData
    )
        external
        view
        virtual
        returns (string memory DID)
    {
        // Stateful Response from the `did` method
        bytes memory pki = extraData[0:20];
        require(_bytesToAddress(pki) == address(this), "PKI: The DID document is not managed by this resolver");
        bytes memory wallet = extraData[20:40];

        // Reponse from Offchain Data Storage
        bytes memory msgSignature = bytes(response[0:65]);
        bytes memory didHex = bytes(response[65:]);
        bytes32 msgHash2 = keccak256(abi.encodePacked(string(didHex)));
        address signer = _recoverSigner(msgHash2, msgSignature);
        // TODO: Verify signature was from a Safe owner or signed by the Safe using EIP-1271
        return string(didHex);
    }

    function computeWalletAddress(
        address singleton,
        address[] memory _owners,
        uint256 saltNonce
    )
        public
        view
        returns (address)
    {
        return _computeAddress(singleton, _owners, saltNonce);
    }

    function isWalletMaterialized(
        address singleton,
        address[] memory owners,
        uint256 saltNonce
    )
        external
        view
        returns (bool)
    {
        address proxyCounterfactual = getSmartWalletAddress(singleton, owners, saltNonce);
        return isContract(proxyCounterfactual);
    }

    function getSmartWalletAddress(
        address _singleton,
        address[] memory _owners,
        uint256 saltNonce
    )
        public
        view
        returns (address proxy)
    {
        address[] memory owners = new address[](_owners.length);
        for (uint256 i = 0; i < _owners.length; i++) {
            owners[i] = _owners[i];
        }

        // Compute the address of the IdentityFallbackHandler
        address identityFallbackHandler = _computeIdentityFallbackHandler(address(this), owners, saltNonce);

        // Compute the address of the Safe
        bytes memory initializer = _encodeInitializer(_owners, identityFallbackHandler);
        bytes32 salt = keccak256(abi.encodePacked(keccak256(initializer), saltNonce));
        bytes memory deploymentData = abi.encodePacked(type(SafeProxy).creationCode, uint256(uint160(_singleton)));
        bytes32 hash = keccak256(abi.encodePacked(bytes1(0xff), address(this), salt, keccak256(deploymentData)));
        // NOTE: cast last 20 bytes of hash to address
        return address(uint160(uint256(hash)));
    }

    /*//////////////////////////////////////////////////////////////////////////
                                   WRITE FUNCTIONS
    //////////////////////////////////////////////////////////////////////////*/

    function createWallet(
        address _singleton,
        address[] memory owners,
        uint256 saltNonce
    )
        public
        returns (SafeProxy proxy)
    {
        IdentityFallbackHandler fallbackHandler = _createIdentityFallbackHandler(address(this), owners, saltNonce);
        bytes memory initializer = _encodeInitializer(owners, address(fallbackHandler));
        bytes32 salt = keccak256(abi.encodePacked(keccak256(initializer), saltNonce));
        proxy = deployProxy(_singleton, initializer, salt);

        // Set the owner of the IdentityFallbackHandler to the Safe
        fallbackHandler.initOwner(address(proxy));

        // Set the default URLs for the IdentityFallbackHandler.
        // Can be updated by the Safe after initialization.
        fallbackHandler.initUrls(urls);

        emit ProxyCreation(proxy, _singleton);
    }

    /*//////////////////////////////////////////////////////////////////////////
                                  INTERNAL FUNCTIONS
    //////////////////////////////////////////////////////////////////////////*/

    function _computeAddress(
        address singleton,
        address[] memory _owners,
        uint256 saltNonce
    )
        internal
        view
        returns (address)
    {
        address identityFallbackHandler = _computeIdentityFallbackHandler(address(this), _owners, saltNonce);
        bytes memory initializer = _encodeInitializer(_owners, identityFallbackHandler);
        bytes32 salt = keccak256(abi.encodePacked(keccak256(initializer), saltNonce));
        bytes memory deploymentData = abi.encodePacked(type(SafeProxy).creationCode, uint256(uint160(singleton)));
        bytes32 hash = keccak256(abi.encodePacked(bytes1(0xff), address(this), salt, keccak256(deploymentData)));
        // NOTE: cast last 20 bytes of hash to address
        return address(uint160(uint256(hash)));
    }

    function _encodeInitializer(
        address[] memory _owners,
        address fallbackHandler
    )
        internal
        pure
        returns (bytes memory initializer)
    {
        address[] memory owners = new address[](_owners.length);
        for (uint256 i = 0; i < _owners.length; i++) {
            owners[i] = _owners[i];
        }
        initializer = abi.encodeWithSelector(
            Safe.setup.selector,
            owners,
            1, // threshold
            address(0), // to
            new bytes(0), // data
            address(0), // fallbackHandler
            address(0), // paymentToken
            0, // payment
            payable(address(0)) // paymentReceiver
        );
    }
}
