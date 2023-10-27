// SPDX-License-Identifier: MIT
pragma solidity >=0.8.19;

contract Utilities {
    function _isWallet(address target) internal view returns (bool) {
        uint256 size;
        assembly {
            size := extcodesize(target)
        }
        return size > 0;
    }

    function _bytesToAddress(bytes memory data) internal pure returns (address) {
        require(data.length == 20, "Invalid data length"); // Ensure the data length is 20 bytes (address size)

        address addr;
        assembly {
            addr := mload(add(data, 20)) // Load 20 bytes (address size) starting from the data offset
        }

        return addr;
    }

    function _bytesToUint256(bytes memory data) internal pure returns (uint256 result) {
        require(data.length >= 32, "Invalid data length");
        assembly {
            result := mload(add(data, 0x20))
        }
    }

    function _stringToAddress(string memory _str) internal pure returns (address) {
        bytes memory strBytes = bytes(_str);
        require(strBytes.length == 42, "Invalid address length");

        uint256 result = 0;
        for (uint256 i = 0; i < 40; i++) {
            uint256 charValue = uint256(uint8(strBytes[i + 2])); // Skip '0x' prefix
            if (charValue >= 48 && charValue <= 57) {
                charValue -= 48;
            } else if (charValue >= 65 && charValue <= 70) {
                charValue -= 55;
            } else if (charValue >= 97 && charValue <= 102) {
                charValue -= 87;
            } else {
                revert("Invalid character in address");
            }
            result = result * 16 + charValue;
        }
        return address(uint160(result));
    }

    function _recoverSigner(bytes32 msgHash, bytes memory msgSignature) internal pure returns (address) {
        bytes32 r;
        bytes32 s;
        uint8 v;

        bytes32 prefixedHash = keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", msgHash));

        //Check the signature length
        if (msgSignature.length != 65) {
            return (address(0));
        }

        // Divide the signature in r, s and v variables
        assembly {
            r := mload(add(msgSignature, 32))
            s := mload(add(msgSignature, 64))
            v := byte(0, mload(add(msgSignature, 96)))
        }

        // Version of signature should be 27 or 28, but 0 and 1 are also possible versions
        if (v < 27) {
            v += 27;
        }

        // If the version is correct return the signer address
        if (v != 27 && v != 28) {
            return (address(0));
        } else {
            return ecrecover(prefixedHash, v, r, s);
        }
    }
}
