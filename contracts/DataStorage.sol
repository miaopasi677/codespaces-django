// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract DataStorage {
    mapping(string => string) private hashes;

    function storeHash(string memory hash) public {
        hashes[hash] = hash;
    }

    function getHash(string memory hash) public view returns (string memory) {
        return hashes[hash];
    }
}