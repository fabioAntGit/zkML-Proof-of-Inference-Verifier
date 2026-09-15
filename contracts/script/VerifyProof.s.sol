pragma solidity ^0.8.20;

import "forge-std/Script.sol";
import "../src/CVMatchRegistry.sol";
import "../src/Verifier.sol";

library ProofUtils {
    // O ZK proof exporta a instância em Little-Endian, mas a EVM exige Big-Endian.
    function reverseBytes(uint256 input) internal pure returns (uint256 output) {
        for (uint8 i = 0; i < 32; i++) {
            output = (output << 8) | ((input >> (i * 8)) & 0xFF);
        }
    }
}

contract VerifyProofScript is Script {
    function run(string memory proofPath) external returns (bool) {
        Halo2Verifier verifier = new Halo2Verifier();
        CVMatchRegistry registry = new CVMatchRegistry(address(verifier));

        string memory json = vm.readFile(proofPath);
        bytes memory proof = vm.parseJsonBytes(json, ".hex_proof");
        string memory instHex = vm.parseJsonString(json, ".instances[0][0]");

        uint256[] memory instances = new uint256[](1);
        uint256 parsedInstance = vm.parseUint(string.concat("0x", instHex));
        instances[0] = ProofUtils.reverseBytes(parsedInstance);

        address candidate = address(0xCAFE);
        vm.prank(candidate);
        registry.registerMatch(proof, instances);
        require(registry.hasCertifiedMatch(candidate), "Not certified");
        return true;
    }
}
