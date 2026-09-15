pragma solidity ^0.8.20;

import "forge-std/Test.sol";
import "../src/CVMatchRegistry.sol";
import "../src/Verifier.sol";
import "../script/VerifyProof.s.sol";

contract CVMatchRegistryTest is Test {
    CVMatchRegistry registry;

    function setUp() public {
        Halo2Verifier verifier = new Halo2Verifier();
        registry = new CVMatchRegistry(address(verifier));
    }

    function _loadProof() internal view returns (bytes memory proof, uint256[] memory instances) {
        string memory json = vm.readFile("../zk/proofs/proof.json");
        proof = vm.parseJsonBytes(json, ".hex_proof");
        string memory instHex = vm.parseJsonString(json, ".instances[0][0]");
        
        instances = new uint256[](1);
        
        uint256 parsedInstance = vm.parseUint(string.concat("0x", instHex));
        instances[0] = ProofUtils.reverseBytes(parsedInstance);
    }

    function test_RegisterMatch() public {
        (bytes memory proof, uint256[] memory instances) = _loadProof();
        registry.registerMatch(proof, instances);
        assertTrue(registry.hasCertifiedMatch(address(this)));
    }

    function test_RegisterMatchEmitsEvent() public {
        (bytes memory proof, uint256[] memory instances) = _loadProof();
        vm.expectEmit(true, false, false, false);
        emit CVMatchRegistry.MatchCertified(address(this));
        registry.registerMatch(proof, instances);
    }

    function test_RevertWhen_InvalidProof() public {
        (, uint256[] memory instances) = _loadProof();
        bytes memory fakeProof = hex"deadbeef";
        vm.expectRevert();
        registry.registerMatch(fakeProof, instances);
    }

    function test_RevertWhen_TamperedInstance() public {
        (bytes memory proof, uint256[] memory instances) = _loadProof();
        instances[0] = instances[0] + 1;
        vm.expectRevert();
        registry.registerMatch(proof, instances);
    }
}