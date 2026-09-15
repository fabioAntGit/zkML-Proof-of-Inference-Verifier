    pragma solidity ^0.8.0;
    import "./IVerifier.sol";

    contract CVMatchRegistry {
        IVerifier public verifier;

        mapping(address => bool) public hasCertifiedMatch;

        event MatchCertified (address indexed candidate);

        constructor(address _verifier) {
            verifier = IVerifier(_verifier);
        }

        function registerMatch(bytes calldata proof, uint[] calldata instances) external {
            require(verifier.verifyProof(proof, instances), "Invalid proof");
            hasCertifiedMatch[msg.sender] = true;
            emit MatchCertified(msg.sender);
        }
    }