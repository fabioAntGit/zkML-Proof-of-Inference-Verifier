import ezkl

from zk.config import (
    DEFAULT_INPUT_PATH,
    COMPILED_MODEL_PATH,
    PK_PATH,
    VK_PATH,
    SETTINGS_PATH,
    WITNESS_PATH,
    PROOF_PATH,
)


def prove(
    input_path: str = str(DEFAULT_INPUT_PATH),
    proof_path: str = str(PROOF_PATH),
    witness_path: str = str(WITNESS_PATH),
):
    ezkl.gen_witness(str(input_path), str(COMPILED_MODEL_PATH), str(witness_path))
    ezkl.prove(str(witness_path), str(COMPILED_MODEL_PATH), str(PK_PATH), str(proof_path))
    assert ezkl.verify(str(proof_path), str(SETTINGS_PATH), str(VK_PATH))
    print(f"Proof generated and verified successfully at: {proof_path}")


if __name__ == "__main__":
    prove()