from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent

ZK_DIR = BASE_DIR / "zk"
CIRCUIT_DIR = ZK_DIR / "circuit"
KEYS_DIR = ZK_DIR / "keys"
PROOFS_DIR = ZK_DIR / "proofs"
VERIFIER_DIR = ZK_DIR / "verifier"

MODEL_ONNX_PATH = BASE_DIR / "ml" / "models" / "onnx" / "cv_model_v1.onnx"
DEFAULT_INPUT_PATH = BASE_DIR / "ml" / "models" / "onnx" / "data" / "cv_model_v1" / "input.json"

SETTINGS_PATH = CIRCUIT_DIR / "settings.json"
COMPILED_MODEL_PATH = CIRCUIT_DIR / "model.compiled"
VK_PATH = KEYS_DIR / "vk.key"
PK_PATH = KEYS_DIR / "pk.key"

WITNESS_PATH = PROOFS_DIR / "witness.json"
PROOF_PATH = PROOFS_DIR / "proof.json"
ABI_PATH = VERIFIER_DIR / "abi.json"

CONTRACTS_SRC_DIR = BASE_DIR / "contracts" / "src"
VERIFIER_SOL_PATH = CONTRACTS_SRC_DIR / "Verifier.sol"
