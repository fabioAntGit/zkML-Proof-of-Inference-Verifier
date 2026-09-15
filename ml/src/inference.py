import json
from datetime import datetime

import torch

from typing import Any

from ml.src.embedding import embedding_cv_job
from ml.src.model import CVModelV1
from ml.src.utils import get_device
from ml.config import MODELS_OUTPUT_DIR, INPUT_ONNX_DATA_DIR
from zk.src.prove import prove
from zk.config import PROOFS_DIR


def inference(cv_text: str, job_text: str) -> dict[str, Any]:
    device = get_device()
    cv_emb, job_emb = embedding_cv_job(cv_text, job_text)
    data = torch.cat((cv_emb, job_emb), dim=0).unsqueeze(0).to(device)

    model = CVModelV1(2048).to(device)
    model.load_state_dict(torch.load(MODELS_OUTPUT_DIR / "cv_model_v1.pt", map_location=device))
    model.eval()

    with torch.inference_mode():
        y_pred = model(data)
        prob = torch.sigmoid(y_pred).item()

    is_match = prob > 0.5
    if is_match:
        print(f"Match: {prob * 100:.2f}%")
    else:
        print(f"No Match: {prob * 100:.2f}%")

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    input_dir = INPUT_ONNX_DATA_DIR / "cv_model_v1"
    input_dir.mkdir(parents=True, exist_ok=True)
    input_path = input_dir / f"input_{timestamp}.json"

    data_array = data.flatten().tolist()
    input_data = dict(input_data=[data_array])
    with open(input_path, "w") as f:
        json.dump(input_data, f)

    print(f"Input saved to: {input_path}")
    print("Generating ZK proof...")
    proof_path = PROOFS_DIR / f"proof_{timestamp}.json"
    witness_path = PROOFS_DIR / f"witness_{timestamp}.json"
    prove(input_path=str(input_path), proof_path=str(proof_path), witness_path=str(witness_path))

    return {
        "match": is_match,
        "probability": prob,
        "input_path": str(input_path),
        "proof_path": str(proof_path),
    }


if __name__ == "__main__":
    test_cv = "Experienced Python and Blockchain developer with Solc and AI expertise."
    test_job = "Looking for a Senior Python Developer with Blockchain knowledge."
    print("Running test inference...")
    inference(test_cv, test_job)