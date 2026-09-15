import torch
import argparse
from ml.src.utils import get_device, export_to_onnx
from ml.src.model import CVModelV1
from ml.config import MODELS_OUTPUT_DIR, ONNX_MODELS_DIR


def export(model_name: str = "cv_model_v1.pt"):
    device = get_device()
    model = CVModelV1(2048)
    model.load_state_dict(torch.load(MODELS_OUTPUT_DIR / model_name, map_location=device))
    model.eval()

    dummy_input = torch.randn(1, 2048)
    export_to_onnx(model, dummy_input, ONNX_MODELS_DIR, f"{model_name.split('.')[0]}.onnx")

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--model", required=True, help="Nome do ficheiro do modelo (ex: cv_model_v1.pt)")
    args = parser.parse_args()
    export(args.model)