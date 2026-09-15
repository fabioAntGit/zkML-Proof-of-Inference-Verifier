import torch
import random
import numpy as np
from torch import nn
import json
from ml.config import INPUT_ONNX_DATA_DIR
from pathlib import Path
import onnx
import pymupdf


def get_device() -> torch.device:
    if torch.cuda.is_available():
        return torch.device("cuda")
    elif torch.backends.mps.is_available():
        return torch.device("mps")
    else:
        return torch.device("cpu")

def set_seed(seed: int = 42):
    torch.manual_seed(seed)
    torch.cuda.manual_seed_all(seed)
    random.seed(seed)
    np.random.seed(seed)
    
def export_to_onnx(model: nn.Module, dummy_input: torch.Tensor, output_path: Path, file_name: str):
    output_path.mkdir(parents=True, exist_ok=True)
    (INPUT_ONNX_DATA_DIR / file_name.split('.')[0]).mkdir(parents=True, exist_ok=True)
    model.eval()
    onnx_path = str(output_path / file_name)
    torch.onnx.export(model,
                dummy_input,
                onnx_path,
                export_params=True,
                opset_version=18,
                do_constant_folding=True,
                input_names=["input"],
                output_names=["output"],
                dynamic_axes={"input": {0: "batch_size"}, "output": {0: "batch_size"}},
                dynamo=False)

    onnx_model = onnx.load(onnx_path)
    onnx.save_model(onnx_model, onnx_path, save_as_external_data=False)

    data_array = dummy_input.flatten().tolist()
    data = dict(input_data=[data_array])
    with open(INPUT_ONNX_DATA_DIR / file_name.split('.')[0] / "input.json", 'w') as f:
        json.dump(data, f)

    print(f"Model exported to {onnx_path}")


def extract_text_from_pdf(pdf_source: str | Path | bytes) -> str:
    if isinstance(pdf_source, bytes):
        doc = pymupdf.open(stream=pdf_source, filetype="pdf")
    else:
        doc = pymupdf.open(str(pdf_source))

    text = " ".join(page.get_text() for page in doc)
    return text.strip()