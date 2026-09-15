import json
from datetime import datetime
from pathlib import Path

import pandas as pd
import torch
from sentence_transformers import SentenceTransformer
from ml.src.embedding import embedding_cv_job
from ml.src.dataset_loader import DocumentDataset
from ml.src.utils import get_device
from ml.config import EMBEDDING_MODEL, BATCH_SIZE, DOCUMENT_DATASET_CSV, EMBEDDINGS_OUTPUT_DIR, DOCUMENT_DATASET_REQUIRED_COLUMNS

def validate_csv(dataset_csv_path: str) -> pd.DataFrame:
    ds = pd.read_csv(dataset_csv_path)

    if len(ds) == 0:
        raise ValueError(f"Dataset is empty: {dataset_csv_path}")

    missing = DOCUMENT_DATASET_REQUIRED_COLUMNS - set(ds.columns)
    if missing:
        raise ValueError(f"Missing columns in {dataset_csv_path}: {missing}")

    if ds[["cv_text", "job_text"]].isnull().any().any():
        raise ValueError(f"Missing values (NaN) in cv_text/job_text in {dataset_csv_path}")

    if ds["label"].isnull().any():
        raise ValueError(f"Missing values (NaN) in label in {dataset_csv_path}")

    if not pd.api.types.is_numeric_dtype(ds["label"]):
        raise ValueError(
            f"label column must be numeric in {dataset_csv_path}, got dtype {ds['label'].dtype}"
        )

    valid_labels = {0, 1}
    if not set(ds["label"].unique()).issubset(valid_labels):
        raise ValueError(f"label column contains unexpected values: {set(ds['label'].unique()) - valid_labels}")

    return ds


def populate_dataset(dataset_csv_path: str) -> DocumentDataset:
    ds = validate_csv(dataset_csv_path)
    return DocumentDataset(
        cv_txt=ds["cv_text"].tolist(),
        job_txt=ds["job_text"].tolist(),
        label=ds["label"].tolist(),
    )


def dataset_embedding(dataset: DocumentDataset, output_dir: Path) -> None:
    output_dir.mkdir(parents=True, exist_ok=True)

    cv_embeddings, job_embeddings = embedding_cv_job(dataset.cv_txt, dataset.job_txt, BATCH_SIZE)

    labels = torch.tensor(dataset.label, dtype=torch.float32)

    torch.save(cv_embeddings, output_dir / "cv_embeddings.pt")
    torch.save(job_embeddings, output_dir / "job_embeddings.pt")
    torch.save(labels, output_dir / "labels.pt")

    metadata = {
        "model_name": EMBEDDING_MODEL,
        "embedding_dim": cv_embeddings.shape[1],
        "n_examples": len(dataset.cv_txt),
        "created_at": datetime.now().isoformat(),
    }
    (output_dir / "metadata.json").write_text(json.dumps(metadata, indent=2))


def load_embedding(output_dir: str | Path = EMBEDDINGS_OUTPUT_DIR) -> None:
    output_dir = Path(output_dir)

    document_dataset = populate_dataset(DOCUMENT_DATASET_CSV)

    try:
        device = get_device()
        model = SentenceTransformer(EMBEDDING_MODEL, device=device)
    except Exception as e:
        raise RuntimeError(f"Failed to load model '{EMBEDDING_MODEL}': {e}") from e

    dataset_embedding(document_dataset, output_dir)


if __name__ == "__main__":
    load_embedding()