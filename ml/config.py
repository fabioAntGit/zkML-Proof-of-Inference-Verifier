from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent
DOCUMENT_DATASET_CSV = BASE_DIR / "resume_job_dataset.csv"
DOCUMENT_DATASET_REQUIRED_COLUMNS = {"cv_text", "job_text", "label"}

EMBEDDINGS_OUTPUT_DIR = Path(__file__).resolve().parent / "data" / "embeddings"
EMBEDDING_MODEL = "BAAI/bge-m3"

BATCH_SIZE = 8

TRAINING_EPOCHS = 100

MODELS_OUTPUT_DIR = Path(__file__).resolve().parent / "models"


