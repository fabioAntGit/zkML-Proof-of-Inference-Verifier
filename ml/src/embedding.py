from sentence_transformers import SentenceTransformer
from ml.src.utils import get_device
from ml.config import EMBEDDING_MODEL
import torch

def embedding_cv_job (cv_text: str, job_text: str, batch: int = 1) -> torch.Tensor:
    model = SentenceTransformer(EMBEDDING_MODEL, device=get_device())

    cv_embedding = model.encode(
        cv_text,
        batch_size=batch,
        convert_to_tensor=True,
        show_progress_bar=True,
    )
    job_embedding = model.encode(
        job_text,
        batch_size=batch,
        convert_to_tensor=True,
        show_progress_bar=True,
    )
    
    return cv_embedding, job_embedding
