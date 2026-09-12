from pathlib import Path
import torch
from torch.utils.data import Dataset
from config import EMBEDDINGS_OUTPUT_DIR

class DocumentDataset(Dataset):
    def __init__(self, cv_txt: list[str], job_txt: list[str], label: list[float]):
        self.cv_txt = cv_txt
        self.job_txt = job_txt
        self.label = label

    def __len__(self):
        return len(self.label)

    def __getitem__(self, idx):
        return self.cv_txt[idx], self.job_txt[idx], self.label[idx]

class EmbeddingDataset(Dataset):
    def __init__(self, embeddings_dir: str | Path = EMBEDDINGS_OUTPUT_DIR):
        d = Path(embeddings_dir)
        self.cv = torch.load(d / "cv_embeddings.pt")
        self.job = torch.load(d / "job_embeddings.pt")
        self.label = torch.load(d / "labels.pt")

    def __len__(self):
        return len(self.label)

    def __getitem__(self, idx):
        cv = self.cv[idx]
        job = self.job[idx]
        x = torch.cat([cv, job, cv * job, torch.abs(cv - job)])
        y = self.label[idx]
        return x, y

