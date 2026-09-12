import torch
from torch import nn

class CVModelV1(nn.Module):
    def __init__(self, input_dim: int = 4096):
        super().__init__()
        self.fc1 = nn.Linear(in_features=input_dim, out_features=384)
        self.fc2 = nn.Linear(in_features=384, out_features=64)
        self.fc3 = nn.Linear(in_features=64, out_features=1)
        self.relu = nn.ReLU()
        self.dropout = nn.Dropout(0.4)

    def forward(self, x):
        x = self.dropout(self.relu(self.fc1(x)))
        x = self.dropout(self.relu(self.fc2(x)))
        x = self.fc3(x)
        return x