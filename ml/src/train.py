from src.datasets import EmbeddingDataset
from config import BATCH_SIZE, TRAINING_EPOCHS
import torch
from torch import nn
from torch.utils.data import DataLoader, random_split
from src.model import CVModelV1

def train():
    dataset = EmbeddingDataset()

    train_size = int(0.8*len(dataset))
    test_size = len(dataset) - train_size

    train_ds, test_ds = random_split(dataset,[train_size, test_size])

    train_loader = DataLoader(train_ds, batch_size=BATCH_SIZE, shuffle=True)
    test_loader = DataLoader(test_ds, batch_size=BATCH_SIZE, shuffle=True)

    model = CVModelV1(4096)
    loss_fn = nn.BCEWithLogitsLoss()
    
    optimizer = torch.optim.Adam(model.parameters(), lr=1e-3)

    for epoch in range(TRAINING_EPOCHS):
        for x_train,y_train in train_loader:
            model.train()

            y_pred = model(x_train)

            loss = loss_fn(y_pred.squeeze(), y_train)

            optimizer.zero_grad()

            loss.backward()

            optimizer.step()
        
        model.eval()
        with torch.inference_mode():
            for x_test,y_test in test_loader:
                test_pred = model(x_test)
                test_loss = loss_fn(test_pred.squeeze(), y_test)

                print(f'Epoch: {epoch}, Loss: {loss:.3f}, Test Loss: {test_loss:.3f}')

                

if __name__ == "__main__":
    train()



            

    
