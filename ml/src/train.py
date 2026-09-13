from src.datasets import EmbeddingDataset
from config import BATCH_SIZE, TRAINING_EPOCHS, MODELS_OUTPUT_DIR, ONNX_MODELS_DIR
import torch
from torch import nn
from torch.utils.data import DataLoader, random_split
from torch.utils.tensorboard import SummaryWriter
from src.model import CVModelV1
from src.utils import get_device, set_seed, export_to_onnx
from sklearn.metrics import classification_report, confusion_matrix



def evaluate(model, test_loader, device):
    model.eval()
    all_preds = []
    all_labels = []
    with torch.inference_mode():
        for x_test, y_test in test_loader:
            logits = model(x_test).squeeze()
            preds = (torch.sigmoid(logits) > 0.5).float()
            all_preds.extend(preds.cpu().tolist())
            all_labels.extend(y_test.cpu().tolist())

    print("\n--- Final Evaluation (best model) ---")
    print(classification_report(all_labels, all_preds, target_names=["No Fit", "Fit"]))
    print("Confusion Matrix:")
    print(confusion_matrix(all_labels, all_preds))


def train():
    #set_seed(42)
    device = get_device()
    dataset = EmbeddingDataset(device=device)

    train_size = int(0.8 * len(dataset))
    test_size = len(dataset) - train_size
    train_ds, test_ds = random_split(dataset, [train_size, test_size])

    train_loader = DataLoader(train_ds, batch_size=BATCH_SIZE, shuffle=True)
    test_loader = DataLoader(test_ds, batch_size=BATCH_SIZE, shuffle=False)

    model = CVModelV1(4096).to(device)
    loss_fn = nn.BCEWithLogitsLoss()
    optimizer = torch.optim.Adam(model.parameters(), lr=1e-3, weight_decay=1e-4)

    MODELS_OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    model_path = MODELS_OUTPUT_DIR / "cv_model_v1.pt"

    writer = SummaryWriter()

    best_test_loss = float("inf")
    patience = 5
    epochs_without_improvement = 0

    for epoch in range(TRAINING_EPOCHS):
        # --- treino ---
        model.train()
        total_train_loss = 0
        for x_train, y_train in train_loader:
            y_pred = model(x_train)
            loss = loss_fn(y_pred.squeeze(), y_train)
            optimizer.zero_grad()
            loss.backward()
            optimizer.step()
            total_train_loss += loss.item()
        avg_train_loss = total_train_loss / len(train_loader)

        # --- avaliação por época (loss + accuracy) ---
        model.eval()
        total_test_loss = 0
        correct = 0
        total = 0
        with torch.inference_mode():
            for x_test, y_test in test_loader:
                test_pred = model(x_test).squeeze()
                total_test_loss += loss_fn(test_pred, y_test).item()
                preds = (torch.sigmoid(test_pred) > 0.5).float()
                correct += (preds == y_test).sum().item()
                total += y_test.size(0)

        avg_test_loss = total_test_loss / len(test_loader)
        accuracy = correct / total
        print(f"Epoch: {epoch}, Train Loss: {avg_train_loss:.3f}, Test Loss: {avg_test_loss:.3f}, Accuracy: {accuracy:.3f}")

        # --- TensorBoard ---
        writer.add_scalars("Loss", {"train": avg_train_loss, "test": avg_test_loss}, epoch)
        writer.add_scalar("Accuracy/test", accuracy, epoch)

        # --- early stopping ---
        if avg_test_loss < best_test_loss:
            best_test_loss = avg_test_loss
            epochs_without_improvement = 0
            torch.save(model.state_dict(), model_path)
        else:
            epochs_without_improvement += 1
            if epochs_without_improvement >= patience:
                print(f"Early stopping at epoch {epoch} (best test loss: {best_test_loss:.3f})")
                break

    writer.close()
    print(f"Model saved to {model_path}")

    # --- avaliação final sobre o melhor modelo ---
    model.load_state_dict(torch.load(model_path))
    model.to(device)
    evaluate(model, test_loader, device)
    export_to_onnx(model, test_loader[0][0], ONNX_MODELS_DIR, "cv_model_v1.onnx")

if __name__ == "__main__":
    train()