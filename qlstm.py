import torch
import torch.nn as nn
import pennylane as qml
from torch.utils.data import DataLoader, Dataset
import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import LabelEncoder

# =========================
# Load Dataset
# =========================

df = pd.read_excel("dataset.xlsx")
df = df.dropna(subset=["URLs", "Labels"])

urls = df["URLs"].astype(str).values
labels = df["Labels"].values

# Character-level encoding
char_set = list(set("".join(urls)))
char_to_idx = {c: i+1 for i, c in enumerate(char_set)}

max_len = 100

def encode_url(url):
    encoded = [char_to_idx.get(c, 0) for c in url[:max_len]]
    encoded += [0] * (max_len - len(encoded))
    return encoded

X = torch.tensor([encode_url(u) for u in urls], dtype=torch.long)
y = torch.tensor(labels, dtype=torch.float32)

X_train, X_test, y_train, y_test = train_test_split(
    X, y, test_size=0.2, random_state=42, stratify=y
)

# =========================
# Quantum Layer
# =========================

n_qubits = 4
dev = qml.device("default.qubit", wires=n_qubits)

@qml.qnode(dev, interface="torch")
def quantum_circuit(inputs, weights):
    for i in range(n_qubits):
        qml.RY(inputs[i], wires=i)
    qml.templates.StronglyEntanglingLayers(weights, wires=range(n_qubits))
    return [qml.expval(qml.PauliZ(i)) for i in range(n_qubits)]

weight_shapes = {"weights": (3, n_qubits, 3)}
qlayer = qml.qnn.TorchLayer(quantum_circuit, weight_shapes)

# =========================
# QLSTM Model
# =========================

class QLSTM(nn.Module):
    def __init__(self, vocab_size, embed_dim, hidden_dim):
        super().__init__()
        self.embedding = nn.Embedding(vocab_size + 1, embed_dim)
        self.lstm = nn.LSTM(embed_dim, hidden_dim, batch_first=True)
        self.quantum = qlayer
        self.fc = nn.Linear(n_qubits, 1)
        self.sigmoid = nn.Sigmoid()

    def forward(self, x):
        x = self.embedding(x)
        lstm_out, _ = self.lstm(x)
        last_hidden = lstm_out[:, -1, :]
        q_input = last_hidden[:, :n_qubits]
        q_out = self.quantum(q_input)
        out = self.fc(q_out)
        return self.sigmoid(out).squeeze()

# =========================
# Training
# =========================

model = QLSTM(len(char_set), 32, 16)
criterion = nn.BCELoss()
optimizer = torch.optim.Adam(model.parameters(), lr=0.001)

dataset = torch.utils.data.TensorDataset(X_train, y_train)
loader = DataLoader(dataset, batch_size=32, shuffle=True)

epochs = 5

for epoch in range(epochs):
    total_loss = 0
    for xb, yb in loader:
        optimizer.zero_grad()
        preds = model(xb)
        loss = criterion(preds, yb)
        loss.backward()
        optimizer.step()
        total_loss += loss.item()
    print(f"Epoch {epoch+1}, Loss: {total_loss:.4f}")

# =========================
# Evaluation
# =========================

with torch.no_grad():
    preds = model(X_test)
    predicted = (preds > 0.5).float()
    accuracy = (predicted == y_test).float().mean()

print("Test Accuracy:", accuracy.item())