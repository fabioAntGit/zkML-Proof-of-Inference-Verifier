# zkML - Proof of Inference Verifier

Match CVs against job postings using a machine learning model **and** cryptographically prove that the model ran correctly, without revealing the private data of the applicant.

---

## What this project is and why it exists

Consider a platform that uses an AI model to decide whether a CV matches (or not) a job posting. There are two trust problems here:

1. **How can anyone trust that the model was actually run, and run correctly?** A company (or a candidate) receiving a "match / no match" result has to take the word of whoever ran the model. A different model could have been used, or the result could have been made up.

2. **How is the candidate's CV protected?** A CV contains sensitive personal data. Ideally, the result should be verifiable without exposing the CV to everyone.

This project addresses both problems with **Zero-Knowledge Machine Learning (ZKML)**. The core objective is:

> To be able to **prove that a specific model was correctly executed on a given input and produced a given output**, and that anyone can *verify* that proof, without having to trust whoever ran the model, and without the private input being revealed.

Instead of "trust me, the model said match", the result becomes "here is a mathematical proof that this model, correctly executed, produced this result".

---

## How it works

The project is a chain of stages, each one feeding the next:

```
1. Data (CVs + job postings)
        ↓
2. Embeddings (turning text into vectors)
        ↓
3. Model (neural network that decides match / no match)
        ↓
4. ZK (generating a proof that the model ran correctly)
        ↓
5. Solidity (verifying that proof on-chain, in a smart contract)
```

**1. Data:** pairs of (CV, job posting) with a label stating whether they match or not.

**2. Embeddings:** a CV and a job posting are text, and a model doesn't work directly with text. Each text is therefore converted into a *vector* using an embedding model. The CV vector and the job vector are then joined together to form the model's input.

**3. Model:** a simple neural network that takes that input and returns a value: the higher it is, the more likely it is to be a "match".

**4. ZK (Zero-Knowledge):** instead of simply running the model and stating the result, a **cryptographic proof** is generated. This proof guarantees that *every operation of the model* (every multiplication, every addition, and so on) was performed correctly, with this specific model, and resulted in this output, without revealing the input.

**5. Solidity:** the proof can be verified in a **smart contract** on the blockchain. Anyone can confirm that the proof is valid, without trusting anyone.

---

## Decisions made (and why)

Several decisions were made throughout the project. Here are the main ones, explained in simple terms:

### A small, simple model (on purpose)
A small neural network was created. This wasn't for lack of ambition: in the ZK world, **the larger the model, the harder (or outright impossible) it becomes to generate the proof**. Every operation in the model has to be "translated" into the cryptographic circuit, so keeping it small is essential for the ZK part to work at all.

### Fighting overfitting
During training, the model started *memorizing* the training data instead of *learning* to generalize. Three techniques were used to fight this:

- **Dropout:** during training, part of the neurons are randomly "switched off", forcing the model to not rely too heavily on any single one and to learn more general patterns.
- **Weight decay:** penalizes the model for having very large weights, keeping it simpler.
- **Early stopping:** training is automatically stopped once the model stops improving on new data, keeping the best version instead of continuing to memorize.

Several versions of the model were compared based on their performance on the test set, using relevant evaluation metrics to identify the architecture that achieved the best generalization performance.

The final architecture is as follows:

```
Input (2048)  →  Linear (228)  →  ReLU  →  Dropout(0.5)
              →  Linear (64)   →  ReLU  →  Dropout(0.5)
              →  Linear (1)    →  logit
```

### Honest evaluation methodology
- The data was split into **train** and **test** sets.
- The **seed** was fixed when comparing architectures, so that comparisons would be fair (the only difference being the architecture, not luck).
- Evaluation was carried out using **accuracy, precision, recall, F1, and a confusion matrix**.

### Privacy with commitment (polycommit)
The ZK setup was configured so that both the **input** and the **model's weights** stay hidden, but with a cryptographic *commitment* (using `polycommit`). This means the proof reveals neither the CV nor the model, while still guaranteeing that the correct ones were used, addressing both privacy and trust at once.

---

## Results

The final model reaches roughly **84% accuracy**, with a good balance between the two classes:

| Class  | Precision | Recall | F1   |
|--------|-----------|--------|------|
| No Fit | 0.83      | 0.85   | 0.84 |
| Fit    | 0.85      | 0.83   | 0.84 |

And the model's inference is **proven in zero-knowledge**, and the verifier **compiles and runs in Solidity**.

---

## Technologies used

| Area                  | Technology |
|------------------------|-----------|
| Embedding model         | **BAAI/bge-m3** |
| Model training           | **PyTorch** |
| Evaluation metrics        | **scikit-learn** |
| Training visualization      | **TensorBoard** |
| Dataset                | **cnamuangtoun/resume-job-description-fit** (Hugging Face) |
| Zero-Knowledge ML        | **EZKL** |
| Smart contracts          | **Solidity** + **Foundry** |
| Web Application        | **Streamlit** |

---

## The dataset

The dataset used was **`cnamuangtoun/resume-job-description-fit`** (from Hugging Face), which contains pairs of (CV, job description) with a compatibility label.

The original dataset had three levels (`No Fit`, `Potential Fit`, `Good Fit`). Since the model is binary (match / no match), the labels were converted: **`No Match` → 0**, and everything else → **1**.

---

## How to run

### Prerequisites
- **Python 3.10+**
- **Foundry:** required by steps 5 and 7 to compile and test the Solidity contracts:
  ```bash
  curl -L https://foundry.paradigm.xyz | bash
  foundryup
  ```
  Make sure `forge` is on your `PATH` (`foundryup` installs it into `~/.foundry/bin`).

The training dataset (`resume_job_dataset.csv`) ships with the repository, so step 2 works
straight after cloning.

### 1. Setup environment
Create and activate a virtual environment, then install dependencies:
```bash
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
pip install -e .
```
The last step installs the project itself in editable mode, which puts the repository
root on Python's import path. Without it, the absolute imports used across the codebase
(`from ml.config import ...`, `from zk.src.prove import ...`) fail with
`ModuleNotFoundError` whenever a script is run directly or from another directory.
It only has to be done once per virtual environment.

### 2. Extract dataset embeddings (Optional if already extracted)
Before training, the text dataset must be converted into embeddings:
```bash
python -m ml.src.extract_embedding
```
This reads `resume_job_dataset.csv` and generates `cv_embeddings.pt`, `job_embeddings.pt`, `labels.pt`, and `metadata.json` inside `ml/data/embeddings/`.

### 3. Train the model
From the project root:
```bash
python -m ml.src.train
```
This loads the precomputed embeddings (`cv_embeddings.pt`, `job_embeddings.pt`, `labels.pt`), trains the neural network, evaluates it on the test split, and exports the model to the ONNX format (`ml/models/onnx/cv_model_v1.onnx`).

### 4. Monitor training with TensorBoard
To visualize the loss and accuracy curves logged during training:
```bash
tensorboard --logdir ml/runs
```
Then open `http://localhost:6006` in your browser.

### 5. Setup the ZK circuit
From the project root:
```bash
python -m zk.src.setup
```
This compiles the ONNX model into a Halo2/EZKL circuit, generates the proving (`pk.key`) and
verification (`vk.key`) keys, and writes the generated Solidity verifier straight into the Foundry
project at `contracts/src/Verifier.sol` (its ABI goes to `zk/verifier/abi.json`). No manual copying
is needed: that is the exact file `contracts/test/` and `contracts/script/` import.

### 6. Run the interactive Streamlit application
Launch the web interface:
```bash
streamlit run app.py
```
In the app, you can:
- Upload or paste a Resume (PDF or TXT) and a Job Description.
- Compute the semantic compatibility score.
- Generate the cryptographic ZK proof of inference.
- Verify the proof against the `CVMatchRegistry.sol` smart contract on the local EVM.

### 7. Test smart contracts
Inside the `contracts/` folder:
```bash
cd contracts
forge test
```
This compiles and runs the Foundry unit test suite, asserting that the smart contract properly verifies the generated ZK proof.

---

## Project structure

```
.
├── app.py           # Streamlit web application
├── ml/              # Machine learning (training, model, embeddings)
│   ├── data/        # Datasets and extracted embeddings
│   ├── models/      # Trained PyTorch model and ONNX exports
│   ├── runs/        # TensorBoard training logs
│   └── src/         # Python code (training, inference, embeddings)
├── zk/              # Zero-Knowledge (circuit, keys, proofs, verifier)
│   ├── circuit/     # Compiled circuit and settings
│   ├── keys/        # Proving (pk) and verification (vk) keys
│   ├── proofs/      # Generated ZK proofs and witnesses
│   ├── src/         # EZKL setup and prove scripts
│   └── verifier/    # ABI of the generated verifier (the .sol goes to contracts/src/)
└── contracts/       # Smart contracts (Foundry)
    ├── src/         # Solidity contracts (CVMatchRegistry, Verifier.sol generated by ezkl)
    ├── script/      # Verification script (VerifyProof)
    └── test/        # Foundry unit tests
```

---

## Notes and limitations

This is a learning and demonstration project. A few honest points about its limits:

- **Model size:** ZK imposes strong limits on model size. Larger models produce circuits that quickly become impractical to prove or to deploy on-chain. This is why the model was kept small.
- **Embeddings are outside the circuit:** the proof covers the classifier's execution; the generation of the embeddings (by bge-m3) is treated as a trusted step outside the proof.
- **Future work with NER (Named Entity Recognition):** a valuable future extension would be combining the semantic zkML model with a NER pipeline to extract key dealbreakers (such as required years of experience, specific certifications, and mandatory technical skills) for structured pre-screening.