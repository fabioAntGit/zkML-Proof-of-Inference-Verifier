import json
import math
import subprocess
from pathlib import Path
import streamlit as st

from ml.src.inference import inference
from ml.src.utils import extract_text_from_pdf
from zk.config import PROOF_PATH


st.set_page_config(
    page_title="zkML Proof-of-Inference | CV Matcher",
    layout="wide",
)

st.title("zkML Proof-of-Inference Verifier | CV Matcher")
st.markdown(    
    """
    Evaluate candidate-job compatibility with **Zero-Knowledge Machine Learning**.
    """
)

st.divider()

col1, col2 = st.columns(2)

with col1:
    st.subheader("CV")
    cv_file = st.file_uploader("Upload CV (.txt or .pdf)", type=["txt", "pdf"])
    cv_text_input = ""

    if cv_file is not None:
        if cv_file.type == "application/pdf":
            cv_text_input = extract_text_from_pdf(cv_file.read())
        else:
            cv_text_input = cv_file.read().decode("utf-8")

    cv_text = st.text_area(
        "Resume Text:",
        value=cv_text_input,
        height=260,
        placeholder="Paste resume text here or upload a file above...",
    )

with col2:
    st.subheader("Job Description")
    job_file = st.file_uploader("Upload Job Description (.txt)", type=["txt"])
    job_text_input = ""

    if job_file is not None:
        job_text_input = job_file.read().decode("utf-8")

    job_text = st.text_area(
        "Job Description Text:",
        value=job_text_input,
        height=260,
        placeholder="Paste job description requirements here...",
    )

st.divider()

submit_btn = st.button("Evaluate Compatibility & Generate ZK Proof", type="primary", use_container_width=True)

if submit_btn:
    if not cv_text.strip() or not job_text.strip():
        st.warning("Please provide both the Resume and the Job Description before proceeding.")
    else:
        with st.spinner("Generating embeddings and computing ZK proof of inference..."):
            try:
                result = inference(cv_text, job_text)
                st.session_state["latest_result"] = result
            except Exception as e:
                st.error(f"Execution error: {e}")

if "latest_result" in st.session_state:
    result = st.session_state["latest_result"]
    prob = result["probability"]
    is_match = result["match"]
    actual_proof_path = result.get("proof_path", str(PROOF_PATH))

    st.subheader("Inference Results")

    res_col1, res_col2 = st.columns([1, 2])

    with res_col1:
        st.metric(
            label="Match Probability",
            value=f"{prob * 100:.1f}%",
            delta="Fit" if is_match else "No Fit",
        )
        st.progress(min(max(prob, 0.0), 1.0))

    with res_col2:
        if is_match:
            st.success("**MATCH CERTIFIED!** Candidate profile meets the job requirements.")
        else:
            st.error("**NO MATCH.** Candidate profile does not satisfy the minimum compatibility threshold.")

        st.info("**Zero-Knowledge Proof successfully generated!**")
        if Path(actual_proof_path).is_file():
            with open(actual_proof_path, "r") as f:
                proof_data = json.load(f)
            hex_proof = proof_data.get("hex_proof", "")
            raw_logit = float(proof_data["pretty_public_inputs"]["rescaled_outputs"][0][0])
            proof_prob = 1 / (1 + math.exp(-raw_logit))
            st.caption(f"Proof file: `{actual_proof_path}`")
            with st.expander("View ZK Proof Details (Hex Proof / Circuit Output)"):
                st.write(
                    f"**Circuit Output (from ZK proof):** logit = {raw_logit:.4f} "
                    f"→ probability = {proof_prob * 100:.2f}%"
                )
                st.caption(
                    "This value is cryptographically bound to the proof above — anyone can verify "
                    "it matches the model's computation without re-running the model."
                )
                st.text_area("Hex Proof (bytes for Smart Contract):", hex_proof[:200] + "...", height=80)

    st.divider()
    st.subheader("Smart Contract (CVMatchRegistry)")

    if st.button("Check hasCertifiedMatch on Smart Contract", type="secondary", use_container_width=True):
        with st.spinner("Calling CVMatchRegistry contract..."):
            contracts_dir = Path(__file__).resolve().parent / "contracts"
            proof_name = Path(actual_proof_path).name
            forge_bin = str(Path.home() / ".foundry/bin/forge") if (Path.home() / ".foundry/bin/forge").is_file() else "forge"
            cmd = [forge_bin, "script", "script/VerifyProof.s.sol:VerifyProofScript", "--sig", "run(string)", f"../zk/proofs/{proof_name}"]
            proc = subprocess.run(cmd, cwd=str(contracts_dir), capture_output=True, text=True)

            if proc.returncode == 0:
                st.success("hasCertifiedMatch: true")
            else:
                st.error("hasCertifiedMatch: false")
