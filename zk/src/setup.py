import asyncio
import ezkl

from zk.config import (
    MODEL_ONNX_PATH,
    DEFAULT_INPUT_PATH,
    SETTINGS_PATH,
    COMPILED_MODEL_PATH,
    VK_PATH,
    PK_PATH,
    VERIFIER_SOL_PATH,
    ABI_PATH,
)


async def main():
    # Configuração de visibilidade: modelo + input privados, output público
    run_args = ezkl.PyRunArgs()
    run_args.param_visibility = "polycommit"
    run_args.input_visibility = "polycommit"
    run_args.output_visibility = "public"

    assert ezkl.gen_settings(str(MODEL_ONNX_PATH), str(SETTINGS_PATH), py_run_args=run_args)
    assert ezkl.calibrate_settings(str(DEFAULT_INPUT_PATH), str(MODEL_ONNX_PATH), str(SETTINGS_PATH), target="resources")
    assert ezkl.compile_circuit(str(MODEL_ONNX_PATH), str(COMPILED_MODEL_PATH), str(SETTINGS_PATH))
    assert await ezkl.get_srs(str(SETTINGS_PATH))
    assert ezkl.setup(str(COMPILED_MODEL_PATH), str(VK_PATH), str(PK_PATH))

    VERIFIER_SOL_PATH.parent.mkdir(parents=True, exist_ok=True)
    ABI_PATH.parent.mkdir(parents=True, exist_ok=True)
    await ezkl.create_evm_verifier(str(VK_PATH), str(SETTINGS_PATH), str(VERIFIER_SOL_PATH), str(ABI_PATH))
    print(f"Setup completed. EVM verifier written to {VERIFIER_SOL_PATH}")


if __name__ == "__main__":
    asyncio.run(main())
