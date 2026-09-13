import ezkl
import json
import asyncio


async def main():
    model_path = "ml/models/onnx/cv_model_v1.onnx"
    input_path = "ml/models/onnx/data/cv_model_v1/input.json"
    settings_path = "zk/circuit/settings.json"
    compiled_path = "zk/circuit/model.compiled"
    vk_path = "zk/keys/vk.key"
    pk_path = "zk/keys/pk.key"
    witness_path = "zk/proofs/witness.json"
    proof_path = "zk/proofs/proof.json"
    sol_code_path = "zk/verifier/verifier.sol"
    abi_path = "zk/verifier/abi.json"

    # ---- config de visibilidade: modelo + input privados, output público ----
    run_args = ezkl.PyRunArgs()
    run_args.param_visibility = "fixed" 
    run_args.input_visibility = "private"
    run_args.output_visibility = "public"

    res = ezkl.gen_settings(model_path, settings_path, py_run_args=run_args)
    assert res == True

    res = ezkl.calibrate_settings(input_path, model_path, settings_path, target="accuracy")
    assert res == True

    res = ezkl.compile_circuit(model_path, compiled_path, settings_path)
    assert res == True

    res = await ezkl.get_srs(settings_path)
    assert res == True

    res = ezkl.setup(compiled_path, vk_path, pk_path)
    assert res == True

    res = ezkl.gen_witness(input_path, compiled_path, witness_path)

    res = ezkl.prove(witness_path, compiled_path, pk_path, proof_path)

    res = ezkl.verify(proof_path, settings_path, vk_path)
    assert res == True
    print("Prova gerada e verificada com sucesso!")

    res = await ezkl.create_evm_verifier(vk_path, settings_path, sol_code_path, abi_path)
    print (res)
    print ("type :" , type(res))
    print("Verificador EVM criado com sucesso!")

if __name__ == "__main__":
    asyncio.run(main())