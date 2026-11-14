"""PQSSI+ experiments: the only file you need to run or edit.

    python main.py                  # full run with the paper's settings (MODE = "paper")
    python main.py smoke            # a few seconds of each experiment, to check the setup
    (on Windows "py main.py ..." also works; on macOS/Linux use python3)

All settings and results are written to one JSON file (OUTPUT below). Timings depend on the
machine; the "device" block of the JSON records which machine produced them.
"""
import json
import sys
import time
from pathlib import Path

from experiments import b1_attack, build, plonky2_bench, stark_bench, system, transmission

# ------------------------------------------------------------------ settings to edit
MODE = "paper"                       # "paper" or "smoke" (also selectable on the command line)
OUTPUT = "results/pqssi_plus_results.json"
PIN_CORE = 0                         # pin benchmarks to this core (Linux only; ignored on Windows/macOS)
WARMUP = 3                           # unrecorded warm-up runs before each timed series
THREADS = 1                          # worker threads for the provers (RAYON_NUM_THREADS); 1 = single-thread,
                                     # which is what the paper's comparison uses. Plonky3 is built without its
                                     # "parallel" feature and is single-threaded regardless.

BUILD = {
    "work_dir": "build",             # Plonky3 source and both Rust builds go here
    "plonky3_commit": "a4982ec0f2842a0bf3a35ab2f961ddeb2e6d418c",
    "plonky3_dir": None,            # path to an existing Plonky3 checkout, or None to download
}

PAPER = {
    "run": {"b1_attack": True, "plonky3": True, "negative_tests": True, "memory": True,
            "wrap_ablation": True, "plonky2": True, "transmission": True},
    "b1_attack": {"years": 100, "codes": 10, "rate_samples": 200_000,
                  "secret": {"birthDate": "1987-03-14", "diagnosisCategory": "F32"}},  # synthetic
    # Table 4: four FRI configurations near 120 bits (classical conjectured, LDT-only);
    # batch_pow = proof-of-work bits on FRI batching (credited by Plonky3's estimator)
    "plonky3": {
        "runs": 30,
        "attribute_counts": [1, 5, 10, 20, 40],
        "fri_configs": [
            {"log_blowup": 2, "queries": 56, "arity": 1, "pow": 16, "batch_pow": 10},
            {"log_blowup": 3, "queries": 38, "arity": 3, "pow": 16, "batch_pow": 10},
            {"log_blowup": 4, "queries": 28, "arity": 3, "pow": 16, "batch_pow": 10},
            {"log_blowup": 5, "queries": 23, "arity": 3, "pow": 16, "batch_pow": 10},
        ],
        "memory_attribute_counts": [1, 40],
        "memory_runs": 3,
    },
    # Table 9: Plonky2 baseline at 121 bits (rate 2^-3, 35 queries, 16 grinding bits, FRI arity 2)
    "plonky2": {"runs": 30, "n_attrs": 1, "rate_bits": 3, "queries": 35, "pow": 16,
                "arity_bits": 1, "final_bits": 2, "memory_runs": 3,
                "all_threads_reference": True},   # also run Plonky2 on all cores (context only)
    # Table 7: throughputs in bit/s (BLE ack., Zigbee, optimised BLE, Wi-Fi-class)
    "transmission": {"rates_bps": [130_000, 250_000, 1_300_000, 10_000_000],
                     "pqssi_reported_presentation_bytes": 16_336},
}

SMOKE = {
    "run": PAPER["run"],
    "b1_attack": {"years": 2, "codes": 10, "rate_samples": 5_000,
                  "secret": {"birthDate": "1927-03-14", "diagnosisCategory": "F32"}},
    "plonky3": {"runs": 2, "attribute_counts": [1],
                "fri_configs": [{"log_blowup": 3, "queries": 38, "arity": 3, "pow": 16, "batch_pow": 10}],
                "memory_attribute_counts": [1], "memory_runs": 1},
    "plonky2": {**PAPER["plonky2"], "runs": 1, "memory_runs": 1},
    "transmission": PAPER["transmission"],
}
# ------------------------------------------------------------------ end of settings


def fri_label(f):
    return f"{f['log_blowup']}_{f['queries']}_{f['arity']}"


def main():
    mode = sys.argv[1] if len(sys.argv) > 1 else MODE
    cfg = {"paper": PAPER, "smoke": SMOKE}[mode]
    run = cfg["run"]
    t0 = time.time()
    results = {}
    print(f"[main] mode = {mode}")

    if run["b1_attack"]:
        print("[main] B1 attribute recovery")
        b = cfg["b1_attack"]
        results["b1_attack"] = b1_attack.run(b["years"], b["codes"], b["secret"], b["rate_samples"])

    need_rust = any(run[k] for k in ("plonky3", "negative_tests", "memory", "wrap_ablation", "plonky2"))
    if need_rust:
        p3bin, p2bin = build.build(BUILD)

    if run["plonky3"] or run["negative_tests"]:
        p3 = cfg["plonky3"]
        results["plonky3"] = {}
        for f in p3["fri_configs"]:
            print(f"[main] Plonky3 presentation, FRI {fri_label(f)}")
            r = stark_bench.run_config(p3bin, f, p3["runs"], p3["attribute_counts"], PIN_CORE,
                                       WARMUP, run["negative_tests"])
            if run["memory"]:
                r["peak_memory_mib"] = {str(n): stark_bench.memory(p3bin, f, n, p3["memory_runs"], PIN_CORE)
                                       for n in p3["memory_attribute_counts"]}
            results["plonky3"][fri_label(f)] = r
        results["negative_tests_total"] = stark_bench.summarize_negatives(
            [c for r in results["plonky3"].values() for c in r["negative_test_cases"]])
        results["honest_presentations_verified_total"] = sum(
            r["honest_presentations_verified"] for r in results["plonky3"].values())

    if run["wrap_ablation"]:
        print("[main] wrap-around ablation (range checks disabled)")
        results["wrap_ablation"] = stark_bench.wrap_ablation(p3bin, cfg["plonky3"]["fri_configs"][0], PIN_CORE)

    if run["plonky2"]:
        p2 = cfg["plonky2"]
        print("[main] Plonky2 baseline")
        results["plonky2"] = plonky2_bench.run(p2bin, p2, p2["runs"], p2["n_attrs"], PIN_CORE,
                                               run["memory"], p2["memory_runs"], THREADS, WARMUP)
        if p2.get("all_threads_reference"):
            print("[main] Plonky2 baseline, all threads (context only)")
            results["plonky2_all_threads"] = plonky2_bench.run(p2bin, p2, p2["runs"], p2["n_attrs"], None,
                                                               False, 1, 0, WARMUP)
        p3ref = results.get("plonky3", {}).get("3_38_3", {}).get("per_n", {}).get(str(p2["n_attrs"]))
        if p3ref:
            results["speedup_plonky3_3_38_3_over_plonky2_zk"] = round(
                results["plonky2"]["zk"]["prove_ms"]["median"] / p3ref["prove_ms"]["median"], 2)

    if run["transmission"]:
        tr = cfg["transmission"]
        payloads = {"PQSSI (reported presentation, context only)": tr["pqssi_reported_presentation_bytes"]}
        for label, r in results.get("plonky3", {}).items():
            first = r["per_n"].get("1")
            if first:
                payloads[f"PQSSI+ {label} (cryptographic payload, n=1, median)"] = first["payload_bytes"]["median"]
        results["transmission_lower_bound_s"] = transmission.table(payloads, tr["rates_bps"])

    out = {"paper": "Attribute Recovery and Linkability in the PQSSI Post-Quantum Credential Framework: Analysis and a Repair under Explicit Proof-System Assumptions",
           "mode": mode, "settings": {"build": BUILD, **cfg, "pin_core": PIN_CORE, "threads": THREADS, "warmup": WARMUP},
           "results": results, "device": system.describe(),
           "wall_clock_s": round(time.time() - t0, 1)}
    path = Path(OUTPUT)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(out, indent=2), encoding="utf-8")
    print(f"[main] done in {out['wall_clock_s']} s; results written to {path}")


if __name__ == "__main__":
    main()
