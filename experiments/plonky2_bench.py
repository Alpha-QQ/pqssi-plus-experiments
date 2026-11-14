"""Plonky2 baseline of a related statement (Table 9 and Sect. 9.4 of the paper).

The circuit uses Plonky2's standard recursion configuration (135 wires, 80 routed wires), the
configuration Plonky2 ships for zero-knowledge proofs; with FRI arity 2 the zero-knowledge
blinding rows are minimal. Timings exclude circuit construction; the memory figure is the peak of
a process that constructs the zero-knowledge circuit once and then proves (ZK_ONLY=1)."""
import os
import re

from . import stats, system

_SAMPLE = re.compile(r"sample n=(\d+) zk=(true|false) prove_ms=([\d.]+) verify_ms=([\d.]+) "
                     r"sign_ms=([\d.]+) mldsa_verify_ms=([\d.]+) proof_bytes=(\d+)")
_ROW = re.compile(r"^(\d+),(true|false),(\d+),", re.M)


def _env(p2, runs, n, threads, warmup=3, extra=None):
    env = dict(os.environ)
    env.pop("RAYON_NUM_THREADS", None)
    if threads:  # 0 or None = let rayon use every logical CPU
        env["RAYON_NUM_THREADS"] = str(threads)
    env.update({"RATE": str(p2["rate_bits"]), "QUERIES": str(p2["queries"]), "POW": str(p2["pow"]),
                "ARITY": str(p2["arity_bits"]), "FINAL": str(p2["final_bits"]),
                "RUNS": str(runs), "WARMUP": str(warmup), "N_LIST": str(n)})
    env.update(extra or {})
    return env


def run(binary, p2, runs, n, pin_core, measure_memory=True, memory_runs=3, threads=1, warmup=3):
    """Run the baseline with and without zero-knowledge for n attributes.

    threads: RAYON_NUM_THREADS for the prover (1 = single-thread, 0 = all logical CPUs).
    """
    cmd = system.pin_prefix(pin_core) + [binary]
    out, err = system.run(cmd, _env(p2, runs, n, threads, warmup))
    res = {}
    rows = {zk: int(deg) for _, zk, deg in _ROW.findall(out)}
    for zk in ("true", "false"):
        s = [m for m in _SAMPLE.finditer(err) if m.group(2) == zk]
        res["zk" if zk == "true" else "no_zk"] = {
            "log2_rows": rows.get(zk),
            "proof_bytes": stats.summarize([int(m.group(7)) for m in s]),
            "prove_ms": stats.summarize([float(m.group(3)) for m in s]),
            "verify_ms": stats.summarize([float(m.group(4)) for m in s]),
            "raw_samples": {"prove_ms": [float(m.group(3)) for m in s],
                            "verify_ms": [float(m.group(4)) for m in s]},
        }
    if measure_memory:
        m = system.peak_memory_mib(cmd, _env(p2, memory_runs, n, threads, 0, {"ZK_ONLY": "1", "NO_NEG": "1"}))
        res["peak_memory_mib_including_circuit_construction"] = None if m is None else round(m, 1)
    res["threads"] = threads if threads else "all"
    return res
