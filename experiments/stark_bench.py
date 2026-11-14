"""PQSSI+ presentation benchmark on Plonky3 (Tables 4 and 6 of the paper), negative tests
(Table 5) and the wrap-around ablation.

Timing and negative tests run in separate processes: timing runs (with warm-up runs that are
not recorded) contain only honest presentations; the negative tests run afterwards in their own
process (NEG_ONLY=1). Every negative case goes through the full verifier (reference time, trace
height, nonce record, ML-DSA, STARK) and its outcome string is stored in the JSON."""
import os
import re
import subprocess

from . import stats, system

_SAMPLE = re.compile(r"sample n=(\d+) k=(\d+) issue_ms=([\d.]+) sign_ms=([\d.]+) prove_ms=([\d.]+) "
                     r"mldsa_verify_ms=([\d.]+) verify_ms=([\d.]+) proof_bytes=(\d+)")
_NEG = re.compile(r"negative test \[layer=([^\]]+)\] \[([^\]]+)\]: (.+)")
_DIAG = re.compile(r"diagnostic \[([^\]]+)\]: (.+)")
_BITS = re.compile(r"conjectured_ldt_bits<=(\d+)")
_SEC = re.compile(r"security n=(\d+) conjectured_bits=(\d+) proven_bits=(\d+) proven_udr_bits=(\d+) "
                  r"proven_ldr_bits=(\d+) legacy_bits=(\d+) conjectured_no_batch_pow_bits=(\d+)")
_CSV_HEAD = "n_attrs,height,width"

SIGNATURE_BYTES = 4627      # ML-DSA-87
PUBLIC_VALUE_BYTES = 12 * 4  # root[8] and nonce[4]; the verifier holds aud, today and the type identifier itself


def _env(fri, runs, n_only=None, warmup=0, extra=None):
    env = dict(os.environ)
    env.update({"LOG_BLOWUP": str(fri["log_blowup"]), "QUERIES": str(fri["queries"]),
                "ARITY": str(fri["arity"]), "POW": str(fri["pow"]),
                "BATCH_POW": str(fri.get("batch_pow", 10)), "RUNS": str(runs), "WARMUP": str(warmup)})
    if n_only:
        env["N_ONLY"] = str(n_only)
    env.update(extra or {})
    return env


def negative_cases(stderr, n):
    """Parse the negative-test lines of one NEG_ONLY run into a list of cases."""
    return [{"n": n, "layer": layer, "case": name, "outcome": outcome.strip()}
            for layer, name, outcome in _NEG.findall(stderr)]


def summarize_negatives(cases):
    """Counts per expected layer and per observed outcome."""
    by_layer = {}
    for c in cases:
        e = by_layer.setdefault(c["layer"], {"cases": 0, "outcomes": {}})
        e["cases"] += 1
        e["outcomes"][c["outcome"]] = e["outcomes"].get(c["outcome"], 0) + 1
    return by_layer


def run_config(binary, fri, runs, attribute_counts, pin_core, warmup=3, negative_tests=True):
    """Run one FRI configuration for each attribute count; return summaries and negative tests."""
    cmd = system.pin_prefix(pin_core) + [binary]
    out, err = "", ""
    cases, diagnostics = [], []
    for n in attribute_counts:
        o, e = system.run(cmd, _env(fri, runs, n, warmup))
        out, err = out + o, err + e
    if negative_tests:
        for n in attribute_counts:
            _, e = system.run(cmd, _env(fri, 1, n, 0, {"NEG_ONLY": "1"}))
            cases += negative_cases(e, n)
            diagnostics += [{"n": n, "check": k, "outcome": v.strip()} for k, v in _DIAG.findall(e)]
    samples = {}
    for m in _SAMPLE.finditer(err):
        n = int(m.group(1))
        d = samples.setdefault(n, {k: [] for k in ("issue_ms", "sign_ms", "prove_ms",
                                                   "mldsa_verify_ms", "verify_ms", "proof_bytes")})
        for key, val in zip(d.keys(), m.groups()[2:]):
            d[key].append(float(val))
    shape = {}
    for line in out.splitlines():
        if line and not line.startswith(_CSV_HEAD):
            f = line.split(",")
            shape[int(f[0])] = {"height": int(f[1]), "width": int(f[2])}
    per_n = {}
    for n, d in sorted(samples.items()):
        sizes = [int(x) for x in d["proof_bytes"]]
        payload = [s + SIGNATURE_BYTES + PUBLIC_VALUE_BYTES for s in sizes]
        verifier = [a + b for a, b in zip(d["verify_ms"], d["mldsa_verify_ms"])]
        per_n[str(n)] = {
            **shape.get(n, {}),
            "proof_bytes": stats.summarize(sizes),        # over all recorded runs
            "payload_bytes": stats.summarize(payload),
            "issue_ms": stats.summarize(d["issue_ms"]),
            "sign_ms": stats.summarize(d["sign_ms"]),
            "prove_ms": stats.summarize(d["prove_ms"]),
            "stark_verify_ms": stats.summarize(d["verify_ms"]),
            "mldsa_verify_ms": stats.summarize(d["mldsa_verify_ms"]),
            "verifier_total_ms": stats.summarize(verifier),
            "raw_samples": d,  # every recorded run (ms; proof_bytes in bytes)
        }
    bits = _BITS.search(err)
    honest = sum(len(d["prove_ms"]) for d in samples.values())
    security = {m.group(1): {"conjectured_instance_bits": int(m.group(2)), "proven_bits": int(m.group(3)),
                             "proven_udr_bits": int(m.group(4)), "proven_ldr_bits": int(m.group(5)),
                             "legacy_bits": int(m.group(6)),
                             "conjectured_instance_bits_without_batch_pow": int(m.group(7))}
                for m in _SEC.finditer(err)}
    return {"conjectured_ldt_bits": int(bits.group(1)) if bits else None,
            "security_by_n": security,  # Plonky3 estimators for the real instance (device-independent)
            "per_n": per_n,
            "negative_tests": summarize_negatives(cases),
            "negative_test_cases": cases,          # every case with its observed outcome
            "diagnostics": diagnostics,            # e.g. a height-2H proof passes the STARK check alone
            "honest_presentations_verified": honest}


def memory(binary, fri, n, runs, pin_core):
    """Peak memory (MiB) of a process that issues, proves and verifies `runs` honest presentations
    for n attributes, without negative tests or warm-up (None if the OS does not report it).
    The process also holds the ML-DSA key pair and the STARK configuration."""
    m = system.peak_memory_mib(system.pin_prefix(pin_core) + [binary], _env(fri, runs, n, 0))
    return None if m is None else round(m, 1)


def wrap_ablation(binary, fri, pin_core):
    """Negative control for Lemma 1: with the attribute range checks disabled (MASK=31) the
    wrap-around proof of birth = p-1 must be ACCEPTED by the full verifier, while every other
    AIR case is still rejected. Reads the outcome line of that case and the exit code."""
    env = _env(fri, 1, 1, 0, {"NEG_ONLY": "1", "MASK": "31", "ABLATION": "1"})
    p = subprocess.run(system.pin_prefix(pin_core) + [binary], env=env, capture_output=True, text=True, encoding="utf-8", errors="replace")
    cases = negative_cases(p.stderr, 1)
    wrap = [c["outcome"] for c in cases if c["case"] == "wrap-around birth date"]
    return {"range_checks_disabled": True, "return_code": p.returncode,
            "wrap_around_outcome": wrap[0] if wrap else None,
            "wrap_around_proof_verified": p.returncode == 0 and wrap == ["accepted"],
            "other_air_cases": {c["case"]: c["outcome"] for c in cases
                                if c["layer"] == "AIR" and c["case"] != "wrap-around birth date"}}
