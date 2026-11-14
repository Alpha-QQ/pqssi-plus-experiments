# PQSSI+ experiments

Code for the experiments of *Attribute Recovery and Linkability in the PQSSI Post-Quantum Credential
Framework: Analysis and a Repair under Explicit Proof-System Assumptions*. All attribute data are synthetic.

## What you need (once)
1. Python 3.9 or newer, and `pip install -r requirements.txt` (the `blake3` package).
2. Rust (https://rustup.rs). On macOS, first run `xcode-select --install`.
   The Plonky3 and Plonky2 proof systems exist only as Rust libraries, so `main.py` builds two small
   Rust programs and drives them; you never call Rust yourself.
3. Internet access on the first run: Plonky3 is downloaded at the pinned commit `a4982ec0`
   (a zip archive; git is used only as a fallback). Both builds use the shipped lockfiles (`--locked`).
   Plonky2 1.1.0 uses nightly-only features; the build sets `RUSTC_BOOTSTRAP=1` so that a stable
   Rust compiler can build it.

## Windows
See `INSTALL-Windows.md` for step-by-step installation. Unzip to a short path such as `C:\pqssi`.
Peak memory on Windows is the peak working set of the process. Use the "Balanced" power plan,
plug in a laptop, and close other programs while measuring.

## Run
```
python main.py smoke     # about a minute after the first build: checks that everything works
python main.py           # the paper's settings (several minutes after the build on a desktop; longer on slower machines)
```
The first run also compiles both Rust programs (5-10 minutes). Everything goes to
`results/pqssi_plus_results.json`. Settings are at the top of `main.py` (`PAPER` and `SMOKE`).

## Measurement protocol
- The issuer refuses attributes outside the schema ranges; the input-validation tests check this.
- Every timed series starts with `WARMUP` (default 3) unrecorded runs; 30 runs are recorded.
- Timing processes contain only honest presentations. The negative tests run afterwards in a
  separate process for each configuration and attribute count.
- Proof sizes vary slightly from run to run (variable-length encoding); the JSON keeps the size of
  every run and reports median, minimum and maximum.
- Peak memory is in MiB (2^20 bytes). For Plonky3 it is the peak of a process that issues, proves and
  verifies three presentations; for Plonky2 it also includes constructing the zero-knowledge circuit.

## Layout
| File | Purpose |
|---|---|
| `main.py` | the only file to run or edit: settings, which experiments to run, output path |
| `experiments/b1_attack.py` | B1: dictionary attack on the unsalted PQSSI commitment (Sect. 9.1) |
| `experiments/stark_bench.py` | PQSSI+ on Plonky3: proving, verification, sizes, security estimates, negative tests, memory, wrap-around ablation (Tables 4-6) |
| `experiments/plonky2_bench.py` | Plonky2 baseline with and without zero-knowledge (Table 9; single-thread, plus an all-threads reference) |
| `experiments/transmission.py` | lower bound 8l/R on transmission time (Table 7) |
| `experiments/stats.py` | mean, standard deviation, median, quartiles, minimum, maximum |
| `experiments/system.py` | device description, core pinning (Linux only), peak memory |
| `experiments/build.py` | downloads Plonky3, adds the PQSSI+ crate and lockfile, builds both programs |
| `rust/p3/` | PQSSI+ AIR, verifier and benchmark (Rust, Plonky3); `Cargo.lock` of the patched workspace |
| `rust/p2/` | Plonky2 baseline (Rust) |

## The verifier
`rust/p3/main.rs`, `PresVerifier::verify`, checks in this order: the reference time, the proof's trace
height against the type's height H (`degree_bits = log2 H + 1` in zero-knowledge mode), the nonce
record (a nonce must have been issued by this verifier for this type and day, must not have
expired, `NONCE_TTL_MS`, and is accepted at most once), the ML-DSA-87
signature on the root, and the STARK proof against the statement (root, nonce, audience, today, type
identifier) that the verifier assembles itself. The type identifier hashes the schema, policy,
parameter version, FRI parameters and trace height, and the AIR fixes it.

## JSON keys and the paper
- `results.b1_attack`: Sect. 9.1 (fixture: verifier-visible fields, hidden claims, encoding and
  dictionary; candidate space, tries, seconds, hash rate, expected time for a uniform secret).
- `results.plonky3.<blowup>_<queries>_<arity>.conjectured_ldt_bits` and `.security_by_n`: Table 4 "bits"
  (parameter-level LDT-only / conjectured for the real instance, with and without the batching
  proof-of-work / proven), from Plonky3's security module with floor(log2 |K|) = 123.
- `results.plonky3.<...>.per_n.<n>`: Table 4 (prove, verify, proof bytes) and Table 6 (issue,
  verifier total, payload bytes); `peak_memory_mib`: Table 6 memory.
- `results.plonky3.<...>.negative_test_cases`: every negative case with its observed outcome;
  `negative_tests` and `results.negative_tests_total`: counts per layer and outcome (Table 5);
  `diagnostics`: whether a height-2H proof passes the STARK check alone (it does, which is why the
  verifier checks the height).
- `results.wrap_ablation`: Lemma 1 control; with the attribute range checks removed, the wrap-around
  proof is accepted by the full verifier (`wrap_around_outcome`) while the other AIR cases are still rejected.
- `results.honest_presentations_verified_total`: recorded honest presentations, all accepted.
- `results.plonky2`, `results.speedup_plonky3_3_38_3_over_plonky2_zk`: Table 9 and Sect. 9.4 (single thread).
- `results.plonky2_all_threads`: Plonky2 with every logical CPU, context only.
- `results.transmission_lower_bound_s`: Table 7.
- `device`: the machine that produced the timings; timings are device-dependent, all other values are not.

Every timing entry has `n`, `mean`, `std` (sample), `median` (conventional: mean of the two middle values
for an even count), `p25`, `p75` (nearest rank), `min`, `max`.
On Windows and macOS, core pinning is skipped; the provers are still limited to one worker thread
(`THREADS = 1`).
