"""Fetch Plonky3 at the pinned commit, add the PQSSI+ crate, and build both Rust programs."""
import io
import os
import sys
import shutil
import subprocess
import urllib.request
import zipfile
from pathlib import Path

HERE = Path(__file__).resolve().parent.parent
EXE = ".exe" if sys.platform == "win32" else ""
RUST = HERE / "rust"


def _download_plonky3(commit, dest):
    url = f"https://github.com/Plonky3/Plonky3/archive/{commit}.zip"
    try:
        print(f"[build] downloading {url}")
        data = urllib.request.urlopen(url, timeout=120).read()
        with zipfile.ZipFile(io.BytesIO(data)) as z:
            top = z.namelist()[0].split("/")[0]
            z.extractall(dest.parent)
        (dest.parent / top).rename(dest)
        return
    except Exception as e:  # fall back to git if the archive cannot be fetched
        print(f"[build] archive download failed ({e}); trying git")
    subprocess.run(["git", "clone", "-q", "https://github.com/Plonky3/Plonky3", str(dest)], check=True)
    subprocess.run(["git", "-C", str(dest), "checkout", "-q", commit], check=True)


def _patch_plonky3(root):
    """The two changes of the paper's artifact: add the workspace member, make Poseidon2-AIR eval public."""
    cargo = root / "Cargo.toml"
    text = cargo.read_text(encoding="utf-8")
    if '"pqssi-plus"' not in text:
        text = text.replace("members = [", 'members = [\n    "pqssi-plus",', 1)
        cargo.write_text(text, encoding="utf-8")
    air = root / "poseidon2-air" / "src" / "air.rs"
    text = air.read_text(encoding="utf-8")
    if "pub(crate) fn eval<" in text:
        air.write_text(text.replace("pub(crate) fn eval<", "pub fn eval<", 1), encoding="utf-8")
    crate = root / "pqssi-plus"
    (crate / "src").mkdir(parents=True, exist_ok=True)
    shutil.copy(RUST / "p3" / "Cargo.toml", crate / "Cargo.toml")
    shutil.copy(RUST / "p3" / "main.rs", crate / "src" / "main.rs")
    # lockfile of the patched workspace (pins fips204 and every other dependency)
    shutil.copy(RUST / "p3" / "Cargo.lock", root / "Cargo.lock")


def build(cfg):
    """Return paths of the Plonky3 and Plonky2 binaries, building them if needed."""
    work = Path(cfg["work_dir"]).resolve()
    work.mkdir(parents=True, exist_ok=True)
    p3root = Path(cfg["plonky3_dir"]).resolve() if cfg.get("plonky3_dir") else work / "Plonky3"
    if not (p3root / "Cargo.toml").exists():
        _download_plonky3(cfg["plonky3_commit"], p3root)
    _patch_plonky3(p3root)
    env = dict(os.environ)
    print("[build] cargo build (Plonky3 prototype); the first build takes several minutes")
    subprocess.run(["cargo", "build", "--release", "--locked", "-p", "pqssi-plus"], cwd=p3root, env=env, check=True)
    p3bin = p3root / "target" / "release" / f"pqssi-plus{EXE}"

    p2dir = work / "plonky2-baseline"
    if p2dir.exists():
        shutil.rmtree(p2dir / "src", ignore_errors=True)
    shutil.copytree(RUST / "p2", p2dir, dirs_exist_ok=True)
    # Plonky2 1.1.0 uses nightly-only features; RUSTC_BOOTSTRAP=1 lets the stable compiler build it.
    env["RUSTC_BOOTSTRAP"] = "1"
    print("[build] cargo build (Plonky2 baseline)")
    subprocess.run(["cargo", "build", "--release", "--locked"], cwd=p2dir, env=env, check=True)
    p2bin = p2dir / "target" / "release" / f"pqssi_plus{EXE}"
    return str(p3bin), str(p2bin)
