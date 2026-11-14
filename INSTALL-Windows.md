# Installing and running on Windows 10/11

1. Python (skip if installed): https://www.python.org/downloads/windows/ ; tick "Add python.exe to PATH".
2. Rust: download `rustup-init.exe` (64-bit) from https://rustup.rs and run it.
   - If it asks for the Visual Studio C++ build tools, choose option 1 (install them via the
     Visual Studio installer; keep "Desktop development with C++" with the Windows SDK selected).
     Alternative download: https://visualstudio.microsoft.com/visual-cpp-build-tools/
   - When the build tools are installed, continue in the rustup window with the default option.
3. Close and reopen PowerShell, then check: `rustc --version` and `cargo --version`.
4. Download the repository to a short path, e.g. `git clone https://github.com/Alpha-QQ/pqssi-plus-experiments C:\pqssi`
   (or "Code" > "Download ZIP" and unpack it there), and open PowerShell in it: `cd C:\pqssi`
5. `py -m pip install -r requirements.txt`
6. Quick test: `py main.py smoke` (the first run downloads Plonky3 and compiles, about 10 minutes).
7. Paper run: `py main.py`. Results: `results\pqssi_plus_results.json`.

Tips for timing: plug in the laptop, use the "Best performance" power mode, close other programs.
On a CPU with performance and efficiency cores (e.g. Intel 12th gen), run the paper run on the
performance cores only: `cmd /c start /affinity 0xFFF /wait /b python main.py` (0xFFF = the 12 logical
processors of six P-cores on an i7-12700H; adjust the mask for other CPUs).
