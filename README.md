# VectorDossier

VectorDossier is a Python micro-project that _statically_ analyzes _vectorization_ depth of programs and libraries.

Most CPUs produced in the last twenty years have SIMD (Single Instruction, Multiple Data) instructions, which allow the same operation to be performed on multiple data elements simultaneously within a single core.
Yet, most compilers can't magically map complex high-level abstractions to SIMD instructions, so the programmer has to do it manually.
Most of us are too lazy to do it, even when there is a [10-100x performance gain to be unlocked compared to good C/C++ code](https://ashvardanian.com/posts/gcc-12-vs-avx512fp16/), and [over 1000x against Python](https://ashvardanian.com/posts/python-c-assembly-comparison/).

This project checks how well different SIMD Assembly instructions are used in different binaries, utilizing the Capstone disassembler to count:

- [x] on x86: SSE, AVX, AVX2, AVX-512, AES, SHA, AMX, etc.
- [x] on Arm: NEON, SVE, SVE2, SME, etc.
- [ ] on Nvidia: FMA, MMA, DPX, etc.

The astonishing results show that often less than 1% of generated lines even reference vector registers.
Let alone use them effectively.

> The original publication was titled ["Only 1% of Software Benefits from SIMD Instructions"](https://ashvardanian.com/posts/simd-popularity/) and the broader ["Less Slow" blog](https://ashvardanian.com/tags/less-slow/) contains many more related articles.

## Project Structure

- `specs_amd64.py` classifies 64-bit x86 instructions by the register size and port usage, allowing better port utilization opportunities to be found.
- `specs_aarch64.py` - classifies 64-bit Arm instructions by the register size, including variable-length SVE registers.
- `specs_amd64.csv` - provides a machine-readable list of ports and latencies for relevant x86 generations, including Haswell, Skylake-X, Ice Lake, Alder Lake-P, Alder Lake-E, Zen 2, and Zen 4, obtained from [uops.info](https://uops.info/table).
- `specs_aarch64.csv` - provides a machine-readable list of instruction latencies obtained from Arm's performance-tuning guides.
- `specs_ptx.csv` - provides a machine-readable list of instruction latencies obtained from Nvidia's performance-tuning guides for V100, A100, and H100 GPUs.
- `main.py` - provides a script capable of dissecting either a specific binary or aggregating statistics across many directories.

![Clusters](/assets/topic_modeling.png)

## Running Locally

```py
git clone https://github.com/ashvardanian/less_slow.py.git # Clone the repository
cd less_slow.py                                            # Change the directory
pip install -r requirements.txt                            # Install the dependencies
main.py --help                                             # Check the available options
```

Alternatively, run the benchmarks in a controlled environment using [`uv`](https://docs.astral.sh/uv/getting-started/installation/).

```sh
uv run --python="3.12" --no-sync \
    --with-requirements requirements.in \
    main.py --help
```

For `uv`, the `--no-sync` flag prevents `uv` from creating a `uv.lock` file or modifying an existing `.venv` folder.
To extend the current list of dependencies, update the `requirements.in` file and run `uv sync` to update the environment.

```sh
uv pip compile requirements.in --universal --output-file requirements.txt
uv pip sync requirements.txt
```