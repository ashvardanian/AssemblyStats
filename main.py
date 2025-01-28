#!/usr/bin/env python
# -*- coding: utf-8 -*-

import os
import random
from typing import Generator

import pandas as pd
from tqdm import tqdm

from specs import BinarySpecs, Specs, restore_state, save_state
from specs_x86 import analyze_binary as analyze_binary_x86


def binaries_from(dir: str) -> Generator[str, None, None]:
    for x in os.listdir(dir):
        p = dir + x
        if os.access(p, os.X_OK):
            yield p


def all_binaries() -> Generator[str, None, None]:
    yield from binaries_from("/usr/bin/")
    yield from binaries_from("/usr/local/bin/")


def pretty_integer(value: int) -> str:
    """
    Formats the integer with comma as a thousands separator.
    E.g., 1234567 -> "1,234,567".
    """
    return f"{value:,}"


def pretty_percent(value: float, decimals: int = 2) -> str:
    """
    Converts a fraction to a percentage with a specified number
    of decimals. For example, 0.1234 -> "12.34%" if decimals=2.
    """
    return f"{value * 100:.{decimals}f}%"


def specs_to_register_sizes_dict(specs: BinarySpecs) -> dict:
    size = specs.total_instructions
    return {
        "Binary": specs.path,
        "Instructions": pretty_integer(size),
        "All SIMD": pretty_percent(specs.simd_instructions / size, 3),
        "128-bit SIMD": pretty_percent(
            specs.size_frequencies.get("128", 0.0) / size, 3
        ),
        "256-bit SIMD": pretty_percent(
            specs.size_frequencies.get("256", 0.0) / size, 3
        ),
        "512-bit SIMD": pretty_percent(
            specs.size_frequencies.get("512", 0.0) / size, 3
        ),
    }


if __name__ == "__main__":

    specs: Specs = restore_state()
    print(f"Restored a state with {len(specs)} entries")

    bins = [x for x in all_binaries() if x not in specs]
    print(f"Want to analyze the remaining {len(bins)} binaries")
    random.shuffle(bins)

    try:
        for x in tqdm(bins, unit="binaries"):
            try:
                specs[x] = analyze_binary_x86(x)
                if len(specs) % 50 == 0:
                    save_state(specs)
            except Exception as e:
                print(f"Faced error: {e}")
                specs[x] = BinarySpecs(x)

        save_state(specs)

    except BaseException:
        save_state(specs)

    print(f"Will sort and export {len(specs)} entries")
    top_list = list(
        sorted(specs.values(), key=lambda x: x.total_instructions, reverse=True)
    )
    top_list = top_list[:100]
    dicts = [specs_to_register_sizes_dict(x) for x in top_list]

    df = pd.DataFrame(dicts)
    text = df.to_markdown(index=False)

    with open("main.md", "w") as f:
        f.write(text)
    print(f"Exported\n {df.to_string()}")
