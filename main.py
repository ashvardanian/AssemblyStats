#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
AssemblyStats main script

This script scans specified directories for executables, analyzes them to collect
statistics on instruction usage (especially SIMD), and exports a Markdown file
of the top binaries (by total instructions). It stores partial results in a
persistent "Specs" object, so you don't lose progress if the script is interrupted.
"""

import os
import random
import sys
import argparse
import platform
from typing import Generator, List, Dict

import pandas as pd
from tqdm import tqdm

from specs import BinarySpecs, Specs, restore_state, save_state
from specs_amd64 import analyze_binary as analyze_binary_amd64
from specs_aarch64 import analyze_binary as analyze_binary_aarch64


def analyze_binary(binary_path: str) -> BinarySpecs:
    """
    Analyzes a binary file and returns a BinarySpecs object.
    """
    if platform.machine() == "aarch64":
        return analyze_binary_aarch64(binary_path)
    elif platform.machine() == "x86_64":
        return analyze_binary_amd64(binary_path)
    else:
        raise ValueError(f"Unsupported platform: {platform.machine()}")


def binaries_from(directory: str) -> Generator[str, None, None]:
    """
    Yields all executables from the given directory.
    """
    for filename in os.listdir(directory):
        path = os.path.join(directory, filename)
        # Check both 'is executable' and 'is not a directory'
        if os.access(path, os.X_OK) and not os.path.isdir(path):
            yield path


def all_binaries(directories: List[str]) -> Generator[str, None, None]:
    """
    Gathers executables from a list of directories.
    """
    for directory in directories:
        yield from binaries_from(directory)


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


def specs_to_register_sizes_dict(specs: BinarySpecs) -> Dict[str, str]:
    """
    Converts a BinarySpecs object to a dictionary with
    pretty-printed fields for easier reading/export.
    """
    size = specs.total_instructions or 1  # Avoid division by zero
    return {
        "Binary": specs.path,
        "Instructions": pretty_integer(specs.total_instructions),
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


def analyze_and_update_specs(
    binaries: List[str],
    specs: Specs,
    save_every: int = 50,
) -> None:
    """
    Analyzes each binary in the provided list, updates the Specs object
    with the results, and periodically saves the state.

    :param binaries: List of paths to binaries that need analysis.
    :param specs:    Specs object (acts like a dict) to store the results.
    :param save_every: Frequency of saving progress (in number of binaries).
    """
    for binary_path in tqdm(binaries, unit="binaries"):
        try:
            specs[binary_path] = analyze_binary(binary_path)
        except Exception as e:
            # Log the error to stdout but continue processing
            print(f"Error analyzing {binary_path}: {e}")
            # Store a default specs object to avoid re-analyzing next time
            specs[binary_path] = BinarySpecs(binary_path)

        # Save progress every 'save_every' analyzed binaries
        if len(specs) % save_every == 0:
            save_state(specs)


def export_top_binaries(
    specs: Specs, top_n: int = 100, output_file: str = "main.md"
) -> None:
    """
    Sorts the binaries in descending order by total_instructions,
    takes the top N, and exports them to a Markdown file.

    :param specs:       The Specs object containing all analyzed binaries.
    :param top_n:       The number of top binaries to include in the export.
    :param output_file: The path to the Markdown file to write.
    """
    print(f"Will sort and export {len(specs)} entries")

    # Sort by descending number of instructions
    sorted_specs = sorted(
        specs.values(), key=lambda x: x.total_instructions, reverse=True
    )
    top_list = sorted_specs[:top_n]

    # Convert specs to dictionaries for DataFrame
    dicts = [specs_to_register_sizes_dict(item) for item in top_list]
    df = pd.DataFrame(dicts)

    # Export as Markdown
    md_text = df.to_markdown(index=False)
    with open(output_file, "w") as f:
        f.write(md_text)

    # Print to stdout as well
    print(f"Exported top {top_n} binaries to {output_file}")
    print(f"Data preview:\n{df.to_string(index=False)}")


def parse_args() -> argparse.Namespace:
    """
    Parses command line arguments and returns them as a Namespace object.
    """
    parser = argparse.ArgumentParser(
        description=(
            "Scan system (or given) directories for executables, analyze them to collect SIMD stats, "
            "and export a Markdown file of the top binaries."
        )
    )
    parser.add_argument(
        "-d",
        "--directories",
        nargs="+",  # Allow one or more directories
        default=["/usr/bin/", "/usr/local/bin/"],
        help="Directories to scan for executables (default: /usr/bin/ and /usr/local/bin/).",
    )
    parser.add_argument(
        "-t",
        "--top",
        type=int,
        default=100,
        help="Number of top binaries to list in the final export (default: 100).",
    )
    parser.add_argument(
        "-o",
        "--output",
        default="main.md",
        help="Output Markdown file (default: main.md).",
    )
    parser.add_argument(
        "--save-every",
        type=int,
        default=50,
        help="Save the specs state after analyzing this many new binaries (default: 50).",
    )
    parser.add_argument(
        "--seed",
        type=int,
        default=None,
        help="Random seed for shuffling the list of binaries (default: None).",
    )
    return parser.parse_args()


def main() -> None:
    """
    Main entry point for the script:
    1. Parses CLI arguments
    2. Restores or creates a Specs object
    3. Scans and analyzes all missing binaries
    4. Exports a summary report to a Markdown file
    """
    args = parse_args()

    # Optionally set a random seed
    if args.seed is not None:
        random.seed(args.seed)

    # 1. Restore or create Specs
    specs: Specs = restore_state()
    print(f"Restored a state with {len(specs)} entries.")

    # 2. Get all new binaries not in specs
    all_executables = list(all_binaries(args.directories))
    binaries_to_analyze = [
        bin_path for bin_path in all_executables if bin_path not in specs
    ]
    print(f"Found {len(binaries_to_analyze)} binaries to analyze.")
    random.shuffle(binaries_to_analyze)  # Randomize the order

    # 3. Analyze new binaries
    try:
        analyze_and_update_specs(binaries_to_analyze, specs, save_every=args.save_every)
        save_state(specs)
    except BaseException as ex:
        # Catching BaseException includes KeyboardInterrupt, SystemExit, etc.
        # We save the partial specs before re-raising.
        save_state(specs)
        print(f"Aborting due to: {ex}", file=sys.stderr)
        raise

    # 4. Export results
    export_top_binaries(specs, top_n=args.top, output_file=args.output)


if __name__ == "__main__":
    main()
