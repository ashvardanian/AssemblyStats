import os
import json
import dataclasses
from dataclasses import dataclass, field
from typing import Dict, List, Tuple


@dataclass
class InstructionSpecs:
    mnemonic: str = ""
    register_size: int = 0

    @property
    def code(self) -> str:
        return str(self.mnemonic).split()[0]

    @property
    def name(self) -> str:
        return f"{self.register_size:03d}b-{self.code}"


@dataclass
class BinarySpecs:
    path: str
    code_frequencies: Dict[str, int] = field(default_factory=dict)
    size_frequencies: Dict[str, int] = field(default_factory=dict)

    @property
    def total_instructions(self) -> int:
        n = 0
        for _, v in self.size_frequencies.items():
            n += v
        return n

    @property
    def simd_instructions(self) -> int:
        n = 0
        for k, v in self.size_frequencies.items():
            if int(k) > 64:
                n += v
        return n


def sort_histogram(hist: Dict[str, int]) -> List[Tuple[str, int]]:
    codes_and_counts = [(k, v) for k, v in hist.items()]
    codes_and_counts.sort(reverse=True, key=lambda x: x[1])
    return codes_and_counts


Specs = Dict[str, BinarySpecs]


class EnhancedJSONEncoder(json.JSONEncoder):
    def default(self, o):
        if dataclasses.is_dataclass(o):
            return dataclasses.asdict(o)
        return super().default(o)


def restore_state(path: str = "main.json") -> Specs:
    if not os.path.exists(path):
        return dict()

    s = open(path, "r").read()
    dicts = json.loads(s)
    specs = dict()
    for k, d in dicts.items():
        specs[k] = BinarySpecs(**d)
    return specs


def save_state(obj: Specs, path: str = "main.json"):
    s = json.dumps(obj, cls=EnhancedJSONEncoder)
    with open(path, "w") as f:
        f.write(s)


if __name__ == "__main__":
    restore_state()
