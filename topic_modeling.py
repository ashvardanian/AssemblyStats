from typing import Iterable, List, Tuple
import numpy as np

from specs import BinarySpecs


def doc_term_frequency_matrix(specs: Iterable[BinarySpecs]) -> Tuple[List[str], List[str], np.array]:

    # Prepare the document names
    unique_docs = [s.path for s in specs]

    # Prepare the unique mnemonics names
    unique_terms = set()
    for s in specs:
        for term in s.code_frequencies.keys():
            unique_terms.add(term)
    unique_terms = list(unique_terms)

    # Prepare the doc-term frequency matrix
    freqs_matrix = np.zeros((len(unique_docs), len(unique_terms)), dtype=int)
    for doc_idx, s in enumerate(specs):
        for term, count in s.code_frequencies.items():
            term_idx = unique_terms.index(term)
            freqs_matrix[doc_idx, term_idx] = float(count)

    return unique_docs, unique_terms, np.matrix(freqs_matrix)
