# Hardware-Specific Operation Codes

This directory contains platform-specific operation codes for x86, Arm, and Nvidia architectures.
Each `.csv` file contains a list of instructions with their latencies and other relevant information, like port usage, and intrinsic names.
On x86, for Skylake-X, the file may contain lines like:

```csv
"instruction",                  "family",           "latency",  "throughput",   "uops",     "ports"
"PREFETCH_EXCLUSIVE (M512)",    "3DNOW_PREFETCH",   "",         "0.50 / 0.50",  "1 / 1",    "1*p23"
"VANDNPS (XMM, XMM, XMM)",      "AVX",              "1",        "0.33 / 0.33",  "1 / 1",    "1*p015"
"VANDNPS (YMM, YMM, M256)",     "AVX",              "[1;≤9]",   "0.50 / 0.50",  "1 / 2",    "1*p015+1*p23"
"VANDNPS (ZMM, K, ZMM, ZMM)",   "AVX512EVEX",       "1",        "0.50 / 0.50",  "1 / 1",    "1*p05"
"VANDNPS (ZMM, ZMM, M32_1to16)","AVX512EVEX",       "[1;≤9]",   "0.50 / 0.50",  "1 / 2",    "1*p05+1*p23"
"VANDNPS (ZMM, ZMM, M512)",     "AVX512EVEX",       "[1;≤9]",   "0.50 / 0.50",  "1 / 2",    "1*p05+1*p23"
"VANDNPS (ZMM, ZMM, ZMM)",      "AVX512EVEX",       "1",        "0.50 / 0.50",  "1 / 1",    "1*p05"
```

## Sourcing Manuals

### x86

On x86, most of the data was downloaded from [uops.info](https://uops.info/table).

## Arm

Most of the documentation Arm provides in a form of 50+ page long PDFs.
Those have been processed with AI models to output the relevant information in a machine-readable format.

- [Arm Neoverse N1 Software Optimization Guide](https://developer.arm.com/documentation/109896/latest/)
- [Arm Neoverse V1 Software Optimization Guide](https://developer.arm.com/documentation/109897/latest/)
- [Arm Neoverse N2 Software Optimization Guide](https://developer.arm.com/documentation/109914/latest/)
- [Arm Neoverse V2 Software Optimization Guide](https://developer.arm.com/documentation/109898/latest/)
- [Arm Neoverse V3 Software Optimization Guide](https://developer.arm.com/documentation/109678/latest/)

## Nvidia

Stay tuned 😉
