# avian_lwma

High-performance LWMA (Zawy v3) target calculator for dual-algo Avian forks (X16RT + MinotaurX).

- No Boost/OpenSSL: ships a tiny 256-bit integer core (GCC/Clang required for __uint128_t).
- pybind11: import from Python and call at header-sync/checkpoint time.
- Per-algo windows: pass the last N headers of a given algo.
- Optional WASM FFI: compile the same core to .wasm if you want a web/Node verifier (not included in this zip).

## Quick start (build wheel)

```bash
pip install -U pip build
pip install pybind11 scikit-build-core
pip install .
```

> Windows: build with MSYS2/MinGW or Clang, or use WSL. (MSVC lacks __uint128_t; a MSVC-safe Big256 can be added.)

## CMake build

```bash
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build -j
```

## Python usage

```python
from avian_lwma import HeaderLite, next_bits_window, filter_last_n_for_algo

N = 45           # LWMA window
T = 30           # target spacing (seconds)
POW_LIMITS = {
    0: "00000fffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",  # X16RT
    1: "000fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",  # MinotaurX
}

def algo_from_version(ver: int) -> int:
    return 1 if (ver & (1<<28)) else 0  # example mapping

# chain: list[HeaderLite] oldest->newest (fill from your header DB)
window = filter_last_n_for_algo(chain, N, algo_from_version, algo_id=1)
expected_bits = next_bits_window(window, T, len(window), POW_LIMITS[1])
```

### API
- HeaderLite(time: uint32, version: uint32, bits: uint32)
- next_bits_window(window, target_spacing_s, N, pow_limit_hex) -> int (compact bits)
- filter_last_n_for_algo(chain, N, algo_from_version, algo_id) -> list[HeaderLite]

### Notes
- Targets are full 256-bit integers decoded from compact bits. The result is clamped to pow_limit before re-encoding.
- The Big256 here uses __uint128_t for intermediate math. For MSVC, swap in a different Big256 (PRs welcome).
