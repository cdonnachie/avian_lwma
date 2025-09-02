# Example: plug into an ElectrumX-style checkpoint generator
# Assumptions:
#  - You can iterate historical headers as (height, time, version, bits)
#  - You want to validate that stored bits == LWMA(next) per-algo

from avian_lwma import HeaderLite, filter_last_n_for_algo, next_bits_window

T = 30
N = 45
POW_LIMITS = {
    0: "00000fffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",  # X16RT
    1: "000fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",  # MinotaurX
}

# Example mapping - adjust to your chain rules:
# e.g., bit 28 = MinotaurX; else X16RT
def algo_from_version(v: int) -> int:
    return 1 if (v & (1 << 28)) else 0

# Suppose `headers` is a list[HeaderLite] ordered from oldest to newest
headers: list[HeaderLite] = []  # TODO: fill from your ElectrumX header DB

violations = []
for algo_id in (0, 1):
    window = filter_last_n_for_algo(headers, N, algo_from_version, algo_id)
    if len(window) < N:
        continue
    expected = next_bits_window(window, T, len(window), POW_LIMITS[algo_id])
    # Compare with your next header for this algo, if available.
    # if next_header.bits != expected:
    #     violations.append((next_height, algo_id, expected, next_header.bits))

print("OK (example)")
