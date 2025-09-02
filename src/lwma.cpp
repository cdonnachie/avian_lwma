#include "lwma.hpp"
#include <algorithm>
#include <stdexcept>

static inline uint32_t clamp_u32(uint32_t x, uint32_t lo, uint32_t hi){ return std::min(std::max(x,lo),hi); }

uint32_t lwma_next_bits(const std::vector<HeaderLite>& window,
                        uint32_t T,
                        uint32_t N,
                        const Big256& pow_limit)
{
    if (window.size() < N) throw std::runtime_error("insufficient window");

    // Weighted solvetime sum WS = sum i * st_i, with st_i clamped to [1, 6T]
    // st_i uses consecutive headers (same algo): window[i-1] -> window[i]
    uint64_t WS = 0;
    for (size_t i=1; i<window.size(); ++i) {
        uint32_t st = (window[i].time >= window[i-1].time)
                        ? (window[i].time - window[i-1].time) : 0u;
        st = clamp_u32(st, 1u, 6u*T);
        uint64_t weight = i; // i in [1..N-1]
        WS += weight * (uint64_t)st;
    }
    // There are (N-1) intervals between N blocks
    uint64_t K = (uint64_t)(window.size()-1) * (uint64_t)window.size() / 2ull;
    if (K == 0) K = 1; // minimal safety

    // Average target over blocks in window
    Big256 sumT = Big256::zero();
    for (const auto& h : window) {
        Big256 t = Big256::from_compact(h.bits);
        sumT.add_inplace(t);
    }
    Big256 avgT = Big256::div_u64(sumT, (uint64_t)window.size());

    // nextT = avgT * WS / (K*T)
    Big256 num = Big256::mul_u64(avgT, WS);
    Big256 nextT = Big256::div_u64(num, K * (uint64_t)T);

    // clamp to pow_limit
    nextT.clamp_to(pow_limit);

    return nextT.to_compact();
}
