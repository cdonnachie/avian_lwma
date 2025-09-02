#pragma once
#include <vector>
#include <cstdint>
#include "big256.hpp"

struct HeaderLite { uint32_t time; uint32_t version; uint32_t bits; };

// Compute LWMA v3 next target (compact) given last N headers (same algo), oldest->newest
uint32_t lwma_next_bits(const std::vector<HeaderLite>& window,
                        uint32_t target_spacing_s,
                        uint32_t N,
                        const Big256& pow_limit);
