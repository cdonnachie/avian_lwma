#pragma once
#include <array>
#include <cstdint>
#include <cstring>
#include <string>
#include <stdexcept>
#include <algorithm>

// Minimal 256-bit unsigned integer based on 8x32-bit limbs (little-endian).
// NOTE: uses __uint128_t for intermediate math; build with GCC/Clang.
// For MSVC, replace with a portable Big256 (PRs welcome).
struct Big256 {
    std::array<uint32_t, 8> w{}; // least-significant limb at w[0]

    static Big256 zero() { return Big256(); }

    bool is_zero() const {
        for (auto v: w) if (v) return false; return true;
    }

    // Compare: this < other
    bool lt(const Big256& o) const {
        for (int i=7;i>=0;--i) {
            if (w[i] != o.w[i]) return w[i] < o.w[i];
        }
        return false;
    }

    // a += b
    void add_inplace(const Big256& b) {
        uint64_t c=0;
        for (int i=0;i<8;++i) {
            uint64_t t=(uint64_t)w[i]+b.w[i]+c;
            w[i]=(uint32_t)t; c=t>>32;
        }
    }

    // return a * m (m up to 64-bit)
    static Big256 mul_u64(const Big256& a, uint64_t m) {
        Big256 r;
        unsigned __int128 c=0;
        for (int i=0;i<8;++i){
            unsigned __int128 t = (unsigned __int128)a.w[i]*m + c;
            r.w[i] = (uint32_t)t;
            c = t >> 32;
        }
        return r;
    }

    // return a / d (d up to 64-bit)
    static Big256 div_u64(const Big256& a, uint64_t d) {
        if (d==0) throw std::runtime_error("div by zero");
        Big256 r;
        unsigned __int128 rem=0;
        for (int i=7;i>=0;--i){
            unsigned __int128 cur = (rem<<32) + a.w[i];
            uint64_t q = (uint64_t)(cur / d);
            rem = cur % d;
            r.w[i] = (uint32_t)q;
        }
        return r;
    }

    // min(this, limit)
    void clamp_to(const Big256& limit) {
        if (limit.lt(*this)) *this = limit;
    }

    // Decode from Bitcoin compact (nBits)
    static Big256 from_compact(uint32_t nBits) {
        uint32_t exp = nBits >> 24;
        uint32_t mant = nBits & 0x007fffff;

        Big256 t = Big256::zero();

        // target = mant * 256^(exp-3)
        int shift_bytes = (int)exp - 3; // can be negative
        if (shift_bytes < 0) {
            mant >>= (uint32_t)(-shift_bytes * 8);
            shift_bytes = 0;
        }

        int limb = shift_bytes / 4;
        int off  = shift_bytes % 4;

        uint32_t m0 = mant & 0xff;
        uint32_t m1 = (mant >> 8) & 0xff;
        uint32_t m2 = (mant >> 16) & 0xff;
        uint32_t val = (m0) | (m1<<8) | (m2<<16);

        if (limb < 8) {
            uint64_t tmp = ((uint64_t)val) << (off*8);
            t.w[limb] |= (uint32_t)tmp;
            if (limb+1 < 8) t.w[limb+1] |= (uint32_t)(tmp >> 32);
        }
        return t;
    }

    // Encode to compact (approximate, good for difficulty usage)
    uint32_t to_compact() const {
        // find most-significant non-zero byte
        int ms_limb=-1; for (int i=7;i>=0;--i){ if (w[i]) { ms_limb=i; break; } }
        if (ms_limb==-1) return 0;

        // compute exponent = number of bytes
        uint32_t limb = w[ms_limb];
        int msb_byte = 3; while (msb_byte>0 && ((limb >> (msb_byte*8))&0xff)==0) --msb_byte;
        int exp = ms_limb*4 + msb_byte + 1; // number of bytes

        // extract top 3 bytes as mantissa
        // build a shifted copy right by (exp-3) bytes
        int shift = exp - 3;
        Big256 s{};
        int limb_shift = shift/4; int byte_shift = shift%4;
        for (int i=0;i<8;++i){
            unsigned __int128 acc=0;
            int src = i + limb_shift;
            if (src < 8 && src >= 0) acc |= ((unsigned __int128)w[src]) << 32;
            if (src-1 < 8 && src-1 >= 0) acc |= w[src-1];
            uint64_t val = (uint64_t)((acc >> (byte_shift*8)) & 0xffffffffu);
            s.w[i] = (uint32_t)val;
        }

        uint32_t top = s.w[7];
        uint32_t mant = (top >> 8) & 0x007fffff;

        // If highest bit would be set, shift mantissa right and bump exponent
        if (mant & 0x00800000u) {
            mant >>= 8;
            exp += 1;
        }

        return (exp << 24) | mant;
    }

    // Parse big-endian hex pow_limit (64 hex chars)
    static Big256 from_hex_be(const std::string& hex) {
        auto h = hex;
        if (h.size()%2) throw std::runtime_error("pow_limit hex must be even length");
        Big256 r; std::fill(r.w.begin(), r.w.end(), 0);
        int byte_index = 0;
        for (int i=(int)h.size()-2; i>=0; i-=2) {
            unsigned byte = std::stoul(h.substr(i,2), nullptr, 16);
            int limb = byte_index / 4; int off = byte_index % 4;
            if (limb < 8) r.w[limb] |= (uint32_t)byte << (off*8);
            byte_index++;
        }
        return r;
    }
};
