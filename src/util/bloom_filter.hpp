#pragma once

#include <atomic>
#include <array>
#include <cstdint>
#include <functional>
#include <bit>

namespace util {

/**
 * Lock-free Bloom filter to replace rollover_hashset.
 * 32MB allocation (268,435,456 bits) with 4 hash functions.
 * Handles ~26 million items at 1% false positive rate.
 */
class bloom_filter {
    static constexpr size_t BITS = 268435456; // 32MB = 256M bits
    static constexpr size_t K = 4; // Number of hash functions
    static constexpr size_t BITS_PER_WORD = 64;
    static constexpr size_t NUM_WORDS = BITS / BITS_PER_WORD;
    
    std::array<std::atomic<uint64_t>, NUM_WORDS> bits;
    
    // MurmurHash3 mix function
    static uint64_t murmur_mix(uint64_t h) {
        h ^= h >> 33;
        h *= 0xff51afd7ed558ccd;
        h ^= h >> 33;
        h *= 0xc4ceb9fe1a85ec53;
        h ^= h >> 33;
        return h;
    }
    
    std::array<size_t, K> get_positions(const std::string& data) const {
        std::array<size_t, K> positions;
        uint64_t h1 = std::hash<std::string>{}(data);
        uint64_t h2 = murmur_mix(h1);
        
        for (size_t i = 0; i < K; ++i) {
            uint64_t hash = h1 + i * h2;
            positions[i] = hash % BITS;
        }
        
        return positions;
    }
    
public:
    bloom_filter() {
        for (auto& word : bits) {
            word.store(0, std::memory_order_relaxed);
        }
    }
    
    // Returns true if successfully inserted (was new), false if might already exist
    bool try_emplace(const std::string& data) {
        auto positions = get_positions(data);
        bool was_new = false;
        
        for (size_t pos : positions) {
            size_t word_idx = pos / BITS_PER_WORD;
            size_t bit_idx = pos % BITS_PER_WORD;
            uint64_t mask = uint64_t(1) << bit_idx;
            
            uint64_t prev = bits[word_idx].fetch_or(mask, std::memory_order_relaxed);
            
            if ((prev & mask) == 0) {
                was_new = true;
            }
        }
        
        return was_new;
    }
};

// Global instance to replace recent_peermsg_hashes
inline bloom_filter recent_peermsg_hashes;

} // namespace util
