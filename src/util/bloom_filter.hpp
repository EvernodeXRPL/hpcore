#pragma once

#include <atomic>
#include <array>
#include <cstdint>
#include <functional>
#include <bit>
#include <chrono>

namespace util {

/**
 * Lock-free Bloom filter implementation.
 * Each filter uses 16MB (134,217,728 bits) with 4 hash functions.
 * Handles ~13 million items at 1% false positive rate.
 */
class bloom_filter_impl {
    static constexpr size_t BITS = 134217728; // 16MB = 128M bits
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
    bloom_filter_impl() {
        clear();
    }
    
    void clear() {
        for (auto& word : bits) {
            word.store(0, std::memory_order_relaxed);
        }
    }
    
    // Returns true if successfully inserted (was new), false if might already exist
    bool try_insert(const std::string& data) {
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
    
    // Check if item might exist (read-only)
    bool might_contain(const std::string& data) const {
        auto positions = get_positions(data);
        
        for (size_t pos : positions) {
            size_t word_idx = pos / BITS_PER_WORD;
            size_t bit_idx = pos % BITS_PER_WORD;
            uint64_t mask = uint64_t(1) << bit_idx;
            
            if ((bits[word_idx].load(std::memory_order_relaxed) & mask) == 0) {
                return false;
            }
        }
        
        return true;
    }
};

/**
 * Rolling bloom filter using double buffering.
 * Total size: 32MB (2 x 16MB filters)
 * Automatically rotates filters every 5 minutes.
 */
class bloom_filter {
    static constexpr int64_t ROTATION_INTERVAL_MS = 300000; // 5 minutes in milliseconds
    
    bloom_filter_impl filter1;
    bloom_filter_impl filter2;
    std::atomic<int> active_filter{1}; // 1 or 2
    std::atomic<int64_t> last_rotation_time;
    
    int64_t current_time_ms() const {
        return std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::steady_clock::now().time_since_epoch()
        ).count();
    }
    
    void check_rotation() {
        int64_t now = current_time_ms();
        int64_t last_rotation = last_rotation_time.load(std::memory_order_relaxed);
        
        if (now - last_rotation >= ROTATION_INTERVAL_MS) {
            // Try to update the rotation time atomically
            if (last_rotation_time.compare_exchange_strong(last_rotation, now, 
                                                          std::memory_order_relaxed)) {
                // We won the race to rotate
                int current = active_filter.load(std::memory_order_relaxed);
                int next = (current == 1) ? 2 : 1;
                
                // Clear the filter that will become active next rotation
                if (next == 1) {
                    filter1.clear();
                } else {
                    filter2.clear();
                }
                
                // Switch active filter
                active_filter.store(next, std::memory_order_relaxed);
            }
        }
    }
    
public:
    bloom_filter() : last_rotation_time(current_time_ms()) {
        // Both filters start clear
    }
    
    // Returns true if successfully inserted (was new), false if might already exist
    bool try_emplace(const std::string& data) {
        check_rotation();
        
        // Check both filters first
        bool in_filter1 = filter1.might_contain(data);
        bool in_filter2 = filter2.might_contain(data);
        
        if (in_filter1 || in_filter2) {
            return false; // Already exists
        }
        
        // Insert into both filters
        filter1.try_insert(data);
        filter2.try_insert(data);
        
        return true;
    }
};

// Typedef to match rollover_hashset name
using rollover_hashset = bloom_filter;

// Global instances for different message types
inline bloom_filter recent_peermsg_hashes;
inline bloom_filter recent_selfmsg_hashes;

} // namespace util
