/*
Open Asset Import Library (assimp)
----------------------------------------------------------------------

Copyright (c) 2006-2026, assimp team

All rights reserved.

Redistribution and use of this software in source and binary forms,
with or without modification, are permitted provided that the
following conditions are met:

* Redistributions of source code must retain the above
  copyright notice, this list of conditions and the
  following disclaimer.

* Redistributions in binary form must reproduce the above
  copyright notice, this list of conditions and the
  following disclaimer in the documentation and/or other
  materials provided with the distribution.

* Neither the name of the assimp team, nor the names of its
  contributors may be used to endorse or promote products
  derived from this software without specific prior
  written permission of the assimp team.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
"AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
(INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

----------------------------------------------------------------------
*/

/** @file FBXSeededHash.h
 *  @brief Per-process-seeded hashing for the FBX importer's file-derived
 *         name/ID maps (defense against hash flooding / CWE-407).
 */
#ifndef INCLUDED_AI_FBX_SEEDEDHASH_H
#define INCLUDED_AI_FBX_SEEDEDHASH_H

#include <chrono>
#include <cstdint>
#include <functional>
#include <random>
#include <string>
#include <unordered_map>
#include <unordered_set>

namespace Assimp {
namespace FBX {

namespace detail {

// Per-process seed mixed into every hash produced for keys that come
// straight out of a (potentially hostile) FBX file. With an unkeyed hash
// an attacker can pre-compute names that all land in the same bucket and
// turn insertion and lookup of the importer's name maps into quadratic
// work (hash flooding). A secret-per-run seed makes the bucket layout
// unpredictable, so collisions can no longer be pre-computed offline.
inline uint64_t FbxHashSeed() {
    static const uint64_t seed = [] {
        uint64_t s = 0x9e3779b97f4a7c15ULL;
        s ^= static_cast<uint64_t>(
                std::chrono::high_resolution_clock::now().time_since_epoch().count());
        // ASLR: address of this function differs per process on any
        // platform that randomizes load addresses.
        s ^= static_cast<uint64_t>(reinterpret_cast<uintptr_t>(&FbxHashSeed)) << 1;
        try {
            // Best effort: std::random_device is deterministic on some
            // platforms (e.g. old MinGW); the other sources still differ.
            std::random_device rd;
            s ^= (static_cast<uint64_t>(rd()) << 32) | static_cast<uint64_t>(rd());
        } catch (...) {
        }
        return s;
    }();
    return seed;
}

// splitmix64-style finalizer: single multiply-xorshift avalanche so the
// seed actually reaches the low bits that unordered_map buckets use.
inline size_t FbxHashMix(uint64_t x) {
    x += 0x9e3779b97f4a7c15ULL;
    x = (x ^ (x >> 30)) * 0xbf58476d1ce4e5b9ULL;
    x = (x ^ (x >> 27)) * 0x94d049bb133111ebULL;
    x ^= x >> 31;
    return static_cast<size_t>(x);
}

} // namespace detail

// Seeded drop-in replacement for std::hash on the FBX importer's
// unordered containers. std::string keys (node names, property names,
// texture names) take the keyed byte-mixing path; integral keys (file
// object IDs) and pointers are folded through the same seed.
struct FbxSeededHash {
    size_t operator()(const std::string& s) const noexcept {
        // Seeded FNV-1a over the key bytes: every round depends on the
        // (unknown to the attacker) initial state, so a collision set
        // cannot be pre-computed without the seed.
        uint64_t h = detail::FbxHashSeed() ^ 0xcbf29ce484222325ULL;
        for (const unsigned char c : s) {
            h ^= c;
            h *= 0x100000001b3ULL;
        }
        return detail::FbxHashMix(h);
    }

    template <typename T>
    size_t operator()(const T *p) const noexcept {
        return detail::FbxHashMix(
                static_cast<uint64_t>(reinterpret_cast<uintptr_t>(p)) ^
                detail::FbxHashSeed());
    }

    template <typename T>
    size_t operator()(const T &v) const noexcept {
        return detail::FbxHashMix(
                static_cast<uint64_t>(std::hash<T> {}(v)) ^ detail::FbxHashSeed());
    }
};

template <typename Key, typename T>
using fbx_unordered_map = std::unordered_map<Key, T, FbxSeededHash>;
template <typename Key, typename T>
using fbx_unordered_multimap = std::unordered_multimap<Key, T, FbxSeededHash>;
template <typename Key>
using fbx_unordered_set = std::unordered_set<Key, FbxSeededHash>;
template <typename Key>
using fbx_unordered_multiset = std::unordered_multiset<Key, FbxSeededHash>;

} // namespace FBX
} // namespace Assimp

#endif // INCLUDED_AI_FBX_SEEDEDHASH_H
