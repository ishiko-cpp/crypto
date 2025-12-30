// SPDX-FileCopyrightText: 2000-2025 Xavier Leclercq
// SPDX-License-Identifier: MIT

#ifndef GUARD_ISHIKO_CPP_CRYPTO_SHA256HASH_HPP
#define GUARD_ISHIKO_CPP_CRYPTO_SHA256HASH_HPP

#include <Ishiko/Memory.hpp>
#include <botan/sha2_32.h>
#include <array>

namespace Ishiko
{
    /// This class holds a SHA-256 hash and functions to update it.
    class SHA256Hash
    {
    public:
        typedef InplaceOctetBuffer<32> Value;

        /// The constructor.
        SHA256Hash();

        /// Recomputes the value of the hash based on additional data.
        /**
            This function can be called multiple times to append more data each time.
            @param data Pointer to the start of the buffer containing the data.
            @param length Length of the buffer.
        */
        void update(const char* data, size_t length);
        /// Recomputes the value of the hash based on the contents of a file.
        /**
            This is equivalent to calling update with the contents of the file.
            @param filePath The path of the file whose contents will be read and used
              to update the value of the hash.
        */
        void updateFromFile(const std::string& filePath);
        /// Gets the current value of the hash based on the input data passed by the various update functions so far.
        /**
            @return A 256 bit array with the value of the hash.
            @see update
            @see updateFromFile
        */
        const Value& value() const;

    private:
        mutable Botan::SHA_256 m_context;
        mutable Value m_value;
    };
}

#endif
