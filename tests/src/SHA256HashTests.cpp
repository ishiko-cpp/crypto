// SPDX-FileCopyrightText: 2000-2025 Xavier Leclercq
// SPDX-License-Identifier: MIT

#include "SHA256HashTests.hpp"
#include "Ishiko/Crypto/SHA256Hash.hpp"

using namespace Ishiko;

SHA256HashTests::SHA256HashTests(const TestNumber& number, const TestContext& context)
    : TestSequence(number, "SHA256Hash tests", context)
{
    append<HeapAllocationErrorsTest>("Creation test 1", CreationTest1);
    append<HeapAllocationErrorsTest>("value test 1", ValueTest1);
    append<HeapAllocationErrorsTest>("value test 2", ValueTest2);
    append<HeapAllocationErrorsTest>("value test 3", ValueTest3);
    append<HeapAllocationErrorsTest>("value test 4", ValueTest4);
    append<HeapAllocationErrorsTest>("value test 5", ValueTest5);
    append<HeapAllocationErrorsTest>("updateFromFile test 1", UpdateFromFileTest1);
    append<HeapAllocationErrorsTest>("updateFromFile test 2", UpdateFromFileTest2);
    append<HeapAllocationErrorsTest>("updateFromFile test 3", UpdateFromFileTest3);
    append<HeapAllocationErrorsTest>("updateFromFile test 4", UpdateFromFileTest4);
    append<HeapAllocationErrorsTest>("updateFromFile test 5", UpdateFromFileTest5);
}

void SHA256HashTests::CreationTest1(Test& test)
{
    SHA256Hash hash;

    ISHIKO_TEST_PASS();
}

void SHA256HashTests::ValueTest1(Test& test)
{
    SHA256Hash hash;
    const InplaceOctetBuffer<32>& value = hash.value();

    std::array<Octet, 32> referenceValue =
    {
        0xe3, 0xb0, 0xc4, 0x42, 0x98, 0xfc, 0x1c, 0x14,
        0x9a, 0xfb, 0xf4, 0xc8, 0x99, 0x6f, 0xb9, 0x24,
        0x27, 0xae, 0x41, 0xe4, 0x64, 0x9b, 0x93, 0x4c,
        0xa4, 0x95, 0x99, 0x1b, 0x78, 0x52, 0xb8, 0x55
    };

    // We don't use the operator == to make it easier to
    // debug
    bool equal = true;
    for (size_t i = 0; i < 32; ++i)
    {
        if (value[i] != referenceValue[i])
        {
            equal = false;
            break;
        }
    }

    ISHIKO_TEST_FAIL_IF_NOT(equal);
    ISHIKO_TEST_PASS();
}

void SHA256HashTests::ValueTest2(Test& test)
{
    SHA256Hash hash;
    const char* text = "abc";
    hash.update(text, strlen(text));
    const InplaceOctetBuffer<32>& value = hash.value();

    std::array<Octet, 32> referenceValue =
    {
        0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea,
        0x41, 0x41, 0x40, 0xde, 0x5d, 0xae, 0x22, 0x23,
        0xb0, 0x03, 0x61, 0xa3, 0x96, 0x17, 0x7a, 0x9c,
        0xb4, 0x10, 0xff, 0x61, 0xf2, 0x00, 0x15, 0xad
    };

    // We don't use the operator == to make it easier to
    // debug
    bool equal = true;
    for (size_t i = 0; i < 32; ++i)
    {
        if (value[i] != referenceValue[i])
        {
            equal = false;
            break;
        }
    }

    ISHIKO_TEST_FAIL_IF_NOT(equal);
    ISHIKO_TEST_PASS();
}

void SHA256HashTests::ValueTest3(Test& test)
{
    SHA256Hash hash;
    const char* text = "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu";
    hash.update(text, strlen(text));
    const InplaceOctetBuffer<32>& value = hash.value();

    std::array<Octet, 64> referenceValue =
    {
        0x8E, 0x95, 0x9B, 0x75, 0xDA, 0xE3, 0x13, 0xDA,
        0x8C, 0xF4, 0xF7, 0x28, 0x14, 0xFC, 0x14, 0x3F,
        0x8F, 0x77, 0x79, 0xC6, 0xEB, 0x9F, 0x7F, 0xA1,
        0x72, 0x99, 0xAE, 0xAD, 0xB6, 0x88, 0x90, 0x18,
        0x50, 0x1D, 0x28, 0x9E, 0x49, 0x00, 0xF7, 0xE4,
        0x33, 0x1B, 0x99, 0xDE, 0xC4, 0xB5, 0x43, 0x3A,
        0xC7, 0xD3, 0x29, 0xEE, 0xB6, 0xDD, 0x26, 0x54,
        0x5E, 0x96, 0xE5, 0x5B, 0x87, 0x4B, 0xE9, 0x09
    };

    // We don't use the operator == to make it easier to
    // debug
    bool equal = true;
    for (size_t i = 0; i < 64; ++i)
    {
        if (value[i] != referenceValue[i])
        {
            equal = false;
            break;
        }
    }

    ISHIKO_TEST_FAIL_IF_NOT(equal);
    ISHIKO_TEST_PASS();
}

void SHA256HashTests::ValueTest4(Test& test)
{
    SHA256Hash hash;
    std::string text(1000000, 'a');
    hash.update(text.c_str(), text.size());
    const InplaceOctetBuffer<32>& value = hash.value();

    std::array<Octet, 32> referenceValue =
    {
        0xcd, 0xc7, 0x6e, 0x5c, 0x99, 0x14, 0xfb, 0x92,
        0x81, 0xa1, 0xc7, 0xe2, 0x84, 0xd7, 0x3e, 0x67,
        0xf1, 0x80, 0x9a, 0x48, 0xa4, 0x97, 0x20, 0x0e,
        0x04, 0x6d, 0x39, 0xcc, 0xc7, 0x11, 0x2c, 0xd0
    };

    // We don't use the operator == to make it easier to
    // debug
    bool equal = true;
    for (size_t i = 0; i < 32; ++i)
    {
        if (value[i] != referenceValue[i])
        {
            equal = false;
            break;
        }
    }

    ISHIKO_TEST_FAIL_IF_NOT(equal);
    ISHIKO_TEST_PASS();
}

void SHA256HashTests::ValueTest5(Test& test)
{
    SHA256Hash hash;
    std::string text("abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmno");
    for (size_t i = 0; i < 16777216; ++i)
    {
        hash.update(text.c_str(), text.size());
    }
    const InplaceOctetBuffer<32>& value = hash.value();

    std::array<Octet, 64> referenceValue =
    {
        0xb4, 0x7c, 0x93, 0x34, 0x21, 0xea, 0x2d, 0xb1,
        0x49, 0xad, 0x6e, 0x10, 0xfc, 0xe6, 0xc7, 0xf9,
        0x3d, 0x07, 0x52, 0x38, 0x01, 0x80, 0xff, 0xd7,
        0xf4, 0x62, 0x9a, 0x71, 0x21, 0x34, 0x83, 0x1d,
        0x77, 0xbe, 0x60, 0x91, 0xb8, 0x19, 0xed, 0x35,
        0x2c, 0x29, 0x67, 0xa2, 0xe2, 0xd4, 0xfa, 0x50,
        0x50, 0x72, 0x3c, 0x96, 0x30, 0x69, 0x1f, 0x1a,
        0x05, 0xa7, 0x28, 0x1d, 0xbe, 0x6c, 0x10, 0x86
    };

    // We don't use the operator == to make it easier to
    // debug
    bool equal = true;
    for (size_t i = 0; i < 64; ++i)
    {
        if (value[i] != referenceValue[i])
        {
            equal = false;
            break;
        }
    }

    ISHIKO_TEST_FAIL_IF_NOT(equal);
    ISHIKO_TEST_PASS();
}

void SHA256HashTests::UpdateFromFileTest1(Test& test)
{
    SHA256Hash hash;
    hash.updateFromFile(test.context().getDataPath("EmptyFile.txt").string());
    const InplaceOctetBuffer<32>& value = hash.value();

    std::array<Octet, 32> referenceValue =
    {
        0xe3, 0xb0, 0xc4, 0x42, 0x98, 0xfc, 0x1c, 0x14,
        0x9a, 0xfb, 0xf4, 0xc8, 0x99, 0x6f, 0xb9, 0x24,
        0x27, 0xae, 0x41, 0xe4, 0x64, 0x9b, 0x93, 0x4c,
        0xa4, 0x95, 0x99, 0x1b, 0x78, 0x52, 0xb8, 0x55
    };

    // We don't use the operator == to make it easier to
    // debug
    bool equal = true;
    for (size_t i = 0; i < 32; ++i)
    {
        if (value[i] != referenceValue[i])
        {
            equal = false;
            break;
        }
    }

    ISHIKO_TEST_FAIL_IF_NOT(equal);
    ISHIKO_TEST_PASS();
}

void SHA256HashTests::UpdateFromFileTest2(Test& test)
{
    SHA256Hash hash;
    hash.updateFromFile(test.context().getDataPath("abc.txt").string());
    const InplaceOctetBuffer<32>& value = hash.value();

    std::array<Octet, 32> referenceValue =
    {
        0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea,
        0x41, 0x41, 0x40, 0xde, 0x5d, 0xae, 0x22, 0x23,
        0xb0, 0x03, 0x61, 0xa3, 0x96, 0x17, 0x7a, 0x9c,
        0xb4, 0x10, 0xff, 0x61, 0xf2, 0x00, 0x15, 0xad
    };

    // We don't use the operator == to make it easier to
    // debug
    bool equal = true;
    for (size_t i = 0; i < 32; ++i)
    {
        if (value[i] != referenceValue[i])
        {
            equal = false;
            break;
        }
    }

    ISHIKO_TEST_FAIL_IF_NOT(equal);
    ISHIKO_TEST_PASS();
}

void SHA256HashTests::UpdateFromFileTest3(Test& test)
{
    SHA256Hash hash;
    hash.updateFromFile(test.context().getDataPath("smallfile.txt").string());
    const InplaceOctetBuffer<32>& value = hash.value();

    std::array<Octet, 64> referenceValue =
    {
        0x8E, 0x95, 0x9B, 0x75, 0xDA, 0xE3, 0x13, 0xDA,
        0x8C, 0xF4, 0xF7, 0x28, 0x14, 0xFC, 0x14, 0x3F,
        0x8F, 0x77, 0x79, 0xC6, 0xEB, 0x9F, 0x7F, 0xA1,
        0x72, 0x99, 0xAE, 0xAD, 0xB6, 0x88, 0x90, 0x18,
        0x50, 0x1D, 0x28, 0x9E, 0x49, 0x00, 0xF7, 0xE4,
        0x33, 0x1B, 0x99, 0xDE, 0xC4, 0xB5, 0x43, 0x3A,
        0xC7, 0xD3, 0x29, 0xEE, 0xB6, 0xDD, 0x26, 0x54,
        0x5E, 0x96, 0xE5, 0x5B, 0x87, 0x4B, 0xE9, 0x09
    };

    // We don't use the operator == to make it easier to
    // debug
    bool equal = true;
    for (size_t i = 0; i < 64; ++i)
    {
        if (value[i] != referenceValue[i])
        {
            equal = false;
            break;
        }
    }

    ISHIKO_TEST_FAIL_IF_NOT(equal);
    ISHIKO_TEST_PASS();
}

void SHA256HashTests::UpdateFromFileTest4(Test& test)
{
    // Generate a file with a million 'a' characters in it
    // We generate the file because we do not want to store such a large file in version control
    std::string testFilePath = test.context().getOutputPath("milliona.txt").string();
    boost::filesystem::remove(testFilePath);
    std::ofstream testFile(testFilePath);
    for (size_t i = 0; i < 100000; ++i)
    {
        testFile.write("aaaaaaaaaa", 10);
    }
    testFile.close();

    SHA256Hash hash;
    hash.updateFromFile(testFilePath);
    const InplaceOctetBuffer<32>& value = hash.value();

    std::array<Octet, 32> referenceValue =
    {
        0xcd, 0xc7, 0x6e, 0x5c, 0x99, 0x14, 0xfb, 0x92,
        0x81, 0xa1, 0xc7, 0xe2, 0x84, 0xd7, 0x3e, 0x67,
        0xf1, 0x80, 0x9a, 0x48, 0xa4, 0x97, 0x20, 0x0e,
        0x04, 0x6d, 0x39, 0xcc, 0xc7, 0x11, 0x2c, 0xd0
    };

    // We don't use the operator == to make it easier to
    // debug
    bool equal = true;
    for (size_t i = 0; i < 32; ++i)
    {
        if (value[i] != referenceValue[i])
        {
            equal = false;
            break;
        }
    }

    boost::filesystem::remove(testFilePath);

    ISHIKO_TEST_FAIL_IF_NOT(equal);
    ISHIKO_TEST_PASS();
}

void SHA256HashTests::UpdateFromFileTest5(Test& test)
{
    // Generate a file with a million 'a' characters in it
    // We generate the file because we do not want to store such a large file in version control
    std::string testFilePath = test.context().getOutputPath("gigabyte.txt").string();
    boost::filesystem::remove(testFilePath);
    std::ofstream testFile(testFilePath);
    std::string text("abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmno");
    for (size_t i = 0; i < 16777216; ++i)
    {
        testFile.write(text.c_str(), text.size());
    }
    testFile.close();

    SHA256Hash hash;
    hash.updateFromFile(testFilePath);
    const InplaceOctetBuffer<32>& value = hash.value();

    std::array<Octet, 64> referenceValue =
    {
        0xb4, 0x7c, 0x93, 0x34, 0x21, 0xea, 0x2d, 0xb1,
        0x49, 0xad, 0x6e, 0x10, 0xfc, 0xe6, 0xc7, 0xf9,
        0x3d, 0x07, 0x52, 0x38, 0x01, 0x80, 0xff, 0xd7,
        0xf4, 0x62, 0x9a, 0x71, 0x21, 0x34, 0x83, 0x1d,
        0x77, 0xbe, 0x60, 0x91, 0xb8, 0x19, 0xed, 0x35,
        0x2c, 0x29, 0x67, 0xa2, 0xe2, 0xd4, 0xfa, 0x50,
        0x50, 0x72, 0x3c, 0x96, 0x30, 0x69, 0x1f, 0x1a,
        0x05, 0xa7, 0x28, 0x1d, 0xbe, 0x6c, 0x10, 0x86
    };

    // We don't use the operator == to make it easier to
    // debug
    bool equal = true;
    for (size_t i = 0; i < 64; ++i)
    {
        if (value[i] != referenceValue[i])
        {
            equal = false;
            break;
        }
    }

    boost::filesystem::remove(testFilePath);

    ISHIKO_TEST_FAIL_IF_NOT(equal);
    ISHIKO_TEST_PASS();
}
