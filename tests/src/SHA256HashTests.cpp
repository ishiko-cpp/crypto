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

    std::array<Octet, 32> reference_value =
    {
        0xcf, 0x5b, 0x16, 0xa7, 0x78, 0xaf, 0x83, 0x80,
        0x03, 0x6c, 0xe5, 0x9e, 0x7b, 0x04, 0x92, 0x37,
        0x0b, 0x24, 0x9b, 0x11, 0xe8, 0xf0, 0x7a, 0x51,
        0xaf, 0xac, 0x45, 0x03, 0x7a, 0xfe, 0xe9, 0xd1
    };

    // We don't use the operator == to make it easier to
    // debug
    bool equal = true;
    for (size_t i = 0; i < 32; ++i)
    {
        if (value[i] != reference_value[i])
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

    std::array<Octet, 32> reference_value =
    {
        0x50, 0xe7, 0x2a, 0x0e, 0x26, 0x44, 0x2f, 0xe2,
        0x55, 0x2d, 0xc3, 0x93, 0x8a, 0xc5, 0x86, 0x58,
        0x22, 0x8c, 0x0c, 0xbf, 0xb1, 0xd2, 0xca, 0x87,
        0x2a, 0xe4, 0x35, 0x26, 0x6f, 0xcd, 0x05, 0x5e
    };

    // We don't use the operator == to make it easier to
    // debug
    bool equal = true;
    for (size_t i = 0; i < 32; ++i)
    {
        if (value[i] != reference_value[i])
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

    std::array<Octet, 32> reference_value =
    {
        0xcf, 0x5b, 0x16, 0xa7, 0x78, 0xaf, 0x83, 0x80,
        0x03, 0x6c, 0xe5, 0x9e, 0x7b, 0x04, 0x92, 0x37,
        0x0b, 0x24, 0x9b, 0x11, 0xe8, 0xf0, 0x7a, 0x51,
        0xaf, 0xac, 0x45, 0x03, 0x7a, 0xfe, 0xe9, 0xd1
    };

    // We don't use the operator == to make it easier to
    // debug
    bool equal = true;
    for (size_t i = 0; i < 32; ++i)
    {
        if (value[i] != reference_value[i])
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

    std::array<Octet, 32> reference_value =
    {
        0x50, 0xe7, 0x2a, 0x0e, 0x26, 0x44, 0x2f, 0xe2,
        0x55, 0x2d, 0xc3, 0x93, 0x8a, 0xc5, 0x86, 0x58,
        0x22, 0x8c, 0x0c, 0xbf, 0xb1, 0xd2, 0xca, 0x87,
        0x2a, 0xe4, 0x35, 0x26, 0x6f, 0xcd, 0x05, 0x5e
    };

    // We don't use the operator == to make it easier to
    // debug
    bool equal = true;
    for (size_t i = 0; i < 32; ++i)
    {
        if (value[i] != reference_value[i])
        {
            equal = false;
            break;
        }
    }

    boost::filesystem::remove(testFilePath);

    ISHIKO_TEST_FAIL_IF_NOT(equal);
    ISHIKO_TEST_PASS();
}
