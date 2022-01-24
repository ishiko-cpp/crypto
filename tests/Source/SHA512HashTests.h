/*
    Copyright (c) 2017-2022 Xavier Leclercq
    Released under the MIT License
    See https://github.com/Ishiko-cpp/Crypto/blob/master/LICENSE.txt
*/

#ifndef _ISHIKO_CRYPTO_TESTS_SHA512HASHTESTS_H_
#define _ISHIKO_CRYPTO_TESTS_SHA512HASHTESTS_H_

#include <Ishiko/Tests/Core.hpp>

class SHA512HashTests : public Ishiko::Tests::TestSequence
{
public:
    SHA512HashTests(const Ishiko::Tests::TestNumber& number, const Ishiko::Tests::TestContext& context);

private:
    static void CreationTest1(Ishiko::Tests::Test& test);
    static void ValueTest1(Ishiko::Tests::Test& test);
    static void ValueTest2(Ishiko::Tests::Test& test);
    static void ValueTest3(Ishiko::Tests::Test& test);
    static void ValueTest4(Ishiko::Tests::Test& test);
    static void ValueTest5(Ishiko::Tests::Test& test);
    static void UpdateFromFileTest1(Ishiko::Tests::Test& test);
    static void UpdateFromFileTest2(Ishiko::Tests::Test& test);
    static void UpdateFromFileTest3(Ishiko::Tests::Test& test);
    static void UpdateFromFileTest4(Ishiko::Tests::Test& test);
    static void UpdateFromFileTest5(Ishiko::Tests::Test& test);
};

#endif