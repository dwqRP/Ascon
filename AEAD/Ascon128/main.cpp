#include <bits/stdc++.h>
#include "ascon128.h"
using namespace std;
using namespace ASCON128;

int main()
{
    // puts("Start!");
    ascon_data c;
    ascon128 T;
    ascon128 key(0x1a2b3c4d5e6f7a8b, 0x9a8b7c6d5e4f3a2b), nonce(0x0b1c2d3e4f5a6b7c, 0x7a6b5c4d3e2f1a0b);
    ascon_data a = {0x51, 0x84, 0x9a, 0x3d, 0x2b, 0xf5, 0x60, 0x77, 0xee, 0x93, 0x6c, 0xd1, 0x49, 0x21, 0xb7, 0x35, 0x9f, 0xd4, 0x7e, 0x68, 0x1b, 0x06, 0xd7, 0xe8, 0x2a, 0x7c, 0x5f, 0x11, 0x9e, 0x48, 0x70, 0xb4, 0x2e, 0xa7, 0xfd, 0x39, 0xd3, 0x5c, 0xc0};
    ascon_data m = {0xc9, 0x6b, 0x58, 0xe5, 0x70, 0x2e, 0x38, 0xd3, 0xd2, 0x4c, 0xc2, 0x0f, 0x52, 0x7d, 0xf9, 0x9a, 0x9b, 0x65, 0x21, 0x2d, 0x31, 0x58, 0xa3, 0xa9, 0x76, 0xbe, 0x89, 0x03, 0xaf, 0x92, 0xd0, 0x0d, 0x2d, 0x73, 0x01, 0xc8, 0x22, 0xa1, 0x5f, 0x65, 0x32};
    printdata("Plaintext: ", m);
    printdata("AssociatedData: ", a);
    print128("key: ", key);
    print128("nonce: ", nonce);

    puts("--------Enc--------");
    Encryption(m, a, c, key, nonce, T);
    printdata("Ciphertext: ", c);
    print128("tag: ", T);

    puts("--------Dec--------");
    ascon_data mm;
    bool ans = Decryption(c, a, mm, key, nonce, T);
    if (ans)
        puts("correct!");
    else
        puts("error!");
    printdata("Plaintext after Dec: ", mm);
    return 0;
}