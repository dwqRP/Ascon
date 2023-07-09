#ifndef __ASCON128__
#define __ASCON128__

#include <vector>

namespace ASCON128
{
    typedef unsigned char ascon8;
    typedef unsigned long long ascon64;
    typedef std::vector<ascon8> ascon_data;
    typedef std::vector<ascon64> ascon_state;
    typedef std::vector<ascon64> ascon_stream;

    class ascon128
    {
    public:
        ascon128();
        ascon128(ascon64, ascon64);
        ascon64 high, low;
        bool operator==(const ascon128 &tmp) const;
    };

    const int a = 12, b = 6, r = 64;
    const ascon64 cr[12] = {
        0x00000000000000f0,
        0x00000000000000e1,
        0x00000000000000d2,
        0x00000000000000c3,
        0x00000000000000b4,
        0x00000000000000a5,
        0x0000000000000096,
        0x0000000000000087,
        0x0000000000000078,
        0x0000000000000069,
        0x000000000000005a,
        0x000000000000004b};
    const ascon8 Sbox[32] = {
        0x4, 0xb, 0x1f, 0x14, 0x1a, 0x15, 0x9, 0x2,
        0x1b, 0x5, 0x8, 0x12, 0x1d, 0x3, 0x6, 0x1c,
        0x1e, 0x13, 0x7, 0xe, 0x0, 0xd, 0x11, 0x18,
        0x10, 0xc, 0x1, 0x19, 0x16, 0xa, 0xf, 0x17};

    ascon64 Rrotation(ascon64 x, int i);
    void Padding(const ascon_data &data, ascon_stream &res, bool one);
    void Permutation(const int round, ascon_state &S);
    void Transform(const ascon_stream &input, ascon_data &output, int ex);

    void Initialization(ascon_state &S, const ascon128 &key, const ascon128 &nonce);
    void ProcessingAssociatedData(ascon_state &S, const ascon_data &associateddata);
    void ProcessingPlaintext(ascon_state &S, const ascon_data &plaintext, ascon_data &ciphertext);
    void ProcessingCipherext(ascon_state &S, ascon_data &plaintext, const ascon_data &ciphertext);
    void Finalization(ascon_state &S, const ascon128 key, ascon128 &tag);

    void Encryption(const ascon_data &plaintext, const ascon_data &associateddata, ascon_data &ciphertext, const ascon128 &key, const ascon128 &nonce, ascon128 &tag);
    bool Decryption(const ascon_data &ciphertext, const ascon_data &associateddata, ascon_data &plaintext, const ascon128 &key, const ascon128 &nonce, const ascon128 &tag);

    void printdata(const char *info, const ascon_data data);
    void print128(const char *info, const ascon128 data);
};

#endif