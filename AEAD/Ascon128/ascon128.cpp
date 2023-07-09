#include "ascon128.h"
#include <bits/stdc++.h>

namespace ASCON128
{
    ascon128::ascon128() : high(0), low(0) {}
    ascon128::ascon128(ascon64 a, ascon64 b) : high(a), low(b) {}
    bool ascon128::operator==(const ascon128 &tmp) const
    {
        return (tmp.high == this->high) && (tmp.low == this->low);
    }

    void Encryption(const ascon_data &plaintext, const ascon_data &associateddata, ascon_data &ciphertext, const ascon128 &key, const ascon128 &nonce, ascon128 &tag)
    {
        ascon_state S;
        Initialization(S, key, nonce);
        ProcessingAssociatedData(S, associateddata);
        ProcessingPlaintext(S, plaintext, ciphertext);
        Finalization(S, key, tag);
    }

    bool Decryption(const ascon_data &ciphertext, const ascon_data &associateddata, ascon_data &plaintext, const ascon128 &key, const ascon128 &nonce, const ascon128 &tag)
    {
        ascon_state S;
        Initialization(S, key, nonce);
        ProcessingAssociatedData(S, associateddata);
        ProcessingCipherext(S, plaintext, ciphertext);
        ascon128 check;
        Finalization(S, key, check);
        return check == tag;
    }

    void Initialization(ascon_state &S, const ascon128 &key, const ascon128 &nonce)
    {
        // puts("Initializing...");
        if (!S.empty())
            S.clear();
        S.push_back(0x80400c0600000000);
        S.push_back(key.high);
        S.push_back(key.low);
        S.push_back(nonce.high);
        S.push_back(nonce.low);
        // printf("S: ");
        // for (int i = 0; i < 5; i++)
        // {
        //     printf("%016llx ", S[i]);
        // }
        // putchar('\n');
        Permutation(a, S);
        S[3] ^= key.high;
        S[4] ^= key.low;
        // printf("S: ");
        // for (int i = 0; i < 5; i++)
        // {
        //     printf("%016llx ", S[i]);
        // }
        // putchar('\n');
    }

    void ProcessingAssociatedData(ascon_state &S, const ascon_data &associateddata)
    {
        // printdata("ProcessingAssociatedData: ", associateddata);
        if (!associateddata.empty())
        {
            ascon_stream A;
            A.clear();
            Padding(associateddata, A, 1);
            int s = A.size();
            // printf("associateddata.size=%d\n", associateddata.size());
            // for (int i = 0; i < s; i++)
            // {
            //     printf("%016llx ", A[i]);
            // }
            // putchar('\n');
            for (int i = 0; i < s; i++)
            {
                S[0] ^= A[i];
                Permutation(b, S);
            }
        }
        S[4] ^= 1;
        // printf("S: ");
        // for (int i = 0; i < 5; i++)
        // {
        //     printf("%016llx ", S[i]);
        // }
        // putchar('\n');
    }

    void ProcessingPlaintext(ascon_state &S, const ascon_data &plaintext, ascon_data &ciphertext)
    {
        // printdata("ProcessingPlaintext: ", plaintext);
        ascon_stream P, C;
        P.clear();
        C.clear();
        Padding(plaintext, P, 1);
        // printf("plaintext.size=%d\n", plaintext.size());
        int t = P.size(), ex = (plaintext.size() << 3) % r;
        // for (int i = 0; i < t; i++)
        // {
        //     printf("%016llx ", P[i]);
        // }
        // putchar('\n');
        // printf("ex=%d\n", ex);
        for (int i = 0; i < t; i++)
        {
            S[0] ^= P[i];
            C.push_back(S[0]);
            if (i < t - 1)
            {
                Permutation(b, S);
            }
            else
            {
                ascon64 x = -1;
                // printf("%016llx %016llx\n", x, ((x >> (64))));
                x = ex ? ((x >> (64 - ex)) << (64 - ex)) : 0;
                C[i] &= x;
            }
        }
        Transform(C, ciphertext, ex);
    }

    void ProcessingCipherext(ascon_state &S, ascon_data &plaintext, const ascon_data &ciphertext)
    {
        ascon_stream P, C;
        P.clear();
        C.clear();
        Padding(ciphertext, C, 0);
        int t = C.size(), ex = (ciphertext.size() << 3) % r;
        // for (int i = 0; i < t; i++)
        // {
        //     printf("%016llx ", C[i]);
        // }
        // putchar('\n');
        // printf("ex=%d\n", ex);
        for (int i = 0; i < t - 1; i++)
        {
            P.push_back(S[0] ^ C[i]);
            S[0] = C[i];
            Permutation(b, S);
        }
        ascon64 x = ex ? ((S[0] >> (64 - ex)) << (64 - ex)) : 0;
        P.push_back(x ^ C[t - 1]);
        S[0] ^= P[t - 1] | (1ull << (63 - ex));
        Transform(P, plaintext, ex);
    }

    void Finalization(ascon_state &S, const ascon128 key, ascon128 &tag)
    {
        S[1] ^= key.high;
        S[2] ^= key.low;
        Permutation(a, S);
        tag.high = S[3] ^ key.high;
        tag.low = S[4] ^ key.low;
    }

    void Permutation(const int round, ascon_state &S)
    {
        for (int i = 12 - round; i < 12; i++)
        {
            // Round constant addition
            S[2] ^= cr[i];

            // Substitution layer
            for (int j = 0; j < 64; j++)
            {
                ascon8 x = 0;
                ascon64 y = 1ull << j, z = ~y;
                for (int k = 0; k < 5; k++)
                {
                    x <<= 1;
                    if (S[k] & y)
                        x |= 1;
                }
                x = Sbox[x];
                for (int k = 0; k < 5; k++)
                {
                    if (x & (1 << k))
                        S[4 - k] |= y;
                    else
                        S[4 - k] &= z;
                }
            }

            // Linear layer
            S[0] ^= Rrotation(S[0], 19) ^ Rrotation(S[0], 28);
            S[1] ^= Rrotation(S[1], 61) ^ Rrotation(S[1], 39);
            S[2] ^= Rrotation(S[2], 1) ^ Rrotation(S[2], 6);
            S[3] ^= Rrotation(S[3], 10) ^ Rrotation(S[3], 17);
            S[4] ^= Rrotation(S[4], 7) ^ Rrotation(S[4], 41);
        }
    }

    ascon64 Rrotation(ascon64 x, int k)
    {
        return (x << (64 - k)) | (x >> k);
    }

    void Padding(const ascon_data &data, ascon_stream &res, bool one)
    {
        int size = data.size(), block = r >> 3, count = 0;
        for (int i = 0; i < size / block; i++)
        {
            ascon64 tmp = 0;
            for (int j = 0; j < block; j++)
            {
                tmp <<= 8;
                tmp += data[i * block + j];
                count++;
            }
            res.push_back(tmp);
        }
        ascon64 tmp = 0;
        int zeros = r;
        if (size % block)
        {
            for (int i = count; i < size; i++)
            {
                tmp <<= 8;
                tmp |= data[i];
                zeros -= 8;
            }
        }
        if (one)
        {
            tmp <<= 1;
            tmp |= 1;
            zeros--;
        }
        while (zeros--)
            tmp <<= 1;
        res.push_back(tmp);
    }

    void Transform(const ascon_stream &input, ascon_data &output, int ex)
    {
        int si = input.size();
        for (int i = 0; i < si - 1; i++)
        {
            for (int j = 0; j < 8; j++)
            {
                ascon8 x = input[i] >> ((7 - j) << 3);
                output.push_back(x);
            }
        }
        for (int i = 0; i < (ex >> 3); i++)
        {
            ascon8 x = input[si - 1] >> ((7 - i) << 3);
            output.push_back(x);
        }
    }

    void printdata(const char *info, const ascon_data data)
    {
        printf("%s", info);
        int sz = data.size();
        for (int i = 0; i < sz; i++)
        {
            printf("%02x ", data[i]);
        }
        putchar('\n');
    }

    void print128(const char *info, const ascon128 data)
    {
        printf("%s", info);
        printf("%016llx ", data.high);
        printf("%016llx\n", data.low);
    }
};