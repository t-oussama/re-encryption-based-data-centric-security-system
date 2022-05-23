#include <iostream>
#include <algorithm>
#include <cstring>
#include <stdexcept>

#include <bitset>

#include "openssl/sha.h"
#include "openssl/aes.h"
#include <openssl/evp.h>

#include <chrono>
using std::chrono::high_resolution_clock;
using std::chrono::duration_cast;
using std::chrono::duration;
using std::chrono::milliseconds;
using std::chrono::nanoseconds;
#define MILLI_TO_NANO_FACTOR 1000000

#define PRF_KEY_LEN SHA256_DIGEST_LENGTH
#define L PRF_KEY_LEN

using namespace std;

void print(const char* label, const unsigned char* var, const unsigned int len) {
    cout << label << ": ";
    for (unsigned int i = 0; i < len; i++) {
        cout << var[i];
    }
    cout << endl;
}

void printBytes(const char* label, const unsigned char* var, const unsigned int len) {
    cout << label << ": ";
    for (unsigned int i = 0; i < len; i++) {
        cout << (int) var[i] << ",";
    }
    cout << endl;
}

class AontBasedEncryption {
    private:

        unsigned char* AllOrNothingTransform(unsigned char *ctr, unsigned char *m, unsigned int n) {
            // TODO: make keyGen random
            unsigned char keyGen[] = {'a', 'b', 'c', '3' , '9'};
            const int keyGenLength = 5;
            // Generate the Prf key based on keyGen
            unsigned char prfKey[PRF_KEY_LEN];
            SHA256(keyGen, keyGenLength, prfKey);

            const unsigned int messageLength = n*L;
            unsigned char *x = new unsigned char[messageLength+L];
            unsigned int counterMaxBytesCount = (n / 256) + 1;
            counterMaxBytesCount = min(counterMaxBytesCount, (unsigned int) L);
            unsigned int prefixLength = L - counterMaxBytesCount;

            // TODO: check if it's okay that aes block size is 16 but L is 32 (otherwise look for laternatives)
            {
                EVP_CIPHER_CTX *ctx;
                ctx = EVP_CIPHER_CTX_new();
                EVP_EncryptInit_ex(ctx, EVP_aes_256_ctr(), NULL, prfKey, ctr);
                int len, ciphertext_len;
                EVP_EncryptUpdate(ctx, x, &len, (unsigned char*)m, messageLength);
                ciphertext_len = len;
                EVP_EncryptFinal_ex(ctx, x + len, &len);
                ciphertext_len += len;
                /* Clean up */
                EVP_CIPHER_CTX_free(ctx);
            }
            // for (unsigned int i = 0; i < n; i++) {
            //     memcpy(ctr+prefixLength, &i, sizeof(i));
            //     unsigned char *blockRand = this->PseudoRandomFunction(ctr , L, prfKey);
            //     for (unsigned int j = 0; j < L; j++) {
            //         x[i*L+j] = m[i*L+j] ^ blockRand[j];
            //     }
            //     delete[] blockRand;
            // }

            // calc hash of x
            unsigned char token[SHA256_DIGEST_LENGTH];
            SHA256(x, messageLength, token);
            for(unsigned int i = 0; i < L; i++) {
                token[i] ^= prfKey[i];
            }
            // memcpy(x+messageLength, token, L);
            
            unsigned char ctrCopy[32];
            memcpy(ctrCopy, ctr, 32);
            // unsigned char hash[L];
            // for (unsigned int i = 0; i < n; i++) {
            //     memcpy(ctrCopy+prefixLength, &i, sizeof(i));
            //     for (unsigned int j = 0; j < L; j++) {
            //         token[j] = x[messageLength+j] ^ ctrCopy[j];
            //     }
            //     for(int j = 0; j < L/SHA256_DIGEST_LENGTH; j++) {//TODO: useless
            //         SHA256(token, L, hash);
            //     }
            //     for (unsigned int j = 0; j < L; j++) {
            //         x[i*L+j] ^= hash[j];
            //     }
            // }
            // return x;
            {
                for (unsigned int j = 0; j < L; j++) {
                    ctrCopy[j] ^= token[j];
                }                
                EVP_CIPHER_CTX *ctx;
                ctx = EVP_CIPHER_CTX_new();
                unsigned char fixedKey[33] = "12345678901234561234567890123456";
                unsigned char* cipher = new unsigned char[messageLength+L];
                EVP_EncryptInit_ex(ctx, EVP_aes_256_ctr(), NULL, fixedKey, ctrCopy);
                int len, ciphertext_len;
                EVP_EncryptUpdate(ctx, cipher, &len, (unsigned char*)x, messageLength);
                ciphertext_len = len;
                EVP_EncryptFinal_ex(ctx, cipher + len, &len);
                ciphertext_len += len;
                /* Clean up */
                EVP_CIPHER_CTX_free(ctx);
                memcpy(cipher+messageLength, token, L);
                return cipher;
            }
        }

        unsigned char* AllOrNothingRevert(unsigned char *ctr, unsigned char *cipher, unsigned char* token, unsigned int n) {
            const unsigned int messageLength = n*L;
            unsigned char* m = new unsigned char[messageLength];
            unsigned char* x = new unsigned char[messageLength];
            // unsigned char* token = x + messageLength;
            unsigned int counterMaxBytesCount = (n / 256) + 1;
            counterMaxBytesCount = min(counterMaxBytesCount, (unsigned int) L);
            unsigned int prefixLength = L - counterMaxBytesCount;
            
            // for (unsigned int i = 0; i < n; i++) {
            //     memcpy(ctr+prefixLength, &i, sizeof(i));
            //     for (unsigned int j = 0; j < L; j++) {
            //         m[i*L+j] = x[i*L + j] ^ token[j] ^ ctr[j];
            //     }
            // }
            unsigned char hash[L];
            unsigned char xoredToken[L];
            unsigned char ctrCopy[32];
            memcpy(ctrCopy, ctr, 32);
            // for (unsigned int i = 0; i < n; i++) {
            //     memcpy(ctrCopy+prefixLength, &i, sizeof(i));
            //     for (unsigned int j = 0; j < L; j++) {
            //         xoredToken[j] = token[j] ^ ctrCopy[j];
            //     }
            //     for(int j = 0; j < L/SHA256_DIGEST_LENGTH; j++) { //TODO: useless
            //         SHA256(xoredToken, L, hash);
            //     }
            //     for (unsigned int j = 0; j < L; j++) {
            //         x[i*L+j] = x[i*L+j] ^ hash[j];
            //     }
            // }
            { // TODO: check if it's secure to use encryption here.
                for (unsigned int j = 0; j < L; j++) {
                    ctrCopy[j] ^= token[j];
                }
                EVP_CIPHER_CTX *ctx;
                ctx = EVP_CIPHER_CTX_new();
                unsigned char fixedKey[33] = "12345678901234561234567890123456";
                EVP_DecryptInit_ex(ctx, EVP_aes_256_ctr(), NULL, fixedKey, ctrCopy);
                int len, ciphertext_len;
                EVP_DecryptUpdate(ctx, x, &len, cipher, messageLength);
                ciphertext_len = len;
                EVP_DecryptFinal_ex(ctx, x + len, &len);
                ciphertext_len += len;
                /* Clean up */
                EVP_CIPHER_CTX_free(ctx);
            }

            // calc hash of m
            unsigned char prfKey[SHA256_DIGEST_LENGTH];
            SHA256(x, messageLength, prfKey);
            for(unsigned int i = 0; i < L; i++) {
                prfKey[i] ^= token[i];
            }


            EVP_CIPHER_CTX *ctx;
            ctx = EVP_CIPHER_CTX_new();
            EVP_EncryptInit_ex(ctx, EVP_aes_256_ctr(), NULL, prfKey, ctr);
            int len, ciphertext_len;
            EVP_EncryptUpdate(ctx, m, &len, (unsigned char*)x, messageLength);
            ciphertext_len = len;
            EVP_EncryptFinal_ex(ctx, m + len, &len);
            ciphertext_len += len;
            /* Clean up */
            EVP_CIPHER_CTX_free(ctx);
            // for (unsigned int i = 0; i < n; i++) {
            //     memcpy(ctr+prefixLength, &i, sizeof(i));
            //     unsigned char *blockRand = this->PseudoRandomFunction(ctr , L, prfKey);
            //     for (unsigned int j = 0; j < L; j++) {
            //         m[i*L+j] ^= blockRand[j];
            //     }
            //     delete[] blockRand;
            // }

            return m;
        }

        unsigned char* PseudoRandomFunction(const unsigned char* bytes, const unsigned int size, const unsigned char* keyBytes) {
            // unsigned char* plainTextKey = (unsigned char*)"01234567890123456789012345678901";
            AES_KEY key;
            AES_set_encrypt_key(keyBytes, 256, &key);
            unsigned char* result = new unsigned char[size];
            // TODO: don't leave this as a hard coded value
            char iv[17] = "1234567890123456";
            AES_cbc_encrypt((unsigned char*)bytes, result, size, &key, (unsigned char*)iv, AES_ENCRYPT);
            return result;

            // // TODO: only works for simple case of size = SHA256_DIGEST_LENGTH
            // unsigned char* result = new unsigned char[SHA256_DIGEST_LENGTH];
            // SHA256_CTX sha256;
            // SHA256_Init(&sha256);
            // SHA256_Update(&sha256, bytes, size);
            // SHA256_Update(&sha256, keyBytes, PRF_KEY_LEN);
            // SHA256_Final(result, &sha256);
            // return result;
        }

        unsigned char* PermutationEncryption(const unsigned char *input, const unsigned int *permutations, unsigned int n) {
            unsigned char* result = new unsigned char[n*L];
            for(unsigned int i = 0; i < n; i++) {
                memcpy(result+i*L, input+permutations[i]*L, L);
            }
            return result;
        }

        unsigned char* PermutationDecryption(const unsigned char *input, const unsigned int *permutations, unsigned int n) {
            unsigned char* result = new unsigned char[n*L];
            for(unsigned int i = 0; i < n; i++) {
                memcpy(result+permutations[i]*L, input+i*L, L);
            }
            return result;
        }

        // n is the number of bytes
        unsigned char* BitPermutationEncryption(const unsigned char *input, const unsigned int *permutations, unsigned int n) {
            unsigned char* result = new unsigned char[n];
            for(unsigned int i = 0; i < n; i++) {
                const unsigned int blockStart = i*8;
                for(int j = 0; j < 8; j++) {
                    const unsigned int bytePos = permutations[blockStart+j] / 8;
                    const unsigned int bitPos = permutations[blockStart+j] % 8;
                    CopyBit(input+bytePos, result+i, bitPos, j);
                }
            }
            return result;
        }

        // n is the number of bytes
        unsigned char* BitPermutationDecryption(const unsigned char *input, const unsigned int *permutations, unsigned int n) {
            unsigned char* result = new unsigned char[n*8];
            for(unsigned int i = 0; i < n; i++) {
                const unsigned int blockStart = i*8;
                for(int j = 0; j < 8; j++) {
                    const unsigned int bytePos = permutations[blockStart+j] / 8;
                    const unsigned int bitPos = permutations[blockStart+j] % 8;
                    CopyBit(input+i, result+bytePos, j, bitPos);
                }
            }
            return result;
        }

        void CopyBit(const unsigned char* src, unsigned char* dst, int srcPos, int dstPos) {
            *dst = (*dst & ~(1UL << dstPos)) | (((*src >> srcPos) & 1U) << dstPos);
        }

        unsigned char* FindConversionKey(const unsigned char* permutaionListA, const unsigned char* permutationListB, const unsigned int n) {
            unsigned char* conversionKey = new unsigned char[n];
            for(unsigned int i = 0; i < n; i++) {
                for(unsigned int j = 0; j < n; j++) {
                    if(permutaionListA[i] == permutationListB[i]) {
                        conversionKey[j] = i;
                        break;
                    }
                }
            }

            return conversionKey;
        }

        // prfKey is of size L
        unsigned int* generatePermutationKey(unsigned char* prfKey, const unsigned int permutationKeyLen) {
            unsigned int* permutationKey = new unsigned int[permutationKeyLen];
            unsigned char** tmp = new unsigned char*[permutationKeyLen];

            unsigned char* x = new unsigned char[L]{0};
            auto t1 = high_resolution_clock::now();
            long long cost = 0;
            for (unsigned int i = 0; i < permutationKeyLen; i++) {
                permutationKey[i] = i;
                memcpy(x, &i, sizeof(unsigned int));
                tmp[i] = this->PseudoRandomFunction(x , L, prfKey);
            }
            delete[] x;
            auto t2 = high_resolution_clock::now();
            cout << "       PRF took: " << duration_cast<milliseconds>(t2 - t1).count() << endl;

            t1 = high_resolution_clock::now();
            quickSort(permutationKey, tmp, 0, permutationKeyLen);
            t2 = high_resolution_clock::now();
            cout << "       Sorting took: " << duration_cast<milliseconds>(t2 - t1).count() << endl;
            // clean up
            for (unsigned int i = 0; i < permutationKeyLen; i++) {
                delete[] tmp[i];
            }
            delete[] tmp;

            return permutationKey;
        }

        void quickSort(unsigned int* key, unsigned char** tmp, const int start , const int end) {
            if(start >= end -1) {
                return;
            }

            unsigned int q = partition(key, tmp, start, end);
            quickSort(key, tmp, start, q);
            quickSort(key, tmp, q+1, end);
        }

        unsigned int partition(unsigned int* key, unsigned char** tmp, const int start , const int end) {
            unsigned char* pivot = tmp[end-1];
            unsigned int i = start;
            for (unsigned int j = start; j < end - 1; j++) {
                if (memcmp(tmp[j], pivot, L) <= 0) { // compare the actual strings not their addresses
                    swap(tmp+i, tmp+j);
                    swap(key+i, key+j);
                    i++;
                }
            }

            swap(tmp+i, tmp+end-1);
            swap(key+i, key+end-1);
            return i;
        }

        template <typename T> void swap(T* a, T* b) {
            T tmp = *a;
            *a = *b;
            *b = tmp;
        }

    public:
        AontBasedEncryption() { }

        unsigned char** Encrypt(unsigned char* ctr, unsigned char* prfKey1, unsigned char* prfKey2, unsigned char* prfKey3, unsigned char* message, const unsigned int msgLen, const unsigned int n) {
            auto t = high_resolution_clock::now();
            auto permKey1 = generatePermutationKey(prfKey1, L*8);
            auto permKey2 = generatePermutationKey(prfKey2, L*8);
            
            auto t1 = high_resolution_clock::now();
            auto permKey3 = generatePermutationKey(prfKey3, n);
            auto t2 = high_resolution_clock::now();
            cout << "Key 3 generation took: " << duration_cast<milliseconds>(t2 - t1).count() << endl;

            const unsigned int messageLength = n*L;
            unsigned char* iv = new unsigned char [L];
            memcpy(iv, ctr, L);
            unsigned char* cipher = new unsigned char[messageLength+L];
            t1 = high_resolution_clock::now();
            unsigned char* m1 = AllOrNothingTransform(ctr, message, n);
            t2 = high_resolution_clock::now();
            cout << "AONT took: " << duration_cast<milliseconds>(t2 - t1).count() << endl;

            unsigned char* m2 = PermutationEncryption(m1, permKey3, n);
            delete[] permKey3;

            auto encryptedToken = BitPermutationEncryption(m1+messageLength, permKey1, L);
            delete[] m1;
            
            auto encryptedIv = BitPermutationEncryption(iv, permKey2, L);
            for(unsigned int i = 0; i < L; i++) {
                encryptedToken[i] = encryptedToken[i] ^ encryptedIv[i];
            }
            delete[] encryptedIv;
            memcpy(cipher, encryptedToken, L);
            delete[] encryptedToken;

            t1 = high_resolution_clock::now();
            // long long k1 = 0, k2 = 0, xor_t = 0, cpy = 0;
            for (unsigned int i = 0; i < n; i++) {
                auto x = BitPermutationEncryption(m2+i*L, permKey1, L);

                auto y = BitPermutationEncryption(cipher+i*L, permKey2, L);

                for(unsigned int i = 0; i < L; i++) {
                    x[i] = x[i] ^ y[i];
                }
                delete[] y;

                memcpy(cipher+i*L+L, x, L);
                delete[] x;
            }
            t2 = high_resolution_clock::now();
            cout << "Generating final cihper took: " << duration_cast<milliseconds>(t2 - t1).count() << endl;

            delete[] m2;
            delete[] permKey1;
            delete[] permKey2;

            auto res = new unsigned char*[2];
            res[0] = iv;
            res[1] = cipher;

            cout << "TOTAL took: " << duration_cast<milliseconds>(high_resolution_clock::now() - t).count() << endl;
            return res;
        }

        unsigned char* Decrypt(unsigned char* ctr, unsigned char* prfKey1, unsigned char* prfKey2, unsigned char* prfKey3, unsigned char* cipher, const unsigned int cipherLen, const unsigned char* iv, const unsigned int n) {
            // Generate permutation keys
            auto permKey1 = generatePermutationKey(prfKey1, L*8);
            auto permKey2 = generatePermutationKey(prfKey2, L*8);

            unsigned char* m2 = new unsigned char[n*L];
            
            for (unsigned int i = 0; i < n; i++) {
                auto y = BitPermutationEncryption(cipher+(n-i-1)*L, permKey2, L);
                for(unsigned int j = 0; j < L; j++) {
                    y[j] ^= cipher[(n-i)*L+j];
                }
                auto x = BitPermutationDecryption(y, permKey1, L);
                delete[] y;
                memcpy(m2+(n-1-i)*L, x, L);
                delete[] x;
            }

            auto encryptedIv = BitPermutationEncryption(iv, permKey2, L);
            delete[] permKey2;
            auto encryptedToken = new unsigned char[L];
            for(unsigned int j = 0; j < L; j++) {
                    encryptedToken[j] = cipher[j] ^ encryptedIv[j];
            }
            delete[] encryptedIv;

            auto token = BitPermutationDecryption(encryptedToken, permKey1, L);
            delete[] permKey1;
            delete[] encryptedToken;

            auto permKey3 = generatePermutationKey(prfKey3, n);
            auto m1 = PermutationDecryption(m2, permKey3, n);
            delete[] permKey3;

            auto message = AllOrNothingRevert(ctr, m1, token, n);
            delete[] m1;
            delete[] token;
            return message;
        }

        unsigned char* AesCbc(const unsigned char* bytes, const unsigned int size, const unsigned char* keyBytes) {
            auto t = high_resolution_clock::now();
            // unsigned char* plainTextKey = (unsigned char*)"01234567890123456789012345678901";
            AES_KEY key;
            AES_set_encrypt_key(keyBytes, 256, &key);
            unsigned char* ciphertext = new unsigned char[size];
            // TODO: don't leave this as a hard coded value
            char iv[17] = "1234567890123456";
            AES_cbc_encrypt((unsigned char*)bytes, ciphertext, size, &key, (unsigned char*)iv, AES_ENCRYPT);
            cout << "AES TOTAL took: " << duration_cast<milliseconds>(high_resolution_clock::now() - t).count() << endl;
            return ciphertext;
        }
};

// int main(int argc, char *argv[])
// {
//     AontBasedEncryption enc = AontBasedEncryption();
//     unsigned char ctr[64] = {'A'};
//     unsigned char prfKey1[L] = {'1'};
//     unsigned char prfKey2[L] = {'2'};
//     unsigned char prfKey3[L] = {'3'};
//     unsigned char message[64] = {'0'};
//     unsigned int n = 64/L;

//     cout << "Encrypting" << endl;
//     auto res = enc.Encrypt(ctr, prfKey1, prfKey2, prfKey3, message, 64, n);
//     auto iv = res[0];
//     auto cipher = res[1];
//     cout << "Decrypting" << endl;
//     auto msg = enc.Decrypt(ctr, prfKey1, prfKey2, prfKey3, cipher, 64, iv, n);
//     delete[] res;

//     cout << "msg: ";
//     for(unsigned int i = 0 ; i < 64; i++) {
//         cout << msg[i];
//     }
//     cout << endl;
//     delete[] msg;

//     return 0;
// }

extern "C" {
    AontBasedEncryption* AontBasedEncryption_new(){ return new AontBasedEncryption(); }
    void AontBasedEncryption_Test(AontBasedEncryption* enc) {
        unsigned char keyGen[] = {'a', 'b', 'c', '3' , '9'};
        const int keyGenLength = 5;
        // Generate the Prf key based on keyGen
        // unsigned char prfKey1[L];
        // SHA256(keyGen, keyGenLength, prfKey1);
        // unsigned char prfKey2[L];
        // keyGen[0] = 'b';
        // SHA256(keyGen, keyGenLength, prfKey2);
        // unsigned char prfKey3[L];
        // keyGen[0] = 't';
        // SHA256(keyGen, keyGenLength, prfKey3);

        unsigned char prfKey1[L] = {'1'};
        unsigned char prfKey2[L] = {'2'};
        unsigned char prfKey3[L] = {'3'};

        unsigned char ctr[] = "00000000000000000000000000000000";
        unsigned char message[] = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
        const unsigned int msgLen = 64;
        const unsigned int n = 2;
        auto res = enc->Encrypt(ctr, prfKey1, prfKey2, prfKey3, message, msgLen, n);

        auto iv = res[0];
        auto cipher = res[1];
        auto plain = enc->Decrypt(ctr, prfKey1, prfKey2, prfKey3, cipher, msgLen + L, iv, n);

        for(int i=  0; i < 64; i++) {
            cout << plain[i];
        }
        cout << endl;
    }
    unsigned char** AontBasedEncryption_Encrypt(AontBasedEncryption* enc, unsigned char* ctr, unsigned char* prfKey1, unsigned char* prfKey2, unsigned char* prfKey3, unsigned char* message, const unsigned int msgLen, const unsigned int n) {
        return enc->Encrypt(ctr, prfKey1, prfKey2, prfKey3, message, msgLen, n);
    }
    unsigned char* AontBasedEncryption_Decrypt(AontBasedEncryption* enc, unsigned char* ctr, unsigned char* prfKey1, unsigned char* prfKey2, unsigned char* prfKey3, unsigned char* cipher, const unsigned int cipherLen, const unsigned char* iv, const unsigned int n) {
        return enc->Decrypt(ctr, prfKey1, prfKey2, prfKey3, cipher, cipherLen, iv, n);
    }
    // for testing purposes only
    unsigned char* AontBasedEncryption_AesCbc(AontBasedEncryption* enc, const unsigned char* bytes, const unsigned int size, const unsigned char* keyBytes) {
        return enc->AesCbc(bytes, size, keyBytes);
    }
}
