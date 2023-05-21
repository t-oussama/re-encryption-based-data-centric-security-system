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
#define PRF_CTR_LEN SHA256_DIGEST_LENGTH
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

void print(const char* label, unsigned int* var, const unsigned int len) {
    cout << label << ": ";
    for (unsigned int i = 0; i < len; i++) {
        cout << i << " -> " << var[i] << ", ";
    }
    cout << endl;
}

class AontBasedEncryption {
    private:
        unsigned int blockSize;

        unsigned char* AllOrNothingTransform(unsigned char *ctr, unsigned char *m, unsigned int n) {
            // TODO: make keyGen random
            unsigned char keyGen[] = {'a', 'b', 'c', '3' , '9'};
            const int keyGenLength = 5;
            // Generate the Prf key based on keyGen
            unsigned char prfKey[PRF_KEY_LEN];
            SHA256(keyGen, keyGenLength, prfKey);

            // Generate the Prf counter based on ctr
            unsigned char prfCtr[PRF_KEY_LEN];
            SHA256(ctr, this->blockSize, prfCtr);

            const unsigned int messageLength = n*this->blockSize;
            unsigned char *cipher = new unsigned char[messageLength+this->blockSize];

            // Encrypt the plaintext using CTR
            AesCtrEncrypt(m, messageLength, cipher, prfKey, prfCtr);

            // calc hash of the encrypted plaintext
            unsigned char token[SHA256_DIGEST_LENGTH];
            SHA256(cipher, messageLength, token);
            // Generate token as hash xor encryption key
            for(unsigned int i = 0; i < SHA256_DIGEST_LENGTH; i++) {
                token[i] ^= prfKey[i];
            }

            // copy token
            memcpy(cipher+messageLength, token, SHA256_DIGEST_LENGTH);

            // pad the token with random bits until it reaches size this->blockSize
            // to get random bits use an encryption function
            unsigned int paddingLength = this->blockSize - SHA256_DIGEST_LENGTH;
            if (paddingLength <= 0) {
                return cipher;
            }
            unsigned char* plainTokenPadding = new unsigned char[paddingLength]();
            unsigned char* randomTokenPadding = new unsigned char[paddingLength]();
            AesCtrEncrypt(plainTokenPadding, paddingLength, randomTokenPadding, prfKey, prfCtr);
            // copy token padding
            memcpy(cipher+messageLength+SHA256_DIGEST_LENGTH, randomTokenPadding, paddingLength);

            return cipher;
        }

        unsigned char* AllOrNothingRevert(unsigned char *ctr, unsigned char *cipher, unsigned char* token, unsigned int n) {
            const unsigned int messageLength = n*this->blockSize;
            unsigned char* m = new unsigned char[messageLength];
            
            // Generate the Prf counter based on ctr
            unsigned char prfCtr[PRF_KEY_LEN];
            SHA256(ctr, this->blockSize, prfCtr);

            // calc hash of encrypted message
            unsigned char prfKey[SHA256_DIGEST_LENGTH];
            SHA256(cipher, messageLength, prfKey);
            // find the encryption key by xoring hash and token
            for(unsigned int i = 0; i < SHA256_DIGEST_LENGTH; i++) {
                prfKey[i] ^= token[i];
            }

            AesCtrDecrypt(cipher, messageLength, m, prfKey, prfCtr);
            return m;
        }

        void AesCtrEncrypt(unsigned char* plaintext, unsigned int plaintextLength, unsigned char* cipher, unsigned char* key, unsigned char* counter) {
            EVP_CIPHER_CTX *ctx;
            ctx = EVP_CIPHER_CTX_new();
            EVP_EncryptInit_ex(ctx, EVP_aes_256_ctr(), NULL, key, counter);
            int len, ciphertext_len;
            EVP_EncryptUpdate(ctx, cipher, &len, plaintext, plaintextLength);
            ciphertext_len = len;
            EVP_EncryptFinal_ex(ctx, cipher + len, &len);
            ciphertext_len += len;
            /* Clean up */
            EVP_CIPHER_CTX_free(ctx);
        }

        void AesCtrDecrypt(unsigned char* cipher, unsigned int originalPlaintextLength, unsigned char* plaintext, unsigned char* key, unsigned char* counter) {
            EVP_CIPHER_CTX *ctx;
            ctx = EVP_CIPHER_CTX_new();
            EVP_DecryptInit_ex(ctx, EVP_aes_256_ctr(), NULL, key, counter);
            int len, ciphertext_len;
            EVP_DecryptUpdate(ctx, plaintext, &len, (unsigned char*)cipher, originalPlaintextLength);
            ciphertext_len = len;
            EVP_DecryptFinal_ex(ctx, plaintext + len, &len);
            ciphertext_len += len;
            /* Clean up */
            EVP_CIPHER_CTX_free(ctx);
        }

        unsigned char* PermutationEncryption(const unsigned char *input, const unsigned int *permutations, unsigned int n) {
            unsigned char* result = new unsigned char[n*this->blockSize];
            for(unsigned int i = 0; i < n; i++) {
                memcpy(result+i*this->blockSize, input+permutations[i]*this->blockSize, this->blockSize);
            }
            return result;
        }

        unsigned char* PermutationDecryption(const unsigned char *input, const unsigned int *permutations, unsigned int n) {
            unsigned char* result = new unsigned char[n*this->blockSize];
            for(unsigned int i = 0; i < n; i++) {
                memcpy(result+permutations[i]*this->blockSize, input+i*this->blockSize, this->blockSize);
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

        void quickSort(unsigned int* key, unsigned char** tmp, const int start , const int end, size_t tmpUnitSize) {
            if(start >= end -1) {
                return;
            }

            unsigned int q = partition(key, tmp, start, end, tmpUnitSize);
            quickSort(key, tmp, start, q, tmpUnitSize);
            quickSort(key, tmp, q+1, end, tmpUnitSize);
        }

        unsigned int partition(unsigned int* key, unsigned char** tmp, const int start , const int end, size_t tmpUnitSize) {
            unsigned char* pivot = tmp[end-1];
            unsigned int i = start;
            for (unsigned int j = start; j < end - 1; j++) {
                if (memcmp(tmp[j], pivot, tmpUnitSize) <= 0) {
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
        AontBasedEncryption(int blockSize) {
            this->blockSize = blockSize;
        }

        unsigned int* GeneratePermutationKey(unsigned char* prfKey, const unsigned int permutationKeyLen) {
            unsigned int* permutationKey = new unsigned int[permutationKeyLen];
            unsigned char** tmp = new unsigned char*[permutationKeyLen];

            size_t tmpUnitSize = sizeof(unsigned int);
            unsigned char* x = new unsigned char[tmpUnitSize*permutationKeyLen]{0};
            auto t1 = high_resolution_clock::now();
            long long cost = 0;
            for (unsigned int i = 0; i < permutationKeyLen; i++) {
                permutationKey[i] = i;
                memcpy(x + i*tmpUnitSize, &i, tmpUnitSize);
            }

            // TODO: counter probably shouldn't be a constant
            unsigned char counter[PRF_CTR_LEN] = {0};
            // TODO: check if this can be further improved and if using aes ctr
            // causes any security risk
            unsigned char* fullTmp = new unsigned char[tmpUnitSize*permutationKeyLen];
            AesCtrEncrypt(x , tmpUnitSize*permutationKeyLen, fullTmp, prfKey, counter);
            for (unsigned int i = 0; i < permutationKeyLen; i++) {
                tmp[i] = fullTmp + i*tmpUnitSize;
            }

            delete[] x;
            auto t2 = high_resolution_clock::now();
            cout << "       PRF took: " << duration_cast<milliseconds>(t2 - t1).count() << endl;

            t1 = high_resolution_clock::now();
            quickSort(permutationKey, tmp, 0, permutationKeyLen, tmpUnitSize);
            t2 = high_resolution_clock::now();
            cout << "       Sorting took: " << duration_cast<milliseconds>(t2 - t1).count() << endl;
            // clean up
            // for (unsigned int i = 0; i < permutationKeyLen; i++) {
            //     delete[] tmp[i];
            // }
            delete[] fullTmp;
            delete[] tmp;

            return permutationKey;
        }

        unsigned char** Encrypt(unsigned char* ctr, unsigned char* prfKey1, unsigned char* prfKey2, unsigned char* prfKey3, unsigned char* message, const unsigned int msgLen, const unsigned int n) {
            auto t = high_resolution_clock::now();
            auto permKey1 = GeneratePermutationKey(prfKey1, this->blockSize*8);
            auto permKey2 = GeneratePermutationKey(prfKey2, this->blockSize*8);
            
            auto t1 = high_resolution_clock::now();
            auto permKey3 = GeneratePermutationKey(prfKey3, n);
            auto t2 = high_resolution_clock::now();
            cout << "Key 3 generation took: " << duration_cast<milliseconds>(t2 - t1).count() << endl;

            const unsigned int messageLength = n*this->blockSize;
            unsigned char* cipher = new unsigned char[messageLength+this->blockSize];
            t1 = high_resolution_clock::now();
            unsigned char* m1 = AllOrNothingTransform(ctr, message, n);
            t2 = high_resolution_clock::now();
            cout << "AONT took: " << duration_cast<milliseconds>(t2 - t1).count() << endl;

            unsigned char* m2 = PermutationEncryption(m1, permKey3, n);
            delete[] permKey3;

            auto encryptedToken = BitPermutationEncryption(m1+messageLength, permKey1, this->blockSize);
            delete[] m1;
            
            unsigned char* iv = new unsigned char [this->blockSize];
            memcpy(iv, ctr, this->blockSize); // TODO_L: should IV really be the same as ctr ?
            auto encryptedIv = BitPermutationEncryption(iv, permKey2, this->blockSize);
            for(unsigned int i = 0; i < this->blockSize; i++) {
                encryptedToken[i] = encryptedToken[i] ^ encryptedIv[i];
            }
            delete[] encryptedIv;
            memcpy(cipher, encryptedToken, this->blockSize);
            delete[] encryptedToken;

            t1 = high_resolution_clock::now();
            for (unsigned int i = 0; i < n; i++) {
                auto x = BitPermutationEncryption(m2+i*this->blockSize, permKey1, this->blockSize);
                auto y = BitPermutationEncryption(cipher+i*this->blockSize, permKey2, this->blockSize);

                for(unsigned int j = 0; j < this->blockSize; j++) {
                    x[j] = x[j] ^ y[j];
                }
                delete[] y;

                memcpy(cipher+(i+1)*this->blockSize, x, this->blockSize);
                delete[] x;
            }
            cout << endl;
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
            auto permKey1 = GeneratePermutationKey(prfKey1, this->blockSize*8);
            auto permKey2 = GeneratePermutationKey(prfKey2, this->blockSize*8);

            unsigned char* m2 = new unsigned char[n*this->blockSize];
            
            for (unsigned int i = 0; i < n; i++) {
                auto y = BitPermutationEncryption(cipher+(n-i-1)*this->blockSize, permKey2, this->blockSize);
                for(unsigned int j = 0; j < this->blockSize; j++) {
                    y[j] ^= cipher[(n-i)*this->blockSize+j];
                }
                auto x = BitPermutationDecryption(y, permKey1, this->blockSize);
                delete[] y;
                memcpy(m2+(n-1-i)*this->blockSize, x, this->blockSize);
                delete[] x;
            }

            auto encryptedIv = BitPermutationEncryption(iv, permKey2, this->blockSize);
            delete[] permKey2;
            auto encryptedToken = new unsigned char[this->blockSize];
            for(unsigned int j = 0; j < this->blockSize; j++) {
                    encryptedToken[j] = cipher[j] ^ encryptedIv[j];
            }
            delete[] encryptedIv;

            auto token = BitPermutationDecryption(encryptedToken, permKey1, this->blockSize);
            delete[] permKey1;
            delete[] encryptedToken;

            auto permKey3 = GeneratePermutationKey(prfKey3, n);
            auto m1 = PermutationDecryption(m2, permKey3, n);
            delete[] permKey3;

            auto message = AllOrNothingRevert(ctr, m1, token, n);
            delete[] m1;
            delete[] token;
            return message;
        }

        unsigned int* FindConversionKey(const unsigned int* permutationListA, const unsigned int* permutationListB, const unsigned int n) {
            unsigned int* conversionKey = new unsigned int[n];
            unsigned int* inversePermutationListA = new unsigned int[n];
            unsigned int* inversePermutationListB = new unsigned int[n];
            for(unsigned int i = 0; i < n; i++) {
                inversePermutationListA[permutationListA[i]] = i;
                inversePermutationListB[permutationListB[i]] = i;
            }

            for(unsigned int i = 0; i < n; i++) {
                conversionKey[inversePermutationListB[i]] = inversePermutationListA[i];
            }

            return conversionKey;
        }

        unsigned char** ReEncrypt(unsigned int* reEncryptionKey1, unsigned int* originalKey2, unsigned int* newKey2, unsigned int* reEncryptionKey3, unsigned char* iv, unsigned char* cipher, unsigned int n) {
            unsigned char* c1 = new unsigned char[n*this->blockSize];
            
            for (unsigned int i = 0; i < n; i++) {
                auto y = BitPermutationEncryption(cipher+(n-i-1)*this->blockSize, originalKey2, this->blockSize);
                for(unsigned int j = 0; j < this->blockSize; j++) {
                    y[j] ^= cipher[(n-i)*this->blockSize+j];
                }
                auto x = BitPermutationEncryption(y, reEncryptionKey1, this->blockSize);
                delete[] y;
                memcpy(c1+(n-1-i)*this->blockSize, x, this->blockSize);
                delete[] x;
            }

            auto c2_tmp = PermutationEncryption(c1, reEncryptionKey3, n);

            delete[] c1;

            auto encryptedIv1 = BitPermutationEncryption(iv, originalKey2, this->blockSize);
            auto encryptedIv2 = BitPermutationEncryption(iv, newKey2, this->blockSize);
            auto encryptedToken = new unsigned char[this->blockSize];
            for(unsigned int j = 0; j < this->blockSize; j++) {
                encryptedToken[j] = cipher[j] ^ encryptedIv1[j];
            }
            delete[] encryptedIv1;

            auto token = BitPermutationEncryption(encryptedToken, reEncryptionKey1, this->blockSize);

            for(unsigned int j = 0; j < this->blockSize; j++) {
                encryptedToken[j] = token[j] ^ encryptedIv2[j];
            }
            delete[] encryptedIv2;
            delete[] token;

            auto c2 = new unsigned char[n*this->blockSize + this->blockSize];
            memcpy(c2+this->blockSize, c2_tmp, n*this->blockSize);
            memcpy(c2, encryptedToken, this->blockSize);
            delete[] encryptedToken;
            delete[] c2_tmp;

            for (unsigned int i = 0; i < n; i++) {
                auto y = BitPermutationEncryption(c2+i*this->blockSize, newKey2, this->blockSize);

                for(unsigned int j = 0; j < this->blockSize; j++) {
                    y[j] = c2[(i+1)*this->blockSize+j] ^ y[j];
                }

                memcpy(c2+(i+1)*this->blockSize, y, this->blockSize);
                delete[] y;
            }

            auto res = new unsigned char*[2];
            res[0] = iv;
            res[1] = c2;
            return res;
        }

        unsigned int GetBlockSize() {
            return this->blockSize;
        }
};

extern "C" {
    AontBasedEncryption* AontBasedEncryption_new(unsigned int blockSize){ return new AontBasedEncryption(blockSize); }
    unsigned char** AontBasedEncryption_Encrypt(AontBasedEncryption* enc, unsigned char* ctr, unsigned char* prfKey1, unsigned char* prfKey2, unsigned char* prfKey3, unsigned char* message, const unsigned int msgLen, const unsigned int n) {
        return enc->Encrypt(ctr, prfKey1, prfKey2, prfKey3, message, msgLen, n);
    }
    unsigned char* AontBasedEncryption_Decrypt(AontBasedEncryption* enc, unsigned char* ctr, unsigned char* prfKey1, unsigned char* prfKey2, unsigned char* prfKey3, unsigned char* cipher, const unsigned int cipherLen, const unsigned char* iv, const unsigned int n) {
        return enc->Decrypt(ctr, prfKey1, prfKey2, prfKey3, cipher, cipherLen, iv, n);
    }

    unsigned int* AontBasedEncryption_FindConversionKey(AontBasedEncryption* enc, unsigned int* permutationListA, unsigned int* permutationListB, const unsigned int n) {
        return enc->FindConversionKey(permutationListA, permutationListB, n);
    }

    unsigned char** AontBasedEncryption_ReEncrypt(AontBasedEncryption* enc, unsigned int* reEncryptionKey1, unsigned int* originalKey2Generator, unsigned int* newKey2Generator, unsigned int* reEncryptionKey3, unsigned char* iv, unsigned char* cipher, unsigned int n) {
        return enc->ReEncrypt(reEncryptionKey1, originalKey2Generator, newKey2Generator, reEncryptionKey3, iv, cipher, n);
    }

    unsigned int* AontBasedEncryption_GeneratePermutationKey(AontBasedEncryption* enc, unsigned char* prfKey, const unsigned int permutationKeyLen) {
        return enc->GeneratePermutationKey(prfKey, permutationKeyLen);
    }

    unsigned int AontBasedEncryption_GetBlockSize(AontBasedEncryption* enc) {
        return enc->GetBlockSize();
    }
}
