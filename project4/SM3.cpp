#include <iostream>
#include <iomanip>
#include <cstring>
#include <chrono>
#include <random>

using namespace std;

#define ROTL(x, n) (((x) << (n)) | ((x) >> (32 - (n))))

const uint32_t IV[8] = {
    0x7380166F, 0x4914B2B9, 0x172442D7, 0xDA8A0600,
    0xA96F30BC, 0x163138AA, 0xE38DEE4D, 0xB0FB0E4E
};

uint32_t T_j[64];

void Init_T() {
    for (int j = 0; j < 64; j++)
        T_j[j] = (j <= 15) ? 0x79CC4519 : 0x7A879D8A;
}

uint32_t P0(uint32_t x) { return x ^ ROTL(x, 9) ^ ROTL(x, 17); }
uint32_t P1(uint32_t x) { return x ^ ROTL(x, 15) ^ ROTL(x, 23); }

uint32_t FF(uint32_t x, uint32_t y, uint32_t z, int j) {
    return (j <= 15) ? (x ^ y ^ z) : ((x & y) | (x & z) | (y & z));
}
uint32_t GG(uint32_t x, uint32_t y, uint32_t z, int j) {
    return (j <= 15) ? (x ^ y ^ z) : ((x & y) | ((~x) & z));
}

void message_expand(const uint8_t* block, uint32_t* W, uint32_t* W1) {
    for (int j = 0; j < 16; j++) {
        W[j] = (block[j * 4] << 24) | (block[j * 4 + 1] << 16) |
            (block[j * 4 + 2] << 8) | block[j * 4 + 3];
    }
    for (int j = 16; j < 68; j++) {
        W[j] = P1(W[j - 16] ^ W[j - 9] ^ ROTL(W[j - 3], 15)) ^ ROTL(W[j - 13], 7) ^ W[j - 6];
    }
    for (int j = 0; j < 64; j++) {
        W1[j] = W[j] ^ W[j + 4];
    }
}

void CF(uint32_t* V, const uint8_t* block) {
    uint32_t W[68], W1[64];
    message_expand(block, W, W1);

    uint32_t A = V[0], B = V[1], C = V[2], D = V[3];
    uint32_t E = V[4], F = V[5], G = V[6], H = V[7];

    for (int j = 0; j < 64; j++) {
        uint32_t SS1 = ROTL((ROTL(A, 12) + E + ROTL(T_j[j], j)) & 0xFFFFFFFF, 7);
        uint32_t SS2 = SS1 ^ ROTL(A, 12);
        uint32_t TT1 = (FF(A, B, C, j) + D + SS2 + W1[j]) & 0xFFFFFFFF;
        uint32_t TT2 = (GG(E, F, G, j) + H + SS1 + W[j]) & 0xFFFFFFFF;
        D = C;
        C = ROTL(B, 9);
        B = A;
        A = TT1;
        H = G;
        G = ROTL(F, 19);
        F = E;
        E = P0(TT2);
    }

    V[0] ^= A; V[1] ^= B; V[2] ^= C; V[3] ^= D;
    V[4] ^= E; V[5] ^= F; V[6] ^= G; V[7] ^= H;
}

void SM3(const uint8_t* message, uint64_t message_len, uint8_t* digest) {
    uint64_t bit_len = message_len * 8;
    uint64_t k = (448 - (bit_len + 1) % 512) % 512;
    uint64_t total_bits = bit_len + 1 + k + 64;
    uint64_t total_bytes = total_bits / 8;

    uint8_t* padded = new uint8_t[total_bytes];
    memcpy(padded, message, message_len);
    padded[message_len] = 0x80;
    memset(padded + message_len + 1, 0, total_bytes - message_len - 1 - 8);

    for (int i = 0; i < 8; i++) {
        padded[total_bytes - 8 + i] = (bit_len >> (56 - i * 8)) & 0xFF;
    }

    uint32_t V[8];
    memcpy(V, IV, sizeof(IV));

    for (uint64_t i = 0; i < total_bytes; i += 64) {
        CF(V, padded + i);
    }

    delete[] padded;

    for (int i = 0; i < 8; i++) {
        digest[i * 4] = (V[i] >> 24) & 0xFF;
        digest[i * 4 + 1] = (V[i] >> 16) & 0xFF;
        digest[i * 4 + 2] = (V[i] >> 8) & 0xFF;
        digest[i * 4 + 3] = V[i] & 0xFF;
    }
}

void print_hex(const uint8_t* data, int len) {
    for (int i = 0; i < len; i++)
        cout << hex << setw(2) << setfill('0') << (int)data[i];
    cout << dec << endl;
}

// 正确性测试
void correctness_test() {
    cout << "[正确性测试]" << endl;
    uint8_t msg[] = "abc";
    uint8_t digest[32];
    SM3(msg, 3, digest);
    cout << "输入: abc" << endl;
    cout << "SM3结果: ";
    print_hex(digest, 32);
    cout << "期望: 66c7f0f462eeedd9d1f2d46bdc10e4e24167c4875cf2f7a2297da02b8f4ba8e0" << endl;

    const char* longmsg = "The quick brown fox jumps over the lazy dog";
    SM3((const uint8_t*)longmsg, strlen(longmsg), digest);
    cout << "输入: The quick brown fox jumps over the lazy dog" << endl;
    cout << "SM3结果: ";
    print_hex(digest, 32);   
    cout << "期望: 5fdfe814b8573ca021983970fc79b2218c9570369b4859684e2e4c3fc76cb8ea" << endl;
}

// 效率测试
void speed_test(int loops = 1000000) {
    cout << "\n[效率测试]" << endl;
    uint8_t buffer[64], digest[32];
    random_device rd;
    for (int i = 0; i < 64; i++) buffer[i] = rd() % 256;

    auto start = chrono::high_resolution_clock::now();
    for (int i = 0; i < loops; i++) {
        SM3(buffer, 64, digest);
    }
    auto end = chrono::high_resolution_clock::now();
    chrono::duration<double> elapsed = end - start;

    cout << loops << "次 64字节SM3耗时: " << elapsed.count() << " 秒" << endl;
    cout << "速度: " << (loops * 64.0 / (1024 * 1024) / elapsed.count()) << " MB/s" << endl;
}

int main() {
    Init_T();
    correctness_test();
    speed_test();
    return 0;
}
