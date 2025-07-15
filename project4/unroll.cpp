#include <iostream>
#include <iomanip>
#include <cstring>
#include <chrono>
#include <random>
using namespace std;

#define ROTL(x,n) (((x)<<(n))|((x)>>(32-(n))))
#define P0(x) ((x)^ROTL((x),9)^ROTL((x),17))
#define P1(x) ((x)^ROTL((x),15)^ROTL((x),23))
#define FF0(x,y,z) ((x)^(y)^(z))
#define FF1(x,y,z) (((x)&(y))|((x)&(z))|((y)&(z)))
#define GG0(x,y,z) ((x)^(y)^(z))
#define GG1(x,y,z) (((x)&(y))|((~(x))&(z)))

const uint32_t IV[8] = {
    0x7380166F,0x4914B2B9,0x172442D7,0xDA8A0600,
    0xA96F30BC,0x163138AA,0xE38DEE4D,0xB0FB0E4E
};

const uint32_t T[64] = {
    0x79cc4519,0x79cc4519,0x79cc4519,0x79cc4519, 0x79cc4519,0x79cc4519,0x79cc4519,0x79cc4519,
    0x79cc4519,0x79cc4519,0x79cc4519,0x79cc4519, 0x79cc4519,0x79cc4519,0x79cc4519,0x79cc4519,
    0x7a879d8a,0x7a879d8a,0x7a879d8a,0x7a879d8a, 0x7a879d8a,0x7a879d8a,0x7a879d8a,0x7a879d8a,
    0x7a879d8a,0x7a879d8a,0x7a879d8a,0x7a879d8a, 0x7a879d8a,0x7a879d8a,0x7a879d8a,0x7a879d8a,
    0x7a879d8a,0x7a879d8a,0x7a879d8a,0x7a879d8a, 0x7a879d8a,0x7a879d8a,0x7a879d8a,0x7a879d8a,
    0x7a879d8a,0x7a879d8a,0x7a879d8a,0x7a879d8a, 0x7a879d8a,0x7a879d8a,0x7a879d8a,0x7a879d8a,
    0x7a879d8a,0x7a879d8a,0x7a879d8a,0x7a879d8a, 0x7a879d8a,0x7a879d8a,0x7a879d8a,0x7a879d8a,
    0x7a879d8a,0x7a879d8a,0x7a879d8a,0x7a879d8a, 0x7a879d8a,0x7a879d8a,0x7a879d8a,0x7a879d8a
};

inline uint32_t load32(const uint8_t* p) {
    return (p[0] << 24) | (p[1] << 16) | (p[2] << 8) | p[3];
}

inline void store32(uint8_t* p, uint32_t x) {
    p[0] = (x >> 24) & 0xff; p[1] = (x >> 16) & 0xff; p[2] = (x >> 8) & 0xff; p[3] = x & 0xff;
}

void CF(const uint8_t* block, uint32_t V[8]) {
    uint32_t A = V[0], B = V[1], C = V[2], D = V[3];
    uint32_t E = V[4], F = V[5], G = V[6], H = V[7];

    uint32_t W[68], W1[64];
    for (int i = 0; i < 16; i++) W[i] = load32(block + 4 * i);
    for (int i = 16; i < 68; i++)
        W[i] = P1(W[i - 16] ^ W[i - 9] ^ ROTL(W[i - 3], 15)) ^ ROTL(W[i - 13], 7) ^ W[i - 6];
    for (int i = 0; i < 64; i++) W1[i] = W[i] ^ W[i + 4];

#define ROUND(i) { \
    uint32_t SS1=ROTL((ROTL(A,12)+E+ROTL(T[i],i))&0xffffffff,7); \
    uint32_t SS2=SS1^ROTL(A,12); \
    uint32_t TT1=(FF0(A,B,C)*(i<16)+FF1(A,B,C)*(i>=16)+D+SS2+W1[i])&0xffffffff; \
    uint32_t TT2=(GG0(E,F,G)*(i<16)+GG1(E,F,G)*(i>=16)+H+SS1+W[i])&0xffffffff; \
    D=C; C=ROTL(B,9); B=A; A=TT1; \
    H=G; G=ROTL(F,19); F=E; E=P0(TT2); \
}

#define ROUNDS4(i) ROUND(i); ROUND(i+1); ROUND(i+2); ROUND(i+3);

    ROUNDS4(0); ROUNDS4(4); ROUNDS4(8); ROUNDS4(12);
    ROUNDS4(16); ROUNDS4(20); ROUNDS4(24); ROUNDS4(28);
    ROUNDS4(32); ROUNDS4(36); ROUNDS4(40); ROUNDS4(44);
    ROUNDS4(48); ROUNDS4(52); ROUNDS4(56); ROUNDS4(60);

#undef ROUND
#undef ROUNDS4

    V[0] ^= A; V[1] ^= B; V[2] ^= C; V[3] ^= D;
    V[4] ^= E; V[5] ^= F; V[6] ^= G; V[7] ^= H;
}

void sm3(const uint8_t* msg, size_t len, uint8_t out[32]) {
    uint64_t bitlen = len * 8;
    size_t padlen = ((len + 9 + 63) & (~63)) - len;
    uint8_t* data = new uint8_t[len + padlen];
    memcpy(data, msg, len);
    data[len] = 0x80;
    memset(data + len + 1, 0, padlen - 9);
    for (int i = 0; i < 8; i++) data[len + padlen - 8 + i] = (bitlen >> (56 - 8 * i)) & 0xff;

    uint32_t V[8]; memcpy(V, IV, sizeof(V));
    for (size_t i = 0; i < len + padlen; i += 64) CF(data + i, V);
    delete[] data;

    for (int i = 0; i < 8; i++) store32(out + 4 * i, V[i]);
}

void print_hex(const uint8_t* d, int l) { for (int i = 0; i < l; i++) cout << hex << setw(2) << setfill('0') << (int)d[i]; cout << endl; }

void correctness_test() {
    cout << "[Correctness Test]" << endl;
    uint8_t hash[32];
    sm3((const uint8_t*)"abc", 3, hash);
    cout << "abc : "; print_hex(hash, 32);
    cout << "Expected : 66c7f0f462eeedd9d1f2d46bdc10e4e24167c4875cf2f7a2297da02b8f4ba8e0" << endl;
}

void speed_test(int loops = 1000000) {
    uint8_t buf[64], hash[32];
    random_device rd; for (int i = 0; i < 64; i++) buf[i] = rd();
    auto st = chrono::high_resolution_clock::now();
    for (int i = 0; i < loops; i++) sm3(buf, 64, hash);
    auto ed = chrono::high_resolution_clock::now();
    double t = chrono::duration<double>(ed - st).count();
    cout << "[Speed Test] " << loops << " times, time: " << t << " s, speed: " << (loops * 64.0 / 1024 / 1024 / t) << " MB/s" << endl;
}

int main() {
    correctness_test();
    speed_test();
    system("pause");
    return 0;
}
