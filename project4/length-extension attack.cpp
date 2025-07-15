#include <iostream>
#include <iomanip>
#include <cstring>
#include <vector>
#include <cassert>
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
    uint32_t W[68], W1[64];
    for (int i = 0; i < 16; i++) W[i] = load32(block + 4 * i);
    for (int i = 16; i < 68; i++)
        W[i] = P1(W[i - 16] ^ W[i - 9] ^ ROTL(W[i - 3], 15)) ^ ROTL(W[i - 13], 7) ^ W[i - 6];
    for (int i = 0; i < 64; i++) W1[i] = W[i] ^ W[i + 4];

    uint32_t A = V[0], B = V[1], C = V[2], D = V[3];
    uint32_t E = V[4], F = V[5], G = V[6], H = V[7];

    for (int j = 0; j < 64; j++) {
        uint32_t SS1 = ROTL((ROTL(A, 12) + E + ROTL(T[j], j)) & 0xffffffff, 7);
        uint32_t SS2 = SS1 ^ ROTL(A, 12);
        uint32_t TT1 = ((j < 16 ? FF0(A, B, C) : FF1(A, B, C)) + D + SS2 + W1[j]) & 0xffffffff;
        uint32_t TT2 = ((j < 16 ? GG0(E, F, G) : GG1(E, F, G)) + H + SS1 + W[j]) & 0xffffffff;
        D = C; C = ROTL(B, 9); B = A; A = TT1;
        H = G; G = ROTL(F, 19); F = E; E = P0(TT2);
    }

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

    uint32_t V[8];
    memcpy(V, IV, sizeof(V));
    for (size_t i = 0; i < len + padlen; i += 64) CF(data + i, V);
    delete[] data;

    for (int i = 0; i < 8; i++) store32(out + 4 * i, V[i]);
}

// === 计算SM3填充，返回填充字节数（不包括消息） ===
// 注意填充后消息总长度（消息+填充）必须是64字节倍数
size_t sm3_padding_len(size_t msg_len) {
    size_t bit_len = msg_len * 8;
    size_t k = (448 - (bit_len + 1) % 512) % 512;
    return (k + 1 + 64) / 8;
}

// 构造填充字节，返回填充内容
vector<uint8_t> sm3_padding(size_t msg_len) {
    size_t pad_len = sm3_padding_len(msg_len);
    vector<uint8_t> padding(pad_len, 0);
    padding[0] = 0x80;
    uint64_t bit_len = msg_len * 8;
    for (int i = 0; i < 8; i++) {
        padding[pad_len - 8 + i] = (bit_len >> (56 - 8 * i)) & 0xFF;
    }
    return padding;
}

// 从哈希值恢复内部状态
void hash_to_state(const uint8_t hash[32], uint32_t V[8]) {
    for (int i = 0; i < 8; i++) {
        V[i] = (hash[4 * i] << 24) | (hash[4 * i + 1] << 16) | (hash[4 * i + 2] << 8) | hash[4 * i + 3];
    }
}

void print_hex(const uint8_t* d, int l) {
    for (int i = 0; i < l; i++) cout << hex << setw(2) << setfill('0') << (int)d[i];
    cout << dec << endl;
}

int main() {
    const char* M = "attack at dawn";
    size_t M_len = strlen(M);

    uint8_t H_original[32];
    sm3((const uint8_t*)M, M_len, H_original);
    cout << "Original message hash: ";
    print_hex(H_original, 32);

    // 追加消息
    const char* extension = " and dusk";
    size_t ext_len = strlen(extension);

    // 先构造原消息填充
    vector<uint8_t> M_padding = sm3_padding(M_len);

    // 构造完整消息 M||padding||extension 用于直接计算验证
    vector<uint8_t> forged_msg;
    forged_msg.insert(forged_msg.end(), M, M + M_len);
    forged_msg.insert(forged_msg.end(), M_padding.begin(), M_padding.end());
    forged_msg.insert(forged_msg.end(), extension, extension + ext_len);

    uint8_t H_forged_check[32];
    sm3(forged_msg.data(), forged_msg.size(), H_forged_check);
    cout << "Direct hash of M||padding||extension: ";
    print_hex(H_forged_check, 32);

    // 长度扩展攻击：先恢复状态
    uint32_t V[8];
    hash_to_state(H_original, V);

    // 总长度是原消息+填充，必须是64字节倍数
    size_t total_len = M_len + M_padding.size();

    // 对扩展消息加填充
    vector<uint8_t> ext_data(extension, extension + ext_len);
    vector<uint8_t> ext_padding = sm3_padding(total_len + ext_len);
    ext_data.insert(ext_data.end(), ext_padding.begin(), ext_padding.end());

    // 用 CF 继续压缩扩展消息，基于恢复的状态V
    for (size_t i = 0; i < ext_data.size(); i += 64) {
        CF(ext_data.data() + i, V);
    }

    uint8_t H_length_extension[32];
    for (int i = 0; i < 8; i++) store32(H_length_extension + 4 * i, V[i]);

    cout << "Length-extension attack hash: ";
    print_hex(H_length_extension, 32);

    // 验证两值是否一致
    assert(memcmp(H_forged_check, H_length_extension, 32) == 0);
    cout << "Length-extension attack verified: hashes match!" << endl;

    return 0;
}
