#include <iostream>
#include <vector>
#include <random>
#include <iomanip>
#include <cassert>
#include <cstring>
#include <algorithm>

using namespace std;

// ----------------------------- SM3 基础实现 -----------------------------
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

void store32(uint8_t* p, uint32_t x) {
    p[0] = (x >> 24) & 0xff; p[1] = (x >> 16) & 0xff; p[2] = (x >> 8) & 0xff; p[3] = x & 0xff;
}

uint32_t load32(const uint8_t* p) {
    return (p[0] << 24) | (p[1] << 16) | (p[2] << 8) | p[3];
}

void CF(const uint8_t* block, uint32_t V[8]) {
    uint32_t W[68], W1[64];
    for (int i = 0; i < 16; i++) W[i] = load32(block + 4 * i);
    for (int i = 16; i < 68; i++)
        W[i] = P1(W[i - 16] ^ W[i - 9] ^ ROTL(W[i - 3], 15)) ^ ROTL(W[i - 13], 7) ^ W[i - 6];
    for (int i = 0; i < 64; i++) W1[i] = W[i] ^ W[i + 4];

    uint32_t A = V[0], B = V[1], C = V[2], D = V[3], E = V[4], F = V[5], G = V[6], H = V[7];
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
    vector<uint8_t> buf(len + padlen);
    memcpy(buf.data(), msg, len);
    buf[len] = 0x80;
    for (int i = 0; i < 8; i++)
        buf[buf.size() - 8 + i] = (bitlen >> (56 - i * 8)) & 0xff;

    uint32_t V[8];
    memcpy(V, IV, sizeof(V));
    for (size_t i = 0; i < buf.size(); i += 64)
        CF(buf.data() + i, V);
    for (int i = 0; i < 8; i++) store32(out + 4 * i, V[i]);
}

vector<uint8_t> sm3_hash(const vector<uint8_t>& data) {
    uint8_t out[32];
    sm3(data.data(), data.size(), out);
    return vector<uint8_t>(out, out + 32);
}

// ------------------------ RFC6962 Merkle 树实现 ------------------------

vector<uint8_t> LeafHash(const vector<uint8_t>& data) {
    vector<uint8_t> prefix_data = { 0x00 };
    prefix_data.insert(prefix_data.end(), data.begin(), data.end());
    return sm3_hash(prefix_data);
}

vector<uint8_t> NodeHash(const vector<uint8_t>& left, const vector<uint8_t>& right) {
    vector<uint8_t> prefix_data = { 0x01 };
    prefix_data.insert(prefix_data.end(), left.begin(), left.end());
    prefix_data.insert(prefix_data.end(), right.begin(), right.end());
    return sm3_hash(prefix_data);
}

vector<vector<uint8_t>> build_merkle_tree(vector<vector<uint8_t>> leaves) {
    vector<vector<uint8_t>> current = leaves;
    while (current.size() > 1) {
        vector<vector<uint8_t>> next;
        for (size_t i = 0; i < current.size(); i += 2) {
            if (i + 1 < current.size())
                next.push_back(NodeHash(current[i], current[i + 1]));
            else
                next.push_back(current[i]);  // 奇数节点向上提
        }
        current = next;
    }
    return current;
}

vector<vector<uint8_t>> generate_proof(const vector<vector<uint8_t>>& leaf_hashes, int index) {
    vector<vector<uint8_t>> proof;
    vector<vector<uint8_t>> current = leaf_hashes;
    while (current.size() > 1) {
        int sibling = index ^ 1;
        if (sibling < current.size())
            proof.push_back(current[sibling]);
        index /= 2;
        vector<vector<uint8_t>> next;
        for (size_t i = 0; i < current.size(); i += 2) {
            if (i + 1 < current.size())
                next.push_back(NodeHash(current[i], current[i + 1]));
            else
                next.push_back(current[i]);
        }
        current = next;
    }
    return proof;
}

bool verify_proof(const vector<uint8_t>& leaf, const vector<vector<uint8_t>>& proof, int index, const vector<uint8_t>& root) {
    vector<uint8_t> hash = LeafHash(leaf);
    for (const auto& sibling : proof) {
        if (index % 2 == 0)
            hash = NodeHash(hash, sibling);
        else
            hash = NodeHash(sibling, hash);
        index /= 2;
    }
    return hash == root;
}

// ------------------------ 不存在性证明支持 ------------------------

// 查找邻近左右叶子索引，返回 pair<左索引, 右索引>，无则为 -1
pair<int, int> find_neighbor_indices(const vector<vector<uint8_t>>& sorted_leaves, const vector<uint8_t>& target) {
    int n = (int)sorted_leaves.size();
    auto cmp = [](const vector<uint8_t>& a, const vector<uint8_t>& b) { return a < b; };
    auto it = lower_bound(sorted_leaves.begin(), sorted_leaves.end(), target, cmp);
    int right = (it == sorted_leaves.end()) ? -1 : int(distance(sorted_leaves.begin(), it));
    int left = (it == sorted_leaves.begin()) ? -1 : (right - 1);
    return { left, right };
}

// 验证不存在性证明，判断target在左叶子和右叶子之间，且左右存在性证明有效
bool verify_non_inclusion(const vector<uint8_t>& target,
    const vector<vector<uint8_t>>& sorted_leaves,
    const vector<vector<uint8_t>>& proof_left, int left_idx,
    const vector<vector<uint8_t>>& proof_right, int right_idx,
    const vector<uint8_t>& root) {
    bool left_valid = (left_idx == -1) || verify_proof(sorted_leaves[left_idx], proof_left, left_idx, root);
    bool right_valid = (right_idx == -1) || verify_proof(sorted_leaves[right_idx], proof_right, right_idx, root);
    bool between = true;
    if (left_idx != -1 && !(sorted_leaves[left_idx] < target)) between = false;
    if (right_idx != -1 && !(target < sorted_leaves[right_idx])) between = false;
    return left_valid && right_valid && between;
}

void print_hex(const vector<uint8_t>& data) {
    for (uint8_t b : data)
        cout << hex << setw(2) << setfill('0') << (int)b;
    cout << dec << endl;
}

// ---------------------------- 主函数 ----------------------------
int main() {
    const int N = 100000;
    vector<vector<uint8_t>> leaves;
    mt19937 rng(12345);

    cout << "开始生成 " << N << " 个随机叶子数据..." << endl;
    for (int i = 0; i < N; i++) {
        vector<uint8_t> d(32);
        for (int j = 0; j < 32; j++) d[j] = rng() % 256;
        leaves.push_back(d);
    }
    cout << "随机叶子数据生成完毕，开始排序..." << endl;
    sort(leaves.begin(), leaves.end());

    cout << "计算叶子节点的哈希值..." << endl;
    vector<vector<uint8_t>> leaf_hashes;
    for (const auto& d : leaves) leaf_hashes.push_back(LeafHash(d));
    cout << "构造 Merkle 树..." << endl;
    vector<uint8_t> root = build_merkle_tree(leaf_hashes)[0];

    cout << "Merkle 树根哈希值：";
    print_hex(root);

    // 存在性证明测试
    int test_index = rng() % N;
    cout << "测试存在性证明，索引为：" << test_index << endl;
    auto proof = generate_proof(leaf_hashes, test_index);
    bool ok = verify_proof(leaves[test_index], proof, test_index, root);
    cout << "存在性证明验证：" << (ok ? "成功" : "失败") << endl;

    // 不存在性证明测试
    cout << "测试不存在性证明..." << endl;
    vector<uint8_t> target(32);
    for (int j = 0; j < 32; j++) target[j] = rng() % 256;
    cout << "随机生成测试目标数据（不一定存在）：";
    print_hex(target);

    auto neighbors = find_neighbor_indices(leaves, target);
    int left_idx = neighbors.first;
    int right_idx = neighbors.second;

    cout << "目标左右邻近叶子索引：" << left_idx << "，" << right_idx << endl;
    if (left_idx != -1) {
        cout << "左邻叶子哈希：";
        print_hex(leaf_hashes[left_idx]);
    }
    if (right_idx != -1) {
        cout << "右邻叶子哈希：";
        print_hex(leaf_hashes[right_idx]);
    }

    auto proof_left = (left_idx == -1) ? vector<vector<uint8_t>>() : generate_proof(leaf_hashes, left_idx);
    auto proof_right = (right_idx == -1) ? vector<vector<uint8_t>>() : generate_proof(leaf_hashes, right_idx);

    bool non_inc_ok = verify_non_inclusion(target, leaves, proof_left, left_idx, proof_right, right_idx, root);
    cout << "不存在性证明验证：" << (non_inc_ok ? "成功" : "失败") << endl;

    system("pause");
    return 0;
}
