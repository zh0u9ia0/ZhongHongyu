import hashlib
import os
import random

# --- 1. 加密原语 ---

class ECGroup:
    """模拟椭圆曲线群 G，提供哈希、幂运算和随机指数功能。"""
    def __init__(self, curve_name="prime256v1"):
        self.order = 115792089237316195423570985008687907853269984665640564039457584007913129639937

    def gen_exp(self):
        """生成群G中的随机私有指数。"""
        return random.randint(1, self.order - 1)

    def h_to_g(self, ident):
        """将标识符哈希并映射为群G的元素。"""
        h = hashlib.sha256(ident.encode()).hexdigest()
        return int(h, 16) % self.order

    def exp(self, base, e):
        """执行群G中的幂运算。"""
        return pow(base, e, self.order)

class AHE:
    """模拟加法同态加密方案。"""
    def gen_keys(self, lamb=1024):
        """生成加法同态加密的公钥和私钥。"""
        return "pk_ph", "sk_ph"

    def enc(self, pk, val):
        """使用公钥pk加密值。"""
        return f"enc({val})"

    def dec(self, sk, c_text):
        """使用私钥sk解密密文。"""
        if isinstance(c_text, str) and c_text.startswith("enc("):
            return int(c_text.split('(')[1][:-1])
        return 0

    def add_hom(self, c_texts):
        """对多个密文进行同态求和。"""
        total = 0
        for ct in c_texts:
            if isinstance(ct, str) and ct.startswith("enc("):
                total += int(ct.split('(')[1][:-1])
        return f"enc({total})"

    def rand_c(self, pk, c_text):
        """随机化密文以增强隐私性。"""
        return c_text

# --- 2. 协议实现 ---

class DDHPIS:
    """DDH基私有交集和协议的实现。"""
    def __init__(self):
        self.group = ECGroup()
        self.ahe = AHE()

    def p1_round1(self, V, p2_pk):
        """P1的第一轮计算，生成H(v_i)^k1列表。"""
        k1 = self.group.gen_exp()
        Hvk1_list = []
        for v_i in V:
            Hv = self.group.h_to_g(str(v_i))
            Hvk1 = self.group.exp(Hv, k1)
            Hvk1_list.append(Hvk1)
        random.shuffle(Hvk1_list)
        return k1, Hvk1_list

    def p2_round2(self, W, Hvk1_from_p1):
        """P2的第二轮计算，生成Z列表和(H(w_j)^k2, AEnc(t_j))对列表。"""
        k2 = self.group.gen_exp()
        pk, sk = self.ahe.gen_keys()

        Hvk1k2_list = []
        for Hvk1 in Hvk1_from_p1:
            Hvk1k2 = self.group.exp(Hvk1, k2)
            Hvk1k2_list.append(Hvk1k2)
        random.shuffle(Hvk1k2_list)
        Z = Hvk1k2_list

        Hwk2_AEnc_tj_list = []
        for w_j, t_j in W:
            Hwj = self.group.h_to_g(str(w_j))
            Hwk2 = self.group.exp(Hwj, k2)
            AEnc_tj = self.ahe.enc(pk, t_j)
            Hwk2_AEnc_tj_list.append((Hwk2, AEnc_tj))
        random.shuffle(Hwk2_AEnc_tj_list)
        return k2, pk, sk, Z, Hwk2_AEnc_tj_list

    def p1_round3(self, k1, Z_from_p2, p2_pairs_from_p2, p2_pk):
        """P1的第三轮计算，找到交集并同态求和，然后随机化密文。"""
        Hwk1k2_AEnc_tj_list = []
        for Hwj_k2, AEnc_tj in p2_pairs_from_p2:
            Hwk1k2 = self.group.exp(Hwj_k2, k1)
            Hwk1k2_AEnc_tj_list.append((Hwk1k2, AEnc_tj))

        int_c_texts = []
        for Hwk1k2, AEnc_tj in Hwk1k2_AEnc_tj_list:
            if Hwk1k2 in Z_from_p2:
                int_c_texts.append(AEnc_tj)

        if int_c_texts:
            Enc_SJ = self.ahe.add_hom(int_c_texts)
            Enc_SJ_rand = self.ahe.rand_c(p2_pk, Enc_SJ)
            return Enc_SJ_rand
        return None

    def p2_output(self, sk, Enc_SJ_rand):
        """P2接收最终密文并解密。"""
        if Enc_SJ_rand:
            SJ = self.ahe.dec(sk, Enc_SJ_rand)
            return SJ
        return None

# --- 3. 运行示例 (测试) ---

if __name__ == "__main__":
    proto = DDHPIS()

    # 1. 定义输入集合
    P1_V = ["alice@example.com", "bob@example.com", "charlie@example.com", "david@example.com"]
    P2_W = [
        ("bob@example.com", 100),
        ("charlie@example.com", 200),
        ("eve@example.com", 300),
        ("frank@example.com", 400)
    ]

    print("--- 协议测试开始 ---")

    # 2. P2 生成 AHE 密钥对
    p2_pk_initial, p2_sk_initial = proto.ahe.gen_keys()
    # 3. P1 执行 Round 1
    p1_k1, Hvk1_to_p2 = proto.p1_round1(P1_V, p2_pk_initial)
    print(f"P1 计算并发送 H(v_i)^k1 列表给 P2。")

    # 4. P2 执行 Round 2
    p2_k2, p2_pk_final, p2_sk_final, Z_to_p1, P2_pairs_to_p1 = proto.p2_round2(P2_W, Hvk1_to_p2)
    print(f"P2 计算并发送 H(v_i)^k1K2 列表和 (H(w_j)^k2, AEnc(t_j)) 对列表给 P1。")

    # 5. P1 执行 Round 3
    Enc_SJ_rand_to_p2 = proto.p1_round3(p1_k1, Z_to_p1, P2_pairs_to_p1, p2_pk_final)
    if Enc_SJ_rand_to_p2:
        print(f"P1 计算交集并同态求和，发送随机化密文给 P2")
    else:
        print("P1 计算后没有交集元素，未发送最终密文。")

    # 6. P2 获取最终结果
    final_sum_result = proto.p2_output(p2_sk_final, Enc_SJ_rand_to_p2)

    print("\n--- 协议测试结果 ---")
    if final_sum_result is not None:
        print(f"P2 成功解密得到交集和 S_J: {final_sum_result}")
    else:
        print("协议未计算出交集和 (可能无交集)。")

    print("\n--- 验证结果 ---")
    actual_int_elems = []
    actual_sum = 0
    p2_w_dict = {item[0]: item[1] for item in P2_W}

    for v_i in P1_V:
        if v_i in p2_w_dict:
            actual_int_elems.append(v_i)
            actual_sum += p2_w_dict[v_i]

    print(f"P1 的集合: {P1_V}")
    print(f"P2 的集合: {P2_W}")
    print(f"实际交集元素: {actual_int_elems}")
    print(f"实际交集和: {actual_sum}")

    if final_sum_result == actual_sum:
        print("协议计算结果与实际结果匹配。测试通过！")
    else:
        print("协议计算结果与实际结果不匹配。测试失败！")