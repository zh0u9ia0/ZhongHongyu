import hashlib
import random
import time

# SM2参数（同上）
p  = 0xFFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFF
a  = 0xFFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFC
b  = 0x28E9FA9E9D9F5E344D5A9E4BCF6509A7F39789F515AB8F92DDBCBD414D940E93
n  = 0xFFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFF7203DF6B21C6052B53BBF40939D54123
Gx = 0x32C4AE2C1F1981195F9904466A39C9948FE30BBFF2660BE1715A4589334C74C7
Gy = 0xBC3736A2F4F6779C59BDCEE36B692153D0A9877CC62A474002DF32E52139F0A0

class Point:
    def __init__(self, x, y):
        self.x = x
        self.y = y
    def is_infinite(self):
        return self.x is None and self.y is None
    def __eq__(self, other):
        return self.x == other.x and self.y == other.y

O = Point(None, None)

def mod_inv(x, m=p):
    if x == 0:
        raise ZeroDivisionError('division by zero')
    lm, hm = 1, 0
    low, high = x % m, m
    while low > 1:
        r = high // low
        nm, new = hm - lm * r, high - low * r
        lm, low, hm, high = nm, new, lm, low
    return lm % m

def point_add(P, Q):
    if P.is_infinite():
        return Q
    if Q.is_infinite():
        return P
    if P.x == Q.x and (P.y != Q.y or P.y == 0):
        return O

    if P == Q:
        l = (3 * P.x * P.x + a) * mod_inv(2 * P.y) % p
    else:
        l = (Q.y - P.y) * mod_inv(Q.x - P.x) % p

    x3 = (l * l - P.x - Q.x) % p
    y3 = (l * (P.x - x3) - P.y) % p
    return Point(x3, y3)

def point_mul(k, P):
    R = O
    addend = P

    while k > 0:
        if k & 1:
            R = point_add(R, addend)
        addend = point_add(addend, addend)
        k >>= 1
    return R

def generate_keypair():
    d = random.randrange(1, n)
    P = point_mul(d, Point(Gx, Gy))
    return d, P

def sm3_hash(msg):
    return hashlib.sha256(msg).digest()

def sign(message, d):
    e = int.from_bytes(sm3_hash(message), 'big')
    while True:
        k = random.randrange(1, n)
        P = point_mul(k, Point(Gx, Gy))
        r = (e + P.x) % n
        if r == 0 or r + k == n:
            continue
        s = (mod_inv(1 + d, n) * (k - r * d)) % n
        if s != 0:
            break
    return (r, s)

def verify(message, signature, P):
    r, s = signature
    if not (1 <= r <= n - 1) or not (1 <= s <= n - 1):
        return False
    e = int.from_bytes(sm3_hash(message), 'big')
    t = (r + s) % n
    if t == 0:
        return False
    x1y1 = point_add(point_mul(s, Point(Gx, Gy)), point_mul(t, P))
    R = (e + x1y1.x) % n
    return R == r

if __name__ == "__main__":
    d, P = generate_keypair()
    print("私钥 d =", hex(d))
    print("公钥 P = (", hex(P.x), ",", hex(P.y), ")")

    msg = b"Hello SM2"

    # 测试签名效率
    sign_times = []
    sign_rounds = 10
    for _ in range(sign_rounds):
        start = time.time()
        signature = sign(msg, d)
        end = time.time()
        sign_times.append(end - start)
    avg_sign_time = sum(sign_times) / sign_rounds
    print(f"签名平均耗时：{avg_sign_time*1000:.3f} ms")

    # 测试验签效率
    verify_times = []
    verify_rounds = 10
    for _ in range(verify_rounds):
        start = time.time()
        valid = verify(msg, signature, P)
        end = time.time()
        verify_times.append(end - start)
    avg_verify_time = sum(verify_times) / verify_rounds
    print(f"验签平均耗时：{avg_verify_time*1000:.3f} ms")
    print("验签结果:", valid)

