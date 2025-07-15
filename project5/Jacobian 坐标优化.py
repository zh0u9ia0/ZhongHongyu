import gmpy2
import hashlib
import random
import time
from gmpy2 import mpz, invert, powmod

# SM2 参数
p  = mpz('FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFF', 16)
a  = mpz('FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFC', 16)
b  = mpz('28E9FA9E9D9F5E344D5A9E4BCF6509A7F39789F515AB8F92DDBCBD414D940E93', 16)
n  = mpz('FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFF7203DF6B21C6052B53BBF40939D54123', 16)
Gx = mpz('32C4AE2C1F1981195F9904466A39C9948FE30BBFF2660BE1715A4589334C74C7', 16)
Gy = mpz('BC3736A2F4F6779C59BDCEE36B692153D0A9877CC62A474002DF32E52139F0A0', 16)

# Jacobian坐标点
class Point:
    def __init__(self, x, y, z=mpz(1)):
        self.x = x
        self.y = y
        self.z = z

    def is_infinite(self):
        return self.z == 0

    def to_affine(self):
        if self.is_infinite():
            return (None, None)
        z_inv = invert(self.z, p)
        z2_inv = (z_inv * z_inv) % p
        x_aff = (self.x * z2_inv) % p
        y_aff = (self.y * z2_inv * z_inv) % p
        return (x_aff, y_aff)

O = Point(mpz(0), mpz(1), mpz(0))  # 无穷远点

def point_double(P):
    if P.is_infinite() or P.y == 0:
        return O
    X1, Y1, Z1 = P.x, P.y, P.z
    S = (4 * X1 * Y1 * Y1) % p
    M = (3 * X1 * X1 + a * powmod(Z1, 4, p)) % p
    X3 = (M * M - 2 * S) % p
    Y3 = (M * (S - X3) - 8 * powmod(Y1, 4, p)) % p
    Z3 = (2 * Y1 * Z1) % p
    return Point(X3, Y3, Z3)

def point_add(P, Q):
    if P.is_infinite():
        return Q
    if Q.is_infinite():
        return P
    X1, Y1, Z1 = P.x, P.y, P.z
    X2, Y2, Z2 = Q.x, Q.y, Q.z

    Z1Z1 = powmod(Z1, 2, p)
    Z2Z2 = powmod(Z2, 2, p)
    U1 = (X1 * Z2Z2) % p
    U2 = (X2 * Z1Z1) % p
    S1 = (Y1 * Z2 * Z2Z2) % p
    S2 = (Y2 * Z1 * Z1Z1) % p

    if U1 == U2:
        if S1 != S2:
            return O
        else:
            return point_double(P)

    H = (U2 - U1) % p
    R = (S2 - S1) % p
    HH = (H * H) % p
    HHH = (H * HH) % p
    V = (U1 * HH) % p

    X3 = (R * R - HHH - 2 * V) % p
    Y3 = (R * (V - X3) - S1 * HHH) % p
    Z3 = (H * Z1 * Z2) % p
    return Point(X3, Y3, Z3)

def point_mul(k, P):
    R = O
    while k > 0:
        if k & 1:
            R = point_add(R, P)
        P = point_double(P)
        k >>= 1
    return R

def generate_keypair():
    d = gmpy2.mpz_random(gmpy2.random_state(random.SystemRandom().randint(0, 2**64)), n - 1) + 1
    P = point_mul(d, Point(Gx, Gy))
    Px, Py = P.to_affine()
    return d, (Px, Py)

def sm3_hash(msg):
    return hashlib.sha256(msg).digest()

def sign(message, d):
    e = int.from_bytes(sm3_hash(message), 'big') % n
    G = Point(Gx, Gy)
    while True:
        k = gmpy2.mpz_random(gmpy2.random_state(random.SystemRandom().randint(0, 2**64)), n - 1) + 1
        P = point_mul(k, G)
        x1, _ = P.to_affine()
        r = (e + x1) % n
        if r == 0 or r + k == n:
            continue
        s = (invert(1 + d, n) * (k - r * d)) % n
        if s != 0:
            break
    return (int(r), int(s))

def verify(message, signature, Pxy):
    r, s = signature
    if not (1 <= r <= n - 1) or not (1 <= s <= n - 1):
        return False
    e = int.from_bytes(sm3_hash(message), 'big') % n
    t = (r + s) % n
    if t == 0:
        return False
    G = Point(Gx, Gy)
    P = Point(mpz(Pxy[0]), mpz(Pxy[1]))
    Q = point_add(point_mul(s, G), point_mul(t, P))
    x1, _ = Q.to_affine()
    R = (e + x1) % n
    return int(R) == r

if __name__ == "__main__":
    d, Pxy = generate_keypair()
    print("私钥 d =", hex(d))
    print("公钥 P = (", hex(Pxy[0]), ",", hex(Pxy[1]), ")")

    msg = b"Hello SM2"

    sign_times = []
    for _ in range(10):
        t0 = time.perf_counter()
        signature = sign(msg, d)
        t1 = time.perf_counter()
        sign_times.append(t1 - t0)
    print(f"签名平均耗时：{sum(sign_times)/len(sign_times)*1000:.3f} ms")

    verify_times = []
    for _ in range(10):
        t0 = time.perf_counter()
        valid = verify(msg, signature, Pxy)
        t1 = time.perf_counter()
        verify_times.append(t1 - t0)
    print(f"验签平均耗时：{sum(verify_times)/len(verify_times)*1000:.3f} ms")
    print("验签结果:", valid)
