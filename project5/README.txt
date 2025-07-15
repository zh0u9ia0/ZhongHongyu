一、SM2.py：实现了SM2算法的基础版本，未进行优化
	1. mod_inv(x, m)：计算整数x模m的逆元（满足x * x^{-1} ≡ 1 mod m）。
	2. point_add(P, Q)：计算椭圆曲线群上两点P和Q的加法。
	3. point_mul(k, P)：计算点P的标量乘法k*P。
	4. generate_keypair()：随机生成私钥d，并计算公钥P = d*G，其中G是曲线基点。
	5. sm3_hash(msg)：对消息msg计算哈希值。
	6. calculate_Z(ID, Px, Py)：计算用户身份相关的ZA值。
	7. sign(msg, d, ID, Pxy)：计算消息摘要e=SM3(ZA||msg)，并结合随机数k计算签名(r, s)。
	8. verify(msg, signature, ID, Pxy)：通过计算e和点运算验证签名r是否符合SM2验签公式。

二、Jacobian 坐标优化.py：进行了两项优化：使用 gmpy2 替换 Python 内置 int 和模逆运算，提升大数运算效率；引入 Jacobian 坐标优化椭圆曲线加法和倍点运算，消除模逆开销，显著提升签名和验签速度。

未优化时签名耗时12ms，验签耗时23ms，本次优化后签名耗时1.3ms，验签用时1.8ms