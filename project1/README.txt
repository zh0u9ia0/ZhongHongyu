SM4.cpp：SM4的软件实现。单独定义了循环移位函数rotl()、加解密使用的合成变换	T()、密钥扩展使用的合成变换、T_prime()、密钥扩展函数key_schedule()、加解密函数sm4_crypt()；并设计了对加解密的正确性测试，测试过程中随机生成明文和密钥，通过一次加密和对加密结果的解密进行对比来测试正确性；设计了对sm4软件实现的效率测试，通过使用同一密钥对同一明文进行大数量的加密，测量加密时间并算出一次加密的用时。
T-table.cpp：使用T-table查表优化SM4。定义了T查找表构造函数init_tbox()、并将原本的T变换函数更换成T查表函数T_lookup()。再进行效率检测，能够发现明显的效率提升。
SIMD.cpp：在T-table的基础上，使用SIMD并行化处理了SM4，显著提高效率。并行加密函数sm4_encrypt4_sse()，每轮并行处理 4 个 block；并用test_simd_correctness()函数测试了SIMD并行加密的正确性，用test_simd_performance()函数测试了并行加密的效率。
编译方式为：g++ -O3 -msse2 SIMD.cpp -o sm4_simd
未优化时每次加密一个4字块用时约0.93us，T-table优化后用时减少到0.17us，SIMD并行优化后用时0.035us。
SM4-GCM.cpp：实现了基于SM4分组密码的GCM工作模式，包含加密、解密和认证功能。sm4_gcm_encrypt()：对明文进行GCM加密，输出密文和认证标签；sm4_gcm_decrypt()：对密文进行GCM解密并验证标签，返回认证结果；ctr_crypt()：CTR计数器模式加密/解密（调用sm4_crypt）；GHASH类：实现Galois域认证乘法及认证标签计算。
编译方式为：g++ -O3 -std=c++11 SM4-GCM.cpp -o sm4_gcm