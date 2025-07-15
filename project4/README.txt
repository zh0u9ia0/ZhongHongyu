一、SM3.cpp：SM3的基本软件实现，未进行优化，主要函数如下：
	1. ROTL(x, n)
	功能：对32位整数x进行循环左移n位
	用途：SM3算法中大量使用的位运算基本操作

	2. Init_T()
	功能：初始化T_j常量表
	说明：T_j分为前16轮和后48轮两种不同的常数，是SM3压缩函数的一部分

	3. P0(x), P1(x)
	功能：SM3算法定义的非线性置换函数
	用途：
	P0用于压缩函数的状态更新
	P1用于消息扩展阶段

	4. FF(x,y,z,j), GG(x,y,z,j)
	功能：SM3的布尔函数
	说明：
	前16轮采用异或FF=GG=x^y^z
	后48轮采用三输入条件函数

	5. padding(const uint8_t *message, uint64_t message_len, uint8_t *padded, uint64_t &padded_len)
	功能：对输入消息进行SM3标准的填充，结果输出到padded数组，padded_len为填充后的长度
	说明：填充规则为“0x80 + 补0 + 原始消息长度64位”

	6. message_expand(const uint8_t *block, uint32_t *W, uint32_t *W1)
	功能：将512-bit消息块扩展成68个W[j]和64个W1[j]，供后续压缩函数使用
	说明：扩展过程中使用P1非线性函数和旋转操作增加扩散性

	7. CF(uint32_t *V, const uint8_t *block)
	功能：SM3核心压缩函数
	说明：
	- 输入当前哈希状态V和一个512-bit块
	- 执行64轮迭代，更新V
	- 使用FF、GG、P0、消息扩展等组合操作

	8. SM3(const uint8_t *message, uint64_t message_len, uint8_t *digest)
	功能：完整的SM3哈希函数
	说明：
	- 执行消息填充
	- 使用初始IV作为起始状态
	- 每64字节分块执行CF压缩函数
	- 最终结果输出到digest[32]中

	9. print_hex(const uint8_t *data, int len)
	功能：将字节数组以十六进制打印，便于调试和验证

	10. correctness_test()
	功能：使用“abc”字符串进行标准正确性测试，输出SM3计算结果和期望值对比

	11. speed_test(int loops)
	功能：对64字节随机消息进行多轮SM3计算，统计总耗时和吞吐率（MB/s）
	默认执行1,000,000次
