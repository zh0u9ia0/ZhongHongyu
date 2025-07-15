
图片水印嵌入与提取（基于 DCT）
===================================

基于离散余弦变换（DCT）的图像水印嵌入与提取算法，并提供鲁棒性测试（翻转、裁剪、对比度调整、旋转）。

目录结构
--------
- embed_watermark.py       # 嵌入水印主程序
- extract_watermark.py     # 提取水印主程序
- robustness_test.py       # 各类图像扰动测试
- utils.py                 # DCT 变换工具函数
- results/                 # 存放结果图像

运行方式
--------
1. 调用 embed_watermark.py 嵌入水印：
   - 输入图像为灰度图（如 lena.png）
   - 水印图像为二值图（如 watermark.png）
   - 嵌入后输出结果在 results/watermarked.png

2. 调用 extract_watermark.py 提取水印：
   - 提取结果保存在 results/ 中

3. 调用 robustness_test.py 模拟攻击后进行水印提取测试。

依赖库
------
- numpy
- opencv-python
- scipy

安装方式：
```bash
pip install numpy opencv-python scipy
```
