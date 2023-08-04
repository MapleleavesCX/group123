//RFC 6979规定了使用确定性签名算法（Deterministic Signature Algorithm，DSA）的
// 椭圆曲线密码体制（Elliptic Curve Cryptography，ECC），其中包括SM2算法。以下
// 是RFC 6979对于实现SM2的一些规定：
//
//随机数生成：RFC 6979要求在SM2签名过程中使用确定性随机数生成算法。
// 该算法基于私钥和消息的哈希值来生成一个伪随机数，以确保相同的输入
// 会产生相同的输出。
// HMAC(key, message) = SHA256((key xor opad) || SHA256((key xor ipad) || message))

//其中，ipad（inner pad）和 opad（outer pad）分别是两个固定的常量。在计算 HMAC-SHA256 时，
// 首先将密钥与 ipad 进行异或运算（补齐密钥长度），然后将结果与消息进行拼接，并使用 SHA-256 
// 对组合后的数据进行哈希运算。接着，将密钥与 opad 进行异或运算（同样进行补齐），将结果与
// 前一步的哈希结果进行拼接，并再次使用 SHA-256 进行哈希计算。最终得到的哈希结果即为 
// HMAC-SHA256 的输出，即认证码。
// 
//
//哈希函数：RFC 6979指定了SHA - 256作为SM2签名算法中的哈希函数。在签
// 名过程中，会对消息进行SHA - 256哈希运算，以得到一个固定长度的哈希
// 值。
//
//签名算法：RFC 6979规定了基于椭圆曲线的DSA签名算法。在SM2中，使用的
// 是基于elliptic curve domain parameters over Fp的DSA签名算法。该算
// 法涉及到椭圆曲线上的点运算、哈希值的处理、随机数生成等步骤。
//
//总结起来，RFC 6979规定了SM2签名算法中使用的随机数生成方法和哈希函数，
//并提供了基于椭圆曲线的DSA签名算法作为参考。实现SM2时需要遵循这些规定，
// 以确保算法的正确性和安全性。同时，建议参考RFC 6979完整的规范文档，
// 细致了解其中的细节和要求。

#include"sm2.h"

int main() {
	string m = "hello!Nice to see you!__elliptic curve domain parameters over Fphello!Nice to see you!__elliptic curve domain parameters over Fp";
	cout << "明文：" << m << "\n明文长度（字符数）：" << m.size() << endl;
	string sk;
	vector<string> pk;
	vector<string> sign;
	vector<string> c123;

	cout << "生成密钥\n";
	timing(rfc6979_sm2_getKey,sk,pk);

	cout << "尝试签名测试：\n";
	timing(rfc6979_sm2_sign,sign, m, sk);
	cout << "输出sm2对m的签名：(r,s)=(" << sign[0] << ", " << sign[1] << ")\n";

	cout << "验证签名：";
	auto start = chrono::system_clock::now();
	bool test = rfc6979_sm2_verify(m, sign, pk);
	auto end = chrono::system_clock::now();
	auto duration = chrono::duration_cast<chrono::microseconds>(end - start);
	cout << "执行时间：" << duration.count() << " 微秒" << endl;
	if (test) {
		cout << "验签通过！\n";
	}
	else {
		cout << "验签不通过！\n";
	}

	cout << "\n尝试加解密测试：\n";
	timing(sm2_enc,c123, m, pk);
	cout << "输出sm2加密后密文：(c1,c2,c3)=(" << c123[0] << ", " << c123[1] << ", " << c123[2] << ")\n";

	string M;
	timing(sm2_dec,M, sk, c123);
	cout << "输出sm2解密后明文：M = " << M << endl;
}