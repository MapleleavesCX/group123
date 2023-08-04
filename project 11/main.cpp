//RFC 6979�涨��ʹ��ȷ����ǩ���㷨��Deterministic Signature Algorithm��DSA����
// ��Բ�����������ƣ�Elliptic Curve Cryptography��ECC�������а���SM2�㷨������
// ��RFC 6979����ʵ��SM2��һЩ�涨��
//
//��������ɣ�RFC 6979Ҫ����SM2ǩ��������ʹ��ȷ��������������㷨��
// ���㷨����˽Կ����Ϣ�Ĺ�ϣֵ������һ��α���������ȷ����ͬ������
// �������ͬ�������
// HMAC(key, message) = SHA256((key xor opad) || SHA256((key xor ipad) || message))

//���У�ipad��inner pad���� opad��outer pad���ֱ��������̶��ĳ������ڼ��� HMAC-SHA256 ʱ��
// ���Ƚ���Կ�� ipad ����������㣨������Կ���ȣ���Ȼ�󽫽������Ϣ����ƴ�ӣ���ʹ�� SHA-256 
// ����Ϻ�����ݽ��й�ϣ���㡣���ţ�����Կ�� opad ����������㣨ͬ�����в��룩���������
// ǰһ���Ĺ�ϣ�������ƴ�ӣ����ٴ�ʹ�� SHA-256 ���й�ϣ���㡣���յõ��Ĺ�ϣ�����Ϊ 
// HMAC-SHA256 �����������֤�롣
// 
//
//��ϣ������RFC 6979ָ����SHA - 256��ΪSM2ǩ���㷨�еĹ�ϣ��������ǩ
// �������У������Ϣ����SHA - 256��ϣ���㣬�Եõ�һ���̶����ȵĹ�ϣ
// ֵ��
//
//ǩ���㷨��RFC 6979�涨�˻�����Բ���ߵ�DSAǩ���㷨����SM2�У�ʹ�õ�
// �ǻ���elliptic curve domain parameters over Fp��DSAǩ���㷨������
// ���漰����Բ�����ϵĵ����㡢��ϣֵ�Ĵ�����������ɵȲ��衣
//
//�ܽ�������RFC 6979�涨��SM2ǩ���㷨��ʹ�õ���������ɷ����͹�ϣ������
//���ṩ�˻�����Բ���ߵ�DSAǩ���㷨��Ϊ�ο���ʵ��SM2ʱ��Ҫ��ѭ��Щ�涨��
// ��ȷ���㷨����ȷ�ԺͰ�ȫ�ԡ�ͬʱ������ο�RFC 6979�����Ĺ淶�ĵ���
// ϸ���˽����е�ϸ�ں�Ҫ��

#include"sm2.h"

int main() {
	string m = "hello!Nice to see you!__elliptic curve domain parameters over Fphello!Nice to see you!__elliptic curve domain parameters over Fp";
	cout << "���ģ�" << m << "\n���ĳ��ȣ��ַ�������" << m.size() << endl;
	string sk;
	vector<string> pk;
	vector<string> sign;
	vector<string> c123;

	cout << "������Կ\n";
	timing(rfc6979_sm2_getKey,sk,pk);

	cout << "����ǩ�����ԣ�\n";
	timing(rfc6979_sm2_sign,sign, m, sk);
	cout << "���sm2��m��ǩ����(r,s)=(" << sign[0] << ", " << sign[1] << ")\n";

	cout << "��֤ǩ����";
	auto start = chrono::system_clock::now();
	bool test = rfc6979_sm2_verify(m, sign, pk);
	auto end = chrono::system_clock::now();
	auto duration = chrono::duration_cast<chrono::microseconds>(end - start);
	cout << "ִ��ʱ�䣺" << duration.count() << " ΢��" << endl;
	if (test) {
		cout << "��ǩͨ����\n";
	}
	else {
		cout << "��ǩ��ͨ����\n";
	}

	cout << "\n���Լӽ��ܲ��ԣ�\n";
	timing(sm2_enc,c123, m, pk);
	cout << "���sm2���ܺ����ģ�(c1,c2,c3)=(" << c123[0] << ", " << c123[1] << ", " << c123[2] << ")\n";

	string M;
	timing(sm2_dec,M, sk, c123);
	cout << "���sm2���ܺ����ģ�M = " << M << endl;
}