
#define ECMH

#include"sm2.h"
#include"ECMH.h"

#ifdef ECMH

int main() {
    // ���뼯��
    vector<string> elements = { "111","222"};

    // ����ECMH��ϣֵ
    string hash = calculateECMH(elements, NID_sm2);
    if (!hash.empty()) {
        cout << "NID_sm2  ECMH Hash: " << hash << endl;
    }
    else
        cout << "��-����\n";
    printf("over\n\n");

    // ���Լ���Ԫ��˳���û�
    vector<string> elements1 = { "222", "111" };

    printf("��֤��hash({a,b}) == hash({b,a}) ? ...");
    string hash1 = calculateECMH(elements1, NID_sm2);
    if (hash1 == hash) {
        cout << "yes!\n";
        cout << "˳���û��� ECMH Hash: " << hash1 << endl;
    }
    else
        cout << "no!\n";
    printf("over\n\n");

    // ���Կռ�
    vector<string> elements2 = {};

    printf("��֤��hash({}) == ''(���ַ����� ? ...");
    string hash2 = calculateECMH(elements2, NID_sm2);
    if (hash2 == "") {
        cout << "yes!\n";
    }
    else
        cout << "no!\n";
    printf("over\n\n");

    // ���Ը�����ͬ��Բ����������
    string a = calculateECMH(elements, NID_secp256k1);
    if (!a.empty()) {
        cout << "NID_secp256k1 \t\t ECMH Hash: " << a << endl;
    }
    else
        cout << "��-����\n";
    printf("over\n\n");

    string b = calculateECMH(elements, NID_X9_62_prime256v1);
    if (!b.empty()) {
        cout << "NID_X9_62_prime256v1 \t ECMH Hash: " << b << endl;
    }
    else
        cout << "��-����\n";
    printf("over\n\n");


    //���Դ󼯺ϵ�ִ��ʱ��
    //1.100������Ԫ��
    vector<string> E;
    for (int i = 0; i < 100; i++) {
        E.push_back(rand256());
    }
    cout << "100��Ԫ������ECMH��\n";
    string hashout = timing(calculateECMH, E, NID_sm2);
    cout << "�����" << hashout << endl;

    //1.1000������Ԫ��
    vector<string> E2;
    for (int i = 0; i < 1000; i++) {
        E2.push_back(rand256());
    }
    cout << "1000��Ԫ������ECMH��\n";
    string hashout2 = timing(calculateECMH, E2, NID_sm2);
    cout << "�����" << hashout2 << endl;

    //1.10000������Ԫ��
    vector<string> E3;
    for (int i = 0; i < 10000; i++) {
        E3.push_back(rand256());
    }
    cout << "10000��Ԫ������ECMH��\n";
    string hashout3 = timing(calculateECMH, E3, NID_sm2);
    cout << "�����" << hashout3 << endl;


    return 0;
}




























#endif


















