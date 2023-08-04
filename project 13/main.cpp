
#define ECMH

#include"sm2.h"
#include"ECMH.h"

#ifdef ECMH

int main() {
    // 输入集合
    vector<string> elements = { "111","222"};

    // 计算ECMH哈希值
    string hash = calculateECMH(elements, NID_sm2);
    if (!hash.empty()) {
        cout << "NID_sm2  ECMH Hash: " << hash << endl;
    }
    else
        cout << "空-错误！\n";
    printf("over\n\n");

    // 测试集合元素顺序置换
    vector<string> elements1 = { "222", "111" };

    printf("验证：hash({a,b}) == hash({b,a}) ? ...");
    string hash1 = calculateECMH(elements1, NID_sm2);
    if (hash1 == hash) {
        cout << "yes!\n";
        cout << "顺序置换后 ECMH Hash: " << hash1 << endl;
    }
    else
        cout << "no!\n";
    printf("over\n\n");

    // 测试空集
    vector<string> elements2 = {};

    printf("验证：hash({}) == ''(空字符串） ? ...");
    string hash2 = calculateECMH(elements2, NID_sm2);
    if (hash2 == "") {
        cout << "yes!\n";
    }
    else
        cout << "no!\n";
    printf("over\n\n");

    // 测试更换不同椭圆曲线输出结果
    string a = calculateECMH(elements, NID_secp256k1);
    if (!a.empty()) {
        cout << "NID_secp256k1 \t\t ECMH Hash: " << a << endl;
    }
    else
        cout << "空-错误！\n";
    printf("over\n\n");

    string b = calculateECMH(elements, NID_X9_62_prime256v1);
    if (!b.empty()) {
        cout << "NID_X9_62_prime256v1 \t ECMH Hash: " << b << endl;
    }
    else
        cout << "空-错误！\n";
    printf("over\n\n");


    //测试大集合的执行时间
    //1.100个任意元素
    vector<string> E;
    for (int i = 0; i < 100; i++) {
        E.push_back(rand256());
    }
    cout << "100个元素输入ECMH：\n";
    string hashout = timing(calculateECMH, E, NID_sm2);
    cout << "结果：" << hashout << endl;

    //1.1000个任意元素
    vector<string> E2;
    for (int i = 0; i < 1000; i++) {
        E2.push_back(rand256());
    }
    cout << "1000个元素输入ECMH：\n";
    string hashout2 = timing(calculateECMH, E2, NID_sm2);
    cout << "结果：" << hashout2 << endl;

    //1.10000个任意元素
    vector<string> E3;
    for (int i = 0; i < 10000; i++) {
        E3.push_back(rand256());
    }
    cout << "10000个元素输入ECMH：\n";
    string hashout3 = timing(calculateECMH, E3, NID_sm2);
    cout << "结果：" << hashout3 << endl;


    return 0;
}




























#endif


















