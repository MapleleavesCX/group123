#include"sm2.h"


//选择哪一项就取消注释，同时把其他几项注释掉 <<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
#define Leaking_k 
//#define Reusing_k 
//#define Reusing_k_by_different_users
//#define Same_d_and_k_with_ECDSA

void sm2_sign_k(vector<string>& sign, string& message, string& sk, string& k_str);

#ifdef Leaking_k

int main() {

    BN_CTX* ctx = BN_CTX_new();

    //初始化——确定选择sm2椭圆曲线
    EC_GROUP* group = EC_GROUP_new_by_curve_name(NID_sm2);

    //获取椭圆曲线的阶 n
    BIGNUM* n = BN_new();
    EC_GROUP_get_order(group, n, ctx);

    BIGNUM* one = BN_new();
    BN_set_word(one, 1);

	printf("*sm2 leaking k:\n");

	printf("*用户A生成密钥：\n");
	string d_of_A;
	vector<string> P_of_A;
	rfc6979_sm2_getKey(d_of_A, P_of_A);

	cout << "A的私钥 d：" << d_of_A << endl;
	cout << "A的公钥 P：(" << P_of_A[0] << " ," << P_of_A[1] << ")\n";

	printf("*结束\n\n");

	printf("*A开始签名：\n");
	string M = "hello!My name is Alice!";// 待签名明文，可以任意更改
	vector<string> sign;

    string test = "123456789";
    string k_str = hmac_prbg(d_of_A, test, one, n);//k = [1, n)
    cout << "*陷阱条件：\n  签名过程中, 随机数 k 泄露：" << k_str << endl;

    sm2_sign_k(sign, M, d_of_A, k_str);

    cout << "待签名明文：" << M << endl;
    cout << "输出签名:\n  r: " << sign[0] << "\n  s: " << sign[1] << endl;
    
    printf("*结束\n\n");

    printf("*敌手利用签名(r,s)和k攻击破解A的私钥d:\n");
    printf("* 破解算法：d = inv(s + r) * (k - s) mod n\n");
    // 因为 s = ((inv(1 + d) * (k - r * d)) mod n
    //  则 s * (1 + d) = (k - r * d) mod n
    // 得出 d = inv(s + r) * (k - s) mod n

    BIGNUM* r = BN_new();
    BIGNUM* s = BN_new();
    BIGNUM* k = BN_new();
    BN_hex2bn(&r, sign[0].c_str());
    BN_hex2bn(&s, sign[1].c_str());
    BN_hex2bn(&k, k_str.c_str());

    BIGNUM* SK = BN_new();
    BIGNUM* s_add_r = BN_new();
    BIGNUM* k_sub_s = BN_new();
    BIGNUM* inv_of_s_add_r = BN_new();

    // 计算 d = inv(s + r) * (k - s) mod n
    BN_add(s_add_r, s, r);
    BN_mod_inverse(inv_of_s_add_r, s_add_r, n, ctx);
    BN_mod_sub(k_sub_s, k, s, n, ctx);
    BN_mod_mul(SK, inv_of_s_add_r, k_sub_s, n, ctx);
    
    string sk = BN_bn2hex(SK);

    if (sk == d_of_A) {
        cout << "破解成功！解出密钥sk: " << sk << endl;
    }
    else{
        cout << "破解失败！\n";
    }
    printf("*结束\n\n");

    //释放内存
    BN_free(n);
    BN_free(one);
    BN_free(k);
    BN_free(r);
    BN_free(s);
    BN_free(SK);
    BN_free(s_add_r);
    BN_free(k_sub_s);
    BN_free(inv_of_s_add_r);
    EC_GROUP_free(group);
    BN_CTX_free(ctx);

    return 0;
}

#endif

#ifdef Reusing_k 

int main() {

    BN_CTX* ctx = BN_CTX_new();

    //初始化——确定选择sm2椭圆曲线
    EC_GROUP* group = EC_GROUP_new_by_curve_name(NID_sm2);

    //获取椭圆曲线的阶 n
    BIGNUM* n = BN_new();
    EC_GROUP_get_order(group, n, ctx);

    BIGNUM* one = BN_new();
    BN_set_word(one, 1);

    printf("*sm2 reusing k:\n");

    printf("*用户A生成密钥：\n");
    string d_of_A;
    vector<string> P_of_A;
    rfc6979_sm2_getKey(d_of_A, P_of_A);

    cout << "A的私钥 d：" << d_of_A << endl;
    cout << "A的公钥 P：(" << P_of_A[0] << " ," << P_of_A[1] << ")\n";

    printf("*结束\n\n");

    printf("*A开始签名：\n");
    string M1 = "hello!My name is Alice!";// 待签名明文1，可以任意更改
    string M2 = "This is my ID:{12346541765736855}.";// 待签名明文2，可以任意更改
    vector<string> sign1, sign2;

    cout << "待签名明文1：" << M1 << endl;
    cout << "待签名明文2：" << M2 << endl;

    string test = "123456789";
    string k_str = hmac_prbg(d_of_A, test, one, n);//k = [1, n)
    cout << "*陷阱条件：\n  对两段明文重用同一个随机数 k 进行签名：" << k_str << endl;

    sm2_sign_k(sign1, M1, d_of_A, k_str);
    sm2_sign_k(sign2, M2, d_of_A, k_str);

    cout << "输出对明文1的签名1:\n  r1: " << sign1[0] << "\n  s1: " << sign1[1] << endl;
    cout << "输出对明文2的签名2:\n  r2: " << sign2[0] << "\n  s2: " << sign2[1] << endl;

    printf("*结束\n\n");

    printf("*敌手利用签名(r1,s1)和(r2,s2)破解A的私钥d:\n");
    printf("* 破解算法：d = (s2 - s1)/(s1 - s2 + r1 - r2) mod n\n");
    // 因为 s1* (1 + d) = (k - r1 * d) mode n
    // 因为 s2* (1 + d) = (k - r2 * d) mode n
    // 得出 d = (s2 - s1)/(s1 - s2 + r1 - r2) mod n

    BIGNUM* r1 = BN_new();
    BIGNUM* s1 = BN_new();
    BIGNUM* r2 = BN_new();
    BIGNUM* s2 = BN_new();

    BN_hex2bn(&r1, sign1[0].c_str());
    BN_hex2bn(&s1, sign1[1].c_str());
    BN_hex2bn(&r2, sign2[0].c_str());
    BN_hex2bn(&s2, sign2[1].c_str());

    BIGNUM* SK = BN_new();
    BIGNUM* s2_sub_s1 = BN_new();
    BIGNUM* s1_sub_s2 = BN_new();
    BIGNUM* r1_sub_r2 = BN_new();
    BIGNUM* add_all = BN_new();
    BIGNUM* inv_add_all = BN_new();

    // d = (s2 - s1)/(s1 - s2 + r1 - r2) mod n
    BN_mod_sub(s2_sub_s1, s2, s1, n, ctx);
    BN_mod_sub(s1_sub_s2, s1, s2, n, ctx);
    BN_mod_sub(r1_sub_r2, r1, r2, n, ctx);
    BN_mod_add(add_all, s1_sub_s2, r1_sub_r2, n, ctx);
    BN_mod_inverse(inv_add_all, add_all, n, ctx);
    BN_mod_mul(SK, s2_sub_s1, inv_add_all, n, ctx);

    string sk = BN_bn2hex(SK);

    if (sk == d_of_A) {
        cout << "破解成功！解出密钥sk: " << sk << endl;
    }
    else {
        cout << "破解失败！\n";
    }
    printf("*结束\n\n");

    return 0;
}

#endif

#ifdef Reusing_k_by_different_users

int main() {

    BN_CTX* ctx = BN_CTX_new();

    //初始化——确定选择sm2椭圆曲线
    EC_GROUP* group = EC_GROUP_new_by_curve_name(NID_sm2);

    //获取椭圆曲线的阶 n
    BIGNUM* n = BN_new();
    EC_GROUP_get_order(group, n, ctx);

    BIGNUM* one = BN_new();
    BN_set_word(one, 1);

    printf("*sm2 reusing k by different users:\n");

    printf("*用户Alice生成密钥：\n");
    string d_of_A;
    vector<string> P_of_A;
    rfc6979_sm2_getKey(d_of_A, P_of_A);

    cout << "Alice的私钥 d：" << d_of_A << endl;
    cout << "Alice的公钥 P：(" << P_of_A[0] << " ," << P_of_A[1] << ")\n";

    printf("*结束\n\n");

    printf("*用户Bob生成密钥：\n");
    string d_of_B;
    vector<string> P_of_B;
    rfc6979_sm2_getKey(d_of_B, P_of_B);

    cout << "Bob的私钥 d：" << d_of_B << endl;
    cout << "Bob的公钥 P：(" << P_of_B[0] << " ," << P_of_B[1] << ")\n";

    printf("*结束\n\n");

    vector<string> sign1, sign2;
    string test = "123456789";
    string k_str = hmac_prbg(d_of_A, test, one, n);//k = [1, n)
    cout << "*陷阱条件：\n  两个不同用户使用不同私钥对两段明文签名，但重用同一个随机数 k：" << k_str << endl;

    printf("*Alice开始签名：\n");
    string M1 = "hello!My name is Alice!";// 待签名明文1，可以任意更改
    cout << "Alice的待签名明文M1：" << M1 << endl;
    
    sm2_sign_k(sign1, M1, d_of_A, k_str);
    cout << "输出对M1的签名1:\n  r1: " << sign1[0] << "\n  s1: " << sign1[1] << endl;


    printf("*Bob开始签名：\n");
    string M2 = "hello!My name is Bob!";// 待签名明文1，可以任意更改
    cout << "Bob的待签名明文M2：" << M2 << endl;

    sm2_sign_k(sign2, M2, d_of_B, k_str);
    cout << "输出对M2的签名2:\n  r2: " << sign2[0] << "\n  s2: " << sign2[1] << endl;

    printf("*结束\n\n");


    BIGNUM* k = BN_new();
    BIGNUM* r1 = BN_new();
    BIGNUM* s1 = BN_new();
    BIGNUM* r2 = BN_new();
    BIGNUM* s2 = BN_new();
    BN_hex2bn(&k, k_str.c_str());
    BN_hex2bn(&r1, sign1[0].c_str());
    BN_hex2bn(&s1, sign1[1].c_str());
    BN_hex2bn(&r2, sign2[0].c_str());
    BN_hex2bn(&s2, sign2[1].c_str());


    printf("*Alice可以利用Bob的签名(r2,s2)破解Bob的私钥dB:\n");
    printf("* 破解算法：dB = (k - s2)/(s2 + r2) mod n\n");
    BIGNUM* SKB = BN_new();
    BIGNUM* k_sub_s2 = BN_new();
    BIGNUM* s2_add_r2 = BN_new();
    BIGNUM* inv_of_s2_add_r2 = BN_new();

    // d = (k - s2)/(s2 + r2) mod n
    BN_mod_sub(k_sub_s2, k, s2, n, ctx);
    BN_mod_add(s2_add_r2, s2, r2, n, ctx);
    BN_mod_inverse(inv_of_s2_add_r2, s2_add_r2, n, ctx);
    BN_mod_mul(SKB, k_sub_s2, inv_of_s2_add_r2, n, ctx);

    string skB = BN_bn2hex(SKB);

    if (skB == d_of_B) {
        cout << "破解成功！解出Bob的私钥dB: " << skB << endl;
    }
    else {
        cout << "破解失败！\n";
    }
    printf("*结束\n\n");

    printf("*Bob可以利用Alice的签名(r1,s1)破解Alice的私钥dA:\n");
    printf("* 破解算法：dA = (k - s1)/(s1 + r1) mod n\n");
    BIGNUM* SKA = BN_new();
    BIGNUM* k_sub_s1 = BN_new();
    BIGNUM* s1_add_r1 = BN_new();
    BIGNUM* inv_of_s1_add_r1 = BN_new();

    // d = (k - s1)/(s1 + r1) mod n
    BN_mod_sub(k_sub_s1, k, s1, n, ctx);
    BN_mod_add(s1_add_r1, s1, r1, n, ctx);
    BN_mod_inverse(inv_of_s1_add_r1, s1_add_r1, n, ctx);
    BN_mod_mul(SKA, k_sub_s1, inv_of_s1_add_r1, n, ctx);

    string skA = BN_bn2hex(SKA);

    if (skA == d_of_A) {
        cout << "破解成功！解出Alice的私钥dA: " << skA << endl;
    }
    else {
        cout << "破解失败！\n";
    }
    printf("*结束\n\n");

    //释放内存
    BN_free(n);
    BN_free(one);
    BN_free(k);
    BN_free(r1);
    BN_free(s1);
    BN_free(r2);
    BN_free(s2);
    BN_free(SKA);
    BN_free(k_sub_s1);
    BN_free(s1_add_r1);
    BN_free(inv_of_s1_add_r1);
    BN_free(SKB);
    BN_free(k_sub_s2);
    BN_free(s2_add_r2);
    BN_free(inv_of_s2_add_r2);
    
    EC_GROUP_free(group);
    BN_CTX_free(ctx);


    return 0;
}

#endif

#ifdef Same_d_and_k_with_ECDSA

void ECDSA_sign_k(vector<string>& sign, string& message, string& sk, string& k_str);

int main() {

    BN_CTX* ctx = BN_CTX_new();

    //初始化——确定选择sm2椭圆曲线
    EC_GROUP* group = EC_GROUP_new_by_curve_name(NID_sm2);

    //获取椭圆曲线的阶 n
    BIGNUM* n = BN_new();
    EC_GROUP_get_order(group, n, ctx);

    BIGNUM* one = BN_new();
    BN_set_word(one, 1);

    printf("*same d and k with ECDSA:\n");

    printf("*用户A生成密钥：\n");
    string d_of_A;
    vector<string> P_of_A;
    rfc6979_sm2_getKey(d_of_A, P_of_A);

    cout << "A的私钥 d：" << d_of_A << endl;
    cout << "A的公钥 P：(" << P_of_A[0] << " ," << P_of_A[1] << ")\n";

    printf("*结束\n\n");

    vector<string> sign1, sign2;
    string test = "123456789";
    string k_str = hmac_prbg(d_of_A, test, one, n);//k = [1, n)
    cout << "*陷阱条件：\n  用户使用同一私钥分别采取ECDSA与SM2算法签名，但重用同一个随机数 k：" << k_str << endl;

    printf("*A开始使用ECDSA签名：\n");
    string M = "hello!My name is Alice!";// 待签名明文1，可以任意更改
    cout << "A的待签名明文M：" << M << endl;

    ECDSA_sign_k(sign1, M, d_of_A, k_str);
    cout << "输出使用ECDSA对M的签名:\n  r1: " << sign1[0] << "\n  s1: " << sign1[1] << endl;


    printf("*A开始使用SM2签名：\n");
    string ZA = "ID={45243456654456787610324081}";// 待签名明文1，可以任意更改
    cout << "A的待签名消息 ZA||M：" << ZA + M << endl;
    string Z_M = ZA + M;
    sm2_sign_k(sign2, Z_M, d_of_A, k_str);
    cout << "输出使用SM2对ZA||M的签名:\n  r2: " << sign2[0] << "\n  s2: " << sign2[1] << endl;

    printf("*结束\n\n");

    
    string e1_str = _sha256(M);

    BIGNUM* k = BN_new();
    BIGNUM* r1 = BN_new();
    BIGNUM* s1 = BN_new();
    BIGNUM* r2 = BN_new();
    BIGNUM* s2 = BN_new();
    BIGNUM* e1 = BN_new();
    BN_hex2bn(&k, k_str.c_str());
    BN_hex2bn(&e1, e1_str.c_str());
    BN_hex2bn(&r1, sign1[0].c_str());
    BN_hex2bn(&s1, sign1[1].c_str());
    BN_hex2bn(&r2, sign2[0].c_str());
    BN_hex2bn(&s2, sign2[1].c_str());


    printf("*敌手可以利用两段签名(r1,s1)、(r2,s2)以及明文M破解A的私钥d:\n");
    printf("* 破解算法：d = (s1 * s2 - e1)/(r1 - s1 * s2 - s1 * r2) mod n\n");
    BIGNUM* SK = BN_new();
    BIGNUM* s1_mul_s2 = BN_new();
    BIGNUM* sub_e1 = BN_new();
    BIGNUM* s1_mul_r2 = BN_new();
    BIGNUM* r1_sub_s1s2 = BN_new();
    BIGNUM* denominator = BN_new();
    BIGNUM* inv_of_denominator = BN_new();

    // d = (s1 * s2 - e1)/(r1 - s1 * s2 - s1 * r2) mod n
    BN_mod_mul(s1_mul_s2, s1, s2, n, ctx);
    BN_mod_sub(sub_e1, s1_mul_s2, e1, n, ctx);
    BN_mod_mul(s1_mul_r2, s1, r2, n, ctx);
    BN_mod_sub(r1_sub_s1s2, r1, s1_mul_s2, n, ctx);
    BN_mod_sub(denominator, r1_sub_s1s2, s1_mul_r2, n, ctx);
    BN_mod_inverse(inv_of_denominator, denominator, n, ctx);
    BN_mod_mul(SK, sub_e1, inv_of_denominator, n, ctx);

    string sk = BN_bn2hex(SK);

    if (sk == d_of_A) {
        cout << "破解成功！解出A的私钥d: " << sk << endl;
    }
    else {
        cout << "破解失败！\n";
    }
    printf("*结束\n\n");

    //释放内存
    BN_free(n);
    BN_free(one);
    BN_free(k);
    BN_free(e1);
    BN_free(r1);
    BN_free(s1);
    BN_free(r2);
    BN_free(s2);
    BN_free(SK);
    BN_free(s1_mul_s2);
    BN_free(sub_e1);
    BN_free(s1_mul_r2);
    BN_free(r1_sub_s1s2);
    BN_free(denominator);
    BN_free(inv_of_denominator);

    EC_GROUP_free(group);
    BN_CTX_free(ctx);


    return 0;
}

void ECDSA_sign_k(vector<string>& sign, string& message, string& sk, string& k_str) {

    BN_CTX* ctx = BN_CTX_new();

    //初始化——确定选择sm2椭圆曲线
    EC_GROUP* group = EC_GROUP_new_by_curve_name(NID_sm2);

    //获取椭圆曲线的阶 n
    BIGNUM* n = BN_new();
    EC_GROUP_get_order(group, n, ctx);


    //根据sk,message生成确定性随机数k
    BIGNUM* one = BN_new();
    BN_set_word(one, 1);
    BIGNUM* k = BN_new();
    BN_hex2bn(&k, k_str.c_str());

    //计算 R = k * G ；
    EC_POINT* R = EC_POINT_new(group);
    EC_POINT_mul(group, R, k, nullptr, nullptr, ctx);

    //获取point_KG点的 x坐标 :x1
    BIGNUM* x1 = BN_new();
    EC_POINT_get_affine_coordinates(group, R, x1, nullptr, ctx);

    //消息哈希得到hash值 e
    string e_str = _sha256(message);
    BIGNUM* e = BN_new();
    BN_hex2bn(&e, e_str.c_str());

    // r = x1 mod n
    BIGNUM* r = BN_new();
    BN_div(nullptr, r, x1, n, ctx);

    // s = (inv(k) * (e + r * sk))mod n
    BIGNUM* s = BN_new();
    BIGNUM* SK = BN_new();
    BN_hex2bn(&SK, sk.c_str());
    BIGNUM* e_add = BN_new();
    BIGNUM* inv_k = BN_new();
    BIGNUM* r_mul_sk = BN_new();

    BN_mod_inverse(inv_k, k, n, ctx);
    BN_mod_mul(r_mul_sk, r, SK, n, ctx);
    BN_mod_add(e_add, e, r_mul_sk, n, ctx);
    BN_mod_mul(s, inv_k, e_add, n, ctx);

    // (r, s)即为签名
    sign.push_back(BN_bn2hex(r));
    sign.push_back(BN_bn2hex(s));


    //释放内存
    BN_free(n);
    BN_free(k);
    BN_free(x1);
    BN_free(e);
    BN_free(r);
    BN_free(s);
    BN_free(SK);
    BN_free(e_add);
    BN_free(inv_k);
    BN_free(r_mul_sk);
    BN_free(one);
    EC_POINT_free(R);
    EC_GROUP_free(group);
    BN_CTX_free(ctx);
}

#endif



void sm2_sign_k(vector<string>& sign, string& message, string& sk, string& k_str) {

    BN_CTX* ctx = BN_CTX_new();

    //初始化——确定选择sm2椭圆曲线
    EC_GROUP* group = EC_GROUP_new_by_curve_name(NID_sm2);

    //获取椭圆曲线的阶 n
    BIGNUM* n = BN_new();
    EC_GROUP_get_order(group, n, ctx);

    //根据sk,message生成确定性随机数k
    BIGNUM* one = BN_new();
    BN_set_word(one, 1);
    BIGNUM* k = BN_new();
    BN_hex2bn(&k, k_str.c_str());

    //计算 point_kG = k * G ；
    EC_POINT* point_kG = EC_POINT_new(group);
    EC_POINT_mul(group, point_kG, k, nullptr, nullptr, ctx);

    //获取point_KG点的 x坐标 :x1
    BIGNUM* x1 = BN_new();
    EC_POINT_get_affine_coordinates(group, point_kG, x1, nullptr, ctx);

    //消息哈希得到hash值 e
    string e_str = _sha256(message);
    BIGNUM* e = BN_new();
    BN_hex2bn(&e, e_str.c_str());

    // r = (e + x1) mod n
    BIGNUM* r = BN_new();
    BN_mod_add(r, e, x1, n, ctx);

    // s = (inv(1 + sk) * (k - r * sk))mod n
    BIGNUM* s = BN_new();
    BIGNUM* SK = BN_new();
    BN_hex2bn(&SK, sk.c_str());
    BIGNUM* sk_add_1 = BN_new();
    BIGNUM* inv = BN_new();
    BIGNUM* r_mul_sk = BN_new();
    BIGNUM* k_sub = BN_new();

    BN_add(sk_add_1, one, SK);
    BN_mod_inverse(inv, sk_add_1, n, ctx);

    BIGNUM* test = BN_new();
    BN_mod_mul(test, inv, sk_add_1, n, ctx);
    BN_mod_mul(r_mul_sk, r, SK, n, ctx);
    BN_mod_sub(k_sub, k, r_mul_sk, n, ctx);
    BN_mod_mul(s, inv, k_sub, n, ctx);

    // (r, s)即为签名
    sign.push_back(BN_bn2hex(r));
    sign.push_back(BN_bn2hex(s));


    //释放内存
    BN_free(n);
    //BN_free(kk);
    BN_free(k);
    BN_free(x1);
    BN_free(e);
    BN_free(r);
    BN_free(s);
    BN_free(SK);
    BN_free(sk_add_1);
    BN_free(inv);
    BN_free(r_mul_sk);
    BN_free(k_sub);
    BN_free(one);
    EC_POINT_free(point_kG);
    EC_GROUP_free(group);
    BN_CTX_free(ctx);
}