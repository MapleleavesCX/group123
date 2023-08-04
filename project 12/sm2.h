#pragma once
#pragma once
#include <openssl/evp.h>
#include <openssl/bn.h>
#include <openssl/ec.h>
#include <openssl/obj_mac.h>
#include <openssl/objects.h>

#include <iostream>
#include <iomanip>
#include <sstream>
#include<vector>
#include <chrono>
#include <sstream>
#include <string>
#include <cstdint>
#include<random>

using namespace std;

template<typename Func, typename... Args>
void timing(Func func, Args&&... args)
{
    auto start = chrono::system_clock::now();
    func(args...);
    auto end = chrono::system_clock::now();
    auto duration = chrono::duration_cast<chrono::microseconds>(end - start);
    cout << "执行时间：" << duration.count() << " 微秒" << endl;

}

//字符串类型整数字节流转换为字符串表示的十六进制数
string bit2hex(const string& input) {
    stringstream ss;
    uint8_t t;
    size_t len = input.length();
    for (size_t i = 0; i < len; i++) {
        t = input[i];
        ss << hex << uppercase << setw(2) << setfill('0') << (int)t;
    }

    return ss.str();
}

//将字符串表示的十六进制数转换为整数字节流
bool hex2bit(string& output, string& input) {

    if (output.length() % 2 != 0) {
        cout << "错误！字符长度不是2的倍数\n";
        return false;
    }
    output = "";
    size_t L = input.length();
    uint8_t x = 0, t = 0;
    for (size_t i = 0, j = 0; i < L; i++) {
        if (input[i] >= '0' && input[i] <= '9')
        {
            x = input[i] - '0';
        }
        else if (input[i] >= 'a' && input[i] <= 'f')
        {
            x = input[i] - 'a' + 10;
        }
        else if (input[i] >= 'A' && input[i] <= 'F')
        {
            x = input[i] - 'A' + 10;
        }
        else
        {
            cout << "错误！字符表示超出十六进制范围\n";
            return false;
        }
        if (i % 2 == 0) {
            t += x * 16;
        }
        else {
            t += x;
            output.push_back(t);
            t = 0;
        }
    }
    return true;
}




//输入为bit流，输出为用字符串表示的十六进制字符串（共64个字符）
string _sm3(const string& input) {
    EVP_MD_CTX* mdctx;
    unsigned char hash[32];
    unsigned int hash_len;

    mdctx = EVP_MD_CTX_new();
    EVP_DigestInit_ex(mdctx, EVP_sm3(), NULL);
    EVP_DigestUpdate(mdctx, input.c_str(), input.length());
    EVP_DigestFinal_ex(mdctx, hash, &hash_len);
    EVP_MD_CTX_free(mdctx);

    stringstream ss;
    for (unsigned int i = 0; i < hash_len; i++) {
        ss << hex << uppercase << setw(2) << setfill('0') << (int)hash[i];
    }

    return ss.str();
}

//输入为bit流，输出为用字符串表示的十六进制字符串（共64个字符）
string _sha256(const string& input) {
    EVP_MD_CTX* mdctx;
    unsigned char hash[EVP_MAX_MD_SIZE];
    unsigned int hash_len;

    mdctx = EVP_MD_CTX_new();
    EVP_DigestInit_ex(mdctx, EVP_sha256(), NULL);
    EVP_DigestUpdate(mdctx, input.c_str(), input.length());
    EVP_DigestFinal_ex(mdctx, hash, &hash_len);
    EVP_MD_CTX_free(mdctx);

    stringstream ss;
    for (unsigned int i = 0; i < hash_len; i++) {
        ss << hex << uppercase << setw(2) << setfill('0') << (int)hash[i];
    }

    return ss.str();
}

//输入为bit流，输出为string类型的bit流（共32个字符），
//需要用可视化函数转换为用字符串表示的十六进制字符串
string sha256(const string& input) {
    EVP_MD_CTX* mdctx;
    unsigned char hash[EVP_MAX_MD_SIZE];
    unsigned int hash_len;

    mdctx = EVP_MD_CTX_new();
    EVP_DigestInit_ex(mdctx, EVP_sha256(), NULL);
    EVP_DigestUpdate(mdctx, input.c_str(), input.length());
    EVP_DigestFinal_ex(mdctx, hash, &hash_len);
    EVP_MD_CTX_free(mdctx);

    string ss(32, 0x00);
    for (int i = 0; i < 32; i++) {
        ss[i] = hash[i];
    }
    return ss;
}


// 输入为bit流，输出为string类型的bit流（共32个字符）
//HMAC(key, message) = SHA256((key xor opad) || SHA256((key xor ipad) || message))
string hmac_sha256(string& key, const string& message) {
    size_t len = key.size();
    string y1(len, 0x00);
    string input(len, 0x00);

    //(key xor opad), (key xor ipad)
    for (size_t i = 0; i < len; i++) {
        y1[i] = key[i] ^ 0x5c;
        input[i] = key[i] ^ 0x36;
    }

    string y2 = sha256(input);

    return sha256(y1 + y2 + message);
}

//确定性随机数生成器，生成随机数，范围 ( max, min ]
string hmac_prbg(string& input1, string& input2, BIGNUM* Min, BIGNUM* Max) {

    BN_CTX* ctx = BN_CTX_new();

    string rand_out = bit2hex(hmac_sha256(input1, input2));
    BIGNUM* Rand_out = BN_new();
    BN_hex2bn(&Rand_out, rand_out.c_str());

    BIGNUM* modnum = BN_new();
    BIGNUM* result = BN_new();

    // modnum = Max - Min
    BN_sub(modnum, Max, Min);

    // Out = rand % modnum + min
    BIGNUM* Out = BN_new();
    BN_div(nullptr, result, Rand_out, modnum, ctx);//模除Max

    BN_add(Out, result, Min);//加Min

    string out = BN_bn2hex(Out);

    BN_free(Rand_out);
    BN_free(modnum);
    BN_free(result);
    BN_free(Out);
    BN_CTX_free(ctx);

    return out;
}

//生成长度为256位的非确定性随机数，返回为以字符串表示的十六进制数
string rand256() {

    // 使用随机设备作为种子
    random_device rd;

    // 使用 Mersenne Twister 引擎
    mt19937 gen(rd());

    // 生成一个范围在 0 到 15（包括）的随机整数
    uniform_int_distribution<> dis(0, 15);

    uint32_t r;
    string ss(64, 0x00);
    for (uint32_t i = 0; i < 64; i++) {
        r = (uint32_t)dis(gen) % 16;
        if (r < 10)
            ss[i] = r + '0';
        else
            ss[i] = r + 'a' - 10;
    }
    return _sha256(ss);
}

// 输入为bit流，输出为string类型的bit流，每个单位8bit
string HKDF(size_t len, string& salt, string& IKM, string info = "session_key_v1") {

    string output = "";

    string PRK = hmac_sha256(salt, IKM);
    output += PRK;

    string T = "";
    string U = { 0x01 };
    while (output.size() < len) {
        T = hmac_sha256(PRK, T + info + U);
        U[0]++;
        output += T;
    }

    return output.substr(0, len);
}


// sm2的密钥生成函数----------------------------------------------
void rfc6979_sm2_getKey(string& sk, vector<string>& pk) {

    BN_CTX* ctx = BN_CTX_new();

    //初始化——确定选择sm2椭圆曲线
    EC_GROUP* group = EC_GROUP_new_by_curve_name(NID_sm2);
    if (group == NULL)cout << "初始化曲线失败\n";

    //获取椭圆曲线的阶 n
    BIGNUM* n = BN_new();
    EC_GROUP_get_order(group, n, ctx);
    if (n == NULL)cout << "获取椭圆曲线的阶 n 失败\n";

    //生成非确定性随机数;
    string ur1 = rand256();
    string ur2 = rand256();

    //赋值私钥 SK
    BIGNUM* one = BN_new();
    BN_set_word(one, 1);
    string sk_str = hmac_prbg(ur1, ur2, one, n);//sk = [1, n)
    BIGNUM* SK = BN_new();
    BN_hex2bn(&SK, sk_str.c_str());

    //计算 PK = SK * G ；
    EC_POINT* PK = EC_POINT_new(group);
    EC_POINT_mul(group, PK, SK, nullptr, nullptr, ctx);

    //获取点坐标
    BIGNUM* PK_x = BN_new();
    BIGNUM* PK_y = BN_new();
    EC_POINT_get_affine_coordinates(group, PK, PK_x, PK_y, ctx);

    //转换类型，返回公私钥
    sk = BN_bn2hex(SK);
    pk.push_back(BN_bn2hex(PK_x));
    pk.push_back(BN_bn2hex(PK_y));

    //释放
    BN_free(n);
    BN_free(one);
    BN_free(SK);
    BN_free(PK_x);
    BN_free(PK_y);
    EC_POINT_free(PK);
    EC_GROUP_free(group);
    BN_CTX_free(ctx);
}

// sm2的签名函数--------------------------------------------------
void rfc6979_sm2_sign(vector<string>& sign, string& message, string& sk) {

    BN_CTX* ctx = BN_CTX_new();

    //初始化——确定选择sm2椭圆曲线
    EC_GROUP* group = EC_GROUP_new_by_curve_name(NID_sm2);

    //获取椭圆曲线的阶 n
    BIGNUM* n = BN_new();
    EC_GROUP_get_order(group, n, ctx);


    //string k_str = translate(hmac_sha256(sk, message));
    //BIGNUM* kk = BN_new();
    //BN_hex2bn(&kk, k_str.c_str());

    ////经过约化：k = kk mod n 得到最终的 k
    //BIGNUM* k = BN_new();
    //BN_div(nullptr, k, kk, n, ctx);


    //根据sk,message生成确定性随机数k
    BIGNUM* one = BN_new();
    BN_set_word(one, 1);
    string k_str = hmac_prbg(sk, message, one, n);//k = [1, n)
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

// sm2的验签函数--------------------------------------------------
bool rfc6979_sm2_verify(string& message, vector<string>& sign, vector<string>& pk) {

    BN_CTX* ctx = BN_CTX_new();

    //初始化——确定选择sm2椭圆曲线
    EC_GROUP* group = EC_GROUP_new_by_curve_name(NID_sm2);

    //获取椭圆曲线的阶 n
    BIGNUM* n = BN_new();
    EC_GROUP_get_order(group, n, ctx);

    //判断r和s的取值范围
    BIGNUM* r = BN_new();
    BIGNUM* s = BN_new();
    BN_hex2bn(&r, sign[0].c_str());
    BN_hex2bn(&s, sign[1].c_str());

    BIGNUM* one = BN_new();
    BN_set_word(one, 1);

    if (BN_cmp(r, n) >= 0 && BN_cmp(r, one) <= 0)
        return false;
    if (BN_cmp(s, n) >= 0 && BN_cmp(s, one) <= 0)
        return false;


    //消息哈希得到hash值 e
    string e_str = _sha256(message);
    BIGNUM* e = BN_new();
    BN_hex2bn(&e, e_str.c_str());

    // t = (r + s) mod n
    BIGNUM* t = BN_new();
    BN_mod_add(t, r, s, n, ctx);

    //赋值点 PK
    BIGNUM* pk_x = BN_new();
    BIGNUM* pk_y = BN_new();
    BN_hex2bn(&pk_x, pk[0].c_str());
    BN_hex2bn(&pk_y, pk[1].c_str());

    EC_POINT* PK = EC_POINT_new(group);
    EC_POINT_set_affine_coordinates(group, PK, pk_x, pk_y, ctx);

    // (x1, y1) = s * G + t * PK
    EC_POINT* sG = EC_POINT_new(group);
    EC_POINT* tPK = EC_POINT_new(group);
    EC_POINT* XY = EC_POINT_new(group);

    EC_POINT_mul(group, sG, s, nullptr, nullptr, ctx);
    EC_POINT_mul(group, tPK, nullptr, PK, t, ctx);
    EC_POINT_add(group, XY, sG, tPK, ctx);

    BIGNUM* x1 = BN_new();
    EC_POINT_get_affine_coordinates(group, XY, x1, nullptr, ctx);

    // R = (e + x1) mod n
    BIGNUM* R = BN_new();
    BN_mod_add(R, e, x1, n, ctx);
    string R_str = BN_bn2hex(R);

    //释放
    BN_free(n);
    BN_free(r);
    BN_free(s);
    BN_free(one);
    BN_free(e);
    BN_free(t);
    BN_free(pk_x);
    BN_free(pk_y);
    BN_free(x1);
    BN_free(R);
    EC_POINT_free(sG);
    EC_POINT_free(tPK);
    EC_POINT_free(XY);
    EC_GROUP_free(group);
    BN_CTX_free(ctx);

    if (R_str == sign[0])
        return true;
    else
        return false;
}



// sm2的加密函数--------------------------------------------------
bool sm2_enc(vector<string>& c1c2c3, string& message, vector<string>& pk) {

    BN_CTX* ctx = BN_CTX_new();

    //初始化——确定选择sm2椭圆曲线
    EC_GROUP* group = EC_GROUP_new_by_curve_name(NID_sm2);

    //获取椭圆曲线的阶 n
    BIGNUM* n = BN_new();
    EC_GROUP_get_order(group, n, ctx);

    //根据pk,message生成确定性随机数k
    string pkk = pk[0] + pk[1];
    BIGNUM* one = BN_new();
    BN_set_word(one, 1);
    string k_str = hmac_prbg(pkk, message, one, n);//k = [1, n)
    BIGNUM* k = BN_new();
    BN_hex2bn(&k, k_str.c_str());

    //计算 (x1,y1) = k * G ；
    EC_POINT* pC1 = EC_POINT_new(group);
    EC_POINT_mul(group, pC1, k, nullptr, nullptr, ctx);

    //分别获取(x1,y1)
    BIGNUM* x1 = BN_new();
    BIGNUM* y1 = BN_new();
    EC_POINT_get_affine_coordinates(group, pC1, x1, y1, ctx);

    //获取公钥pk
    BIGNUM* pkx = BN_new();
    BIGNUM* pky = BN_new();
    BN_hex2bn(&pkx, pk[0].c_str());
    BN_hex2bn(&pky, pk[1].c_str());
    EC_POINT* PK = EC_POINT_new(group);
    EC_POINT_set_affine_coordinates(group, PK, pkx, pky, ctx);

    // (x2,y2)=k * PK
    EC_POINT* XY2 = EC_POINT_new(group);
    EC_POINT_mul(group, XY2, nullptr, PK, k, ctx);
    BIGNUM* x2 = BN_new();
    BIGNUM* y2 = BN_new();
    EC_POINT_get_affine_coordinates(group, XY2, x2, y2, ctx);

    // t = KDF(x2||y2, mlen)
    size_t mlen = message.size();
    string x2_str = BN_bn2hex(x2);
    string y2_str = BN_bn2hex(y2);

    string t = HKDF(mlen, x2_str, y2_str);



    //获取C1,长度128个字符(512bit)--字符串表示的16进制
    string x1_str = BN_bn2hex(x1);
    string y1_str = BN_bn2hex(y1);
    string C1 = x1_str + y1_str;

    // c2 = M ^ t， 长度为mlen个字符
    string c2(mlen, 0x00);
    for (size_t i = 0; i < mlen; i++) {
        c2[i] = message[i] ^ t[i];
    }

    //将字符翻译为字符串表示的16进制 c2 --> C2
    stringstream ss;
    uint8_t x;
    for (size_t i = 0; i < mlen; i++) {
        x = c2[i];
        ss << hex << uppercase << setw(2) << setfill('0') << (int)x;
    }
    string C2 = ss.str();



    // C3 = HASH(x2 || M || y2)，固定长度64个字符(256bit)--字符串表示的16进制
    string C3 = _sha256(x2_str + message + y2_str);

    //返回C1、C2、C3
    c1c2c3.push_back(C1);
    c1c2c3.push_back(C2);
    c1c2c3.push_back(C3);


    //释放内存
    BN_free(n);
    BN_free(k);
    BN_free(x1);
    BN_free(y1);
    BN_free(x2);
    BN_free(y2);
    BN_free(one);
    EC_POINT_free(pC1);
    EC_GROUP_free(group);
    BN_CTX_free(ctx);

    return true;
}

// sm2的解密函数--------------------------------------------------
bool sm2_dec(string& M, string& sk, vector<string>& c1c2c3) {

    BN_CTX* ctx = BN_CTX_new();

    //初始化——确定选择sm2椭圆曲线
    EC_GROUP* group = EC_GROUP_new_by_curve_name(NID_sm2);

    //获取椭圆曲线的阶 n
    BIGNUM* n = BN_new();
    EC_GROUP_get_order(group, n, ctx);

    //获取sk
    BIGNUM* SK = BN_new();
    BN_hex2bn(&SK, sk.c_str());

    //获取C1
    BIGNUM* C1x = BN_new();
    BIGNUM* C1y = BN_new();
    string c1x = c1c2c3[0].substr(0, 64);
    string c1y = c1c2c3[0].substr(64, 64);
    BN_hex2bn(&C1x, c1x.c_str());
    BN_hex2bn(&C1y, c1y.c_str());

    EC_POINT* C1 = EC_POINT_new(group);
    EC_POINT_set_affine_coordinates(group, C1, C1x, C1y, ctx);

    //判断 C1是否属于椭圆曲线上的点
    if (!EC_POINT_is_on_curve(group, C1, ctx))
    {
        cout << "C1不属于sm2椭圆曲线上的点\n";
        //释放内存
        BN_free(n);
        BN_free(SK);
        BN_free(C1x);
        BN_free(C1y);
        EC_POINT_free(C1);
        EC_GROUP_free(group);
        BN_CTX_free(ctx);
        return false;
    }

    // (x2,y2)=SK * C1
    EC_POINT* XY2 = EC_POINT_new(group);
    EC_POINT_mul(group, XY2, nullptr, C1, SK, ctx);

    //获取x2,y2
    BIGNUM* x2 = BN_new();
    BIGNUM* y2 = BN_new();
    EC_POINT_get_affine_coordinates(group, XY2, x2, y2, ctx);
    string x2_str = BN_bn2hex(x2);
    string y2_str = BN_bn2hex(y2);

    //获取c2
    string C2 = c1c2c3[1];
    size_t L = C2.length();

    //将字符串表示的16进制串转换为bit流, C2 --> c2
    string c2;
    if (!hex2bit(c2, C2))
    {
        //释放内存
        BN_free(n);
        BN_free(SK);
        BN_free(C1x);
        BN_free(C1y);
        BN_free(x2);
        BN_free(y2);
        EC_POINT_free(C1);
        EC_GROUP_free(group);
        BN_CTX_free(ctx);
        return false;
    }

    // t = KDF(x2||y2, mlen)
    size_t mlen = c2.length();
    string t = HKDF(mlen, x2_str, y2_str);

    // M = c2 ^ t， 长度为mlen个字符
    string m(mlen, 0x00);
    for (size_t i = 0; i < mlen; i++) {
        m[i] = c2[i] ^ t[i];
    }

    // U = HASH(x2 || M || y2)
    string U = _sha256(x2_str + m + y2_str);

    //判断：U==C3？
    if (U != c1c2c3[2])
    {
        cout << "U != C3\n";
        //释放内存
        BN_free(n);
        BN_free(SK);
        BN_free(C1x);
        BN_free(C1y);
        BN_free(x2);
        BN_free(y2);
        EC_POINT_free(C1);
        EC_GROUP_free(group);
        BN_CTX_free(ctx);
        return false;
    }

    //返回明文
    M = m;

    //释放内存
    BN_free(n);
    BN_free(SK);
    BN_free(C1x);
    BN_free(C1y);
    BN_free(x2);
    BN_free(y2);
    EC_POINT_free(C1);
    EC_GROUP_free(group);
    BN_CTX_free(ctx);

    return true;
}