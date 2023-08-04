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


// 计算给定集合的ECMH哈希值
string calculateECMH(vector<string>& elements, uint32_t NID_EC_type) {

    if (elements.size() == 0) {
        //cout << "空集->无穷远点->返回空字符\n";
        return "";
    }

    BN_CTX* ctx = BN_CTX_new();

    //初始化椭圆曲线
    EC_GROUP* group = EC_GROUP_new_by_curve_name(NID_EC_type);
    if (group == NULL)cout << "初始化曲线失败！\n";

    // 创建空点
    EC_POINT* resultPoint = EC_POINT_new(group);

    // 对每个元素进行加法运算
    for (const auto& element : elements) {

        // 将元素转换为点
        EC_POINT* elementPoint = EC_POINT_new(group);

        // 为适应任意长度的字符串元素，将其经过hash后标准化为长度为64的用字符串表示的十六进制256bit串
        string elem_str = _sha256(element);
        BIGNUM* elem = BN_new();
        BN_hex2bn(&elem, elem_str.c_str());

        // 将得到的 elem 值与椭圆曲线 基点G 相乘，自然得到一个EC点，视该点为元素在EC上的映射点
        if (!EC_POINT_mul(group, elementPoint, elem, nullptr, nullptr, ctx)) {
            cout << "元素映射到椭圆曲线上点失败！\n";
            BN_free(elem);
            EC_POINT_free(elementPoint);
            EC_POINT_free(resultPoint);
            EC_GROUP_free(group);
            return "";
        }

        // 进行点的加法运算， ECMH多集hash运算核心： Point_out = Point_elem1 + Point_elem2 + ··· + Point_elemN in EC
        if (!EC_POINT_add(group, resultPoint, resultPoint, elementPoint, ctx)) {
            cout << "点加运算失败\n";
            BN_free(elem);
            EC_POINT_free(elementPoint);
            EC_POINT_free(resultPoint);
            EC_GROUP_free(group);
            return "";
        }
        BN_free(elem);
        EC_POINT_free(elementPoint);
    }

    //获取点坐标
    BIGNUM* x = BN_new();
    BIGNUM* y = BN_new();
    EC_POINT_get_affine_coordinates(group, resultPoint, x, y, ctx);
    string x_str = BN_bn2hex(x);
    string y_str = BN_bn2hex(y);


    // 释放资源
    EC_POINT_free(resultPoint);
    EC_GROUP_free(group);
    BN_CTX_free(ctx);
    BN_free(x);
    BN_free(y);

    // 将运算结果点的x和y级联输入hash标准化输出为长度为64的用字符串表示的十六进制256bit串
    return _sha256(x_str + y_str);
}