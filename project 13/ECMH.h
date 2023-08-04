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


// ����������ϵ�ECMH��ϣֵ
string calculateECMH(vector<string>& elements, uint32_t NID_EC_type) {

    if (elements.size() == 0) {
        //cout << "�ռ�->����Զ��->���ؿ��ַ�\n";
        return "";
    }

    BN_CTX* ctx = BN_CTX_new();

    //��ʼ����Բ����
    EC_GROUP* group = EC_GROUP_new_by_curve_name(NID_EC_type);
    if (group == NULL)cout << "��ʼ������ʧ�ܣ�\n";

    // �����յ�
    EC_POINT* resultPoint = EC_POINT_new(group);

    // ��ÿ��Ԫ�ؽ��мӷ�����
    for (const auto& element : elements) {

        // ��Ԫ��ת��Ϊ��
        EC_POINT* elementPoint = EC_POINT_new(group);

        // Ϊ��Ӧ���ⳤ�ȵ��ַ���Ԫ�أ����侭��hash���׼��Ϊ����Ϊ64�����ַ�����ʾ��ʮ������256bit��
        string elem_str = _sha256(element);
        BIGNUM* elem = BN_new();
        BN_hex2bn(&elem, elem_str.c_str());

        // ���õ��� elem ֵ����Բ���� ����G ��ˣ���Ȼ�õ�һ��EC�㣬�Ӹõ�ΪԪ����EC�ϵ�ӳ���
        if (!EC_POINT_mul(group, elementPoint, elem, nullptr, nullptr, ctx)) {
            cout << "Ԫ��ӳ�䵽��Բ�����ϵ�ʧ�ܣ�\n";
            BN_free(elem);
            EC_POINT_free(elementPoint);
            EC_POINT_free(resultPoint);
            EC_GROUP_free(group);
            return "";
        }

        // ���е�ļӷ����㣬 ECMH�༯hash������ģ� Point_out = Point_elem1 + Point_elem2 + ������ + Point_elemN in EC
        if (!EC_POINT_add(group, resultPoint, resultPoint, elementPoint, ctx)) {
            cout << "�������ʧ��\n";
            BN_free(elem);
            EC_POINT_free(elementPoint);
            EC_POINT_free(resultPoint);
            EC_GROUP_free(group);
            return "";
        }
        BN_free(elem);
        EC_POINT_free(elementPoint);
    }

    //��ȡ������
    BIGNUM* x = BN_new();
    BIGNUM* y = BN_new();
    EC_POINT_get_affine_coordinates(group, resultPoint, x, y, ctx);
    string x_str = BN_bn2hex(x);
    string y_str = BN_bn2hex(y);


    // �ͷ���Դ
    EC_POINT_free(resultPoint);
    EC_GROUP_free(group);
    BN_CTX_free(ctx);
    BN_free(x);
    BN_free(y);

    // �����������x��y��������hash��׼�����Ϊ����Ϊ64�����ַ�����ʾ��ʮ������256bit��
    return _sha256(x_str + y_str);
}