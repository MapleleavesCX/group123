#include"sm2.h"


//ѡ����һ���ȡ��ע�ͣ�ͬʱ����������ע�͵� <<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
#define Leaking_k 
//#define Reusing_k 
//#define Reusing_k_by_different_users
//#define Same_d_and_k_with_ECDSA

void sm2_sign_k(vector<string>& sign, string& message, string& sk, string& k_str);

#ifdef Leaking_k

int main() {

    BN_CTX* ctx = BN_CTX_new();

    //��ʼ������ȷ��ѡ��sm2��Բ����
    EC_GROUP* group = EC_GROUP_new_by_curve_name(NID_sm2);

    //��ȡ��Բ���ߵĽ� n
    BIGNUM* n = BN_new();
    EC_GROUP_get_order(group, n, ctx);

    BIGNUM* one = BN_new();
    BN_set_word(one, 1);

	printf("*sm2 leaking k:\n");

	printf("*�û�A������Կ��\n");
	string d_of_A;
	vector<string> P_of_A;
	rfc6979_sm2_getKey(d_of_A, P_of_A);

	cout << "A��˽Կ d��" << d_of_A << endl;
	cout << "A�Ĺ�Կ P��(" << P_of_A[0] << " ," << P_of_A[1] << ")\n";

	printf("*����\n\n");

	printf("*A��ʼǩ����\n");
	string M = "hello!My name is Alice!";// ��ǩ�����ģ������������
	vector<string> sign;

    string test = "123456789";
    string k_str = hmac_prbg(d_of_A, test, one, n);//k = [1, n)
    cout << "*����������\n  ǩ��������, ����� k й¶��" << k_str << endl;

    sm2_sign_k(sign, M, d_of_A, k_str);

    cout << "��ǩ�����ģ�" << M << endl;
    cout << "���ǩ��:\n  r: " << sign[0] << "\n  s: " << sign[1] << endl;
    
    printf("*����\n\n");

    printf("*��������ǩ��(r,s)��k�����ƽ�A��˽Կd:\n");
    printf("* �ƽ��㷨��d = inv(s + r) * (k - s) mod n\n");
    // ��Ϊ s = ((inv(1 + d) * (k - r * d)) mod n
    //  �� s * (1 + d) = (k - r * d) mod n
    // �ó� d = inv(s + r) * (k - s) mod n

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

    // ���� d = inv(s + r) * (k - s) mod n
    BN_add(s_add_r, s, r);
    BN_mod_inverse(inv_of_s_add_r, s_add_r, n, ctx);
    BN_mod_sub(k_sub_s, k, s, n, ctx);
    BN_mod_mul(SK, inv_of_s_add_r, k_sub_s, n, ctx);
    
    string sk = BN_bn2hex(SK);

    if (sk == d_of_A) {
        cout << "�ƽ�ɹ��������Կsk: " << sk << endl;
    }
    else{
        cout << "�ƽ�ʧ�ܣ�\n";
    }
    printf("*����\n\n");

    //�ͷ��ڴ�
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

    //��ʼ������ȷ��ѡ��sm2��Բ����
    EC_GROUP* group = EC_GROUP_new_by_curve_name(NID_sm2);

    //��ȡ��Բ���ߵĽ� n
    BIGNUM* n = BN_new();
    EC_GROUP_get_order(group, n, ctx);

    BIGNUM* one = BN_new();
    BN_set_word(one, 1);

    printf("*sm2 reusing k:\n");

    printf("*�û�A������Կ��\n");
    string d_of_A;
    vector<string> P_of_A;
    rfc6979_sm2_getKey(d_of_A, P_of_A);

    cout << "A��˽Կ d��" << d_of_A << endl;
    cout << "A�Ĺ�Կ P��(" << P_of_A[0] << " ," << P_of_A[1] << ")\n";

    printf("*����\n\n");

    printf("*A��ʼǩ����\n");
    string M1 = "hello!My name is Alice!";// ��ǩ������1�������������
    string M2 = "This is my ID:{12346541765736855}.";// ��ǩ������2�������������
    vector<string> sign1, sign2;

    cout << "��ǩ������1��" << M1 << endl;
    cout << "��ǩ������2��" << M2 << endl;

    string test = "123456789";
    string k_str = hmac_prbg(d_of_A, test, one, n);//k = [1, n)
    cout << "*����������\n  ��������������ͬһ������� k ����ǩ����" << k_str << endl;

    sm2_sign_k(sign1, M1, d_of_A, k_str);
    sm2_sign_k(sign2, M2, d_of_A, k_str);

    cout << "���������1��ǩ��1:\n  r1: " << sign1[0] << "\n  s1: " << sign1[1] << endl;
    cout << "���������2��ǩ��2:\n  r2: " << sign2[0] << "\n  s2: " << sign2[1] << endl;

    printf("*����\n\n");

    printf("*��������ǩ��(r1,s1)��(r2,s2)�ƽ�A��˽Կd:\n");
    printf("* �ƽ��㷨��d = (s2 - s1)/(s1 - s2 + r1 - r2) mod n\n");
    // ��Ϊ s1* (1 + d) = (k - r1 * d) mode n
    // ��Ϊ s2* (1 + d) = (k - r2 * d) mode n
    // �ó� d = (s2 - s1)/(s1 - s2 + r1 - r2) mod n

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
        cout << "�ƽ�ɹ��������Կsk: " << sk << endl;
    }
    else {
        cout << "�ƽ�ʧ�ܣ�\n";
    }
    printf("*����\n\n");

    return 0;
}

#endif

#ifdef Reusing_k_by_different_users

int main() {

    BN_CTX* ctx = BN_CTX_new();

    //��ʼ������ȷ��ѡ��sm2��Բ����
    EC_GROUP* group = EC_GROUP_new_by_curve_name(NID_sm2);

    //��ȡ��Բ���ߵĽ� n
    BIGNUM* n = BN_new();
    EC_GROUP_get_order(group, n, ctx);

    BIGNUM* one = BN_new();
    BN_set_word(one, 1);

    printf("*sm2 reusing k by different users:\n");

    printf("*�û�Alice������Կ��\n");
    string d_of_A;
    vector<string> P_of_A;
    rfc6979_sm2_getKey(d_of_A, P_of_A);

    cout << "Alice��˽Կ d��" << d_of_A << endl;
    cout << "Alice�Ĺ�Կ P��(" << P_of_A[0] << " ," << P_of_A[1] << ")\n";

    printf("*����\n\n");

    printf("*�û�Bob������Կ��\n");
    string d_of_B;
    vector<string> P_of_B;
    rfc6979_sm2_getKey(d_of_B, P_of_B);

    cout << "Bob��˽Կ d��" << d_of_B << endl;
    cout << "Bob�Ĺ�Կ P��(" << P_of_B[0] << " ," << P_of_B[1] << ")\n";

    printf("*����\n\n");

    vector<string> sign1, sign2;
    string test = "123456789";
    string k_str = hmac_prbg(d_of_A, test, one, n);//k = [1, n)
    cout << "*����������\n  ������ͬ�û�ʹ�ò�ͬ˽Կ����������ǩ����������ͬһ������� k��" << k_str << endl;

    printf("*Alice��ʼǩ����\n");
    string M1 = "hello!My name is Alice!";// ��ǩ������1�������������
    cout << "Alice�Ĵ�ǩ������M1��" << M1 << endl;
    
    sm2_sign_k(sign1, M1, d_of_A, k_str);
    cout << "�����M1��ǩ��1:\n  r1: " << sign1[0] << "\n  s1: " << sign1[1] << endl;


    printf("*Bob��ʼǩ����\n");
    string M2 = "hello!My name is Bob!";// ��ǩ������1�������������
    cout << "Bob�Ĵ�ǩ������M2��" << M2 << endl;

    sm2_sign_k(sign2, M2, d_of_B, k_str);
    cout << "�����M2��ǩ��2:\n  r2: " << sign2[0] << "\n  s2: " << sign2[1] << endl;

    printf("*����\n\n");


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


    printf("*Alice��������Bob��ǩ��(r2,s2)�ƽ�Bob��˽ԿdB:\n");
    printf("* �ƽ��㷨��dB = (k - s2)/(s2 + r2) mod n\n");
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
        cout << "�ƽ�ɹ������Bob��˽ԿdB: " << skB << endl;
    }
    else {
        cout << "�ƽ�ʧ�ܣ�\n";
    }
    printf("*����\n\n");

    printf("*Bob��������Alice��ǩ��(r1,s1)�ƽ�Alice��˽ԿdA:\n");
    printf("* �ƽ��㷨��dA = (k - s1)/(s1 + r1) mod n\n");
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
        cout << "�ƽ�ɹ������Alice��˽ԿdA: " << skA << endl;
    }
    else {
        cout << "�ƽ�ʧ�ܣ�\n";
    }
    printf("*����\n\n");

    //�ͷ��ڴ�
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

    //��ʼ������ȷ��ѡ��sm2��Բ����
    EC_GROUP* group = EC_GROUP_new_by_curve_name(NID_sm2);

    //��ȡ��Բ���ߵĽ� n
    BIGNUM* n = BN_new();
    EC_GROUP_get_order(group, n, ctx);

    BIGNUM* one = BN_new();
    BN_set_word(one, 1);

    printf("*same d and k with ECDSA:\n");

    printf("*�û�A������Կ��\n");
    string d_of_A;
    vector<string> P_of_A;
    rfc6979_sm2_getKey(d_of_A, P_of_A);

    cout << "A��˽Կ d��" << d_of_A << endl;
    cout << "A�Ĺ�Կ P��(" << P_of_A[0] << " ," << P_of_A[1] << ")\n";

    printf("*����\n\n");

    vector<string> sign1, sign2;
    string test = "123456789";
    string k_str = hmac_prbg(d_of_A, test, one, n);//k = [1, n)
    cout << "*����������\n  �û�ʹ��ͬһ˽Կ�ֱ��ȡECDSA��SM2�㷨ǩ����������ͬһ������� k��" << k_str << endl;

    printf("*A��ʼʹ��ECDSAǩ����\n");
    string M = "hello!My name is Alice!";// ��ǩ������1�������������
    cout << "A�Ĵ�ǩ������M��" << M << endl;

    ECDSA_sign_k(sign1, M, d_of_A, k_str);
    cout << "���ʹ��ECDSA��M��ǩ��:\n  r1: " << sign1[0] << "\n  s1: " << sign1[1] << endl;


    printf("*A��ʼʹ��SM2ǩ����\n");
    string ZA = "ID={45243456654456787610324081}";// ��ǩ������1�������������
    cout << "A�Ĵ�ǩ����Ϣ ZA||M��" << ZA + M << endl;
    string Z_M = ZA + M;
    sm2_sign_k(sign2, Z_M, d_of_A, k_str);
    cout << "���ʹ��SM2��ZA||M��ǩ��:\n  r2: " << sign2[0] << "\n  s2: " << sign2[1] << endl;

    printf("*����\n\n");

    
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


    printf("*���ֿ�����������ǩ��(r1,s1)��(r2,s2)�Լ�����M�ƽ�A��˽Կd:\n");
    printf("* �ƽ��㷨��d = (s1 * s2 - e1)/(r1 - s1 * s2 - s1 * r2) mod n\n");
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
        cout << "�ƽ�ɹ������A��˽Կd: " << sk << endl;
    }
    else {
        cout << "�ƽ�ʧ�ܣ�\n";
    }
    printf("*����\n\n");

    //�ͷ��ڴ�
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

    //��ʼ������ȷ��ѡ��sm2��Բ����
    EC_GROUP* group = EC_GROUP_new_by_curve_name(NID_sm2);

    //��ȡ��Բ���ߵĽ� n
    BIGNUM* n = BN_new();
    EC_GROUP_get_order(group, n, ctx);


    //����sk,message����ȷ���������k
    BIGNUM* one = BN_new();
    BN_set_word(one, 1);
    BIGNUM* k = BN_new();
    BN_hex2bn(&k, k_str.c_str());

    //���� R = k * G ��
    EC_POINT* R = EC_POINT_new(group);
    EC_POINT_mul(group, R, k, nullptr, nullptr, ctx);

    //��ȡpoint_KG��� x���� :x1
    BIGNUM* x1 = BN_new();
    EC_POINT_get_affine_coordinates(group, R, x1, nullptr, ctx);

    //��Ϣ��ϣ�õ�hashֵ e
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

    // (r, s)��Ϊǩ��
    sign.push_back(BN_bn2hex(r));
    sign.push_back(BN_bn2hex(s));


    //�ͷ��ڴ�
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

    //��ʼ������ȷ��ѡ��sm2��Բ����
    EC_GROUP* group = EC_GROUP_new_by_curve_name(NID_sm2);

    //��ȡ��Բ���ߵĽ� n
    BIGNUM* n = BN_new();
    EC_GROUP_get_order(group, n, ctx);

    //����sk,message����ȷ���������k
    BIGNUM* one = BN_new();
    BN_set_word(one, 1);
    BIGNUM* k = BN_new();
    BN_hex2bn(&k, k_str.c_str());

    //���� point_kG = k * G ��
    EC_POINT* point_kG = EC_POINT_new(group);
    EC_POINT_mul(group, point_kG, k, nullptr, nullptr, ctx);

    //��ȡpoint_KG��� x���� :x1
    BIGNUM* x1 = BN_new();
    EC_POINT_get_affine_coordinates(group, point_kG, x1, nullptr, ctx);

    //��Ϣ��ϣ�õ�hashֵ e
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

    // (r, s)��Ϊǩ��
    sign.push_back(BN_bn2hex(r));
    sign.push_back(BN_bn2hex(s));


    //�ͷ��ڴ�
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