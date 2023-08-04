
#include"sm2.h"
#include <WS2tcpip.h>  // ���� Windows ƽ̨��������ͷ�ļ�

#pragma comment(lib, "ws2_32.lib")  // ���ӵ� ws2_32.lib ���ļ�


string serverIP = "192.168.1.5";//ע���޸�IP


int main() {

    //��ʼ����Բ������ز���

    BN_CTX* ctx = BN_CTX_new();

    //��ʼ������ȷ��ѡ��sm2��Բ����
    EC_GROUP* group = EC_GROUP_new_by_curve_name(NID_sm2);
    if (group == NULL)cout << "��ʼ������ʧ��\n";

    //��ȡ��Բ���ߵĽ� n
    BIGNUM* n = BN_new();
    EC_GROUP_get_order(group, n, ctx);
    if (n == NULL)cout << "��ȡ��Բ���ߵĽ� n ʧ��\n";

    // ��ȡ���� G
    const EC_POINT* G = EC_GROUP_get0_generator(group);

    // ��ʼ�� Winsock
    cout << "*���ڳ�ʼ�� Winsock...";
    WSADATA wsData;
    WORD version = MAKEWORD(2, 2);
    int wsResult = WSAStartup(version, &wsData);
    if (wsResult != 0) {
        cerr << "ʧ�ܣ��޷���ʼ�� Winsock  Unable to initialize Winsock\n";
        return -1;
    }
    else {
        cout << "�ɹ�\n";
    }

    // �����ͻ����׽���
    cout << "*���ڴ����׽���...";
    SOCKET clientSocket = socket(AF_INET, SOCK_STREAM, 0);
    if (clientSocket == INVALID_SOCKET) {
        cerr << "ʧ�ܣ��޷������׽��� Unable to create socket\n";
        WSACleanup();
        return -1;
    }
    else {
        cout << "�ɹ�\n";
    }

    // ���ӵ�������
    cout << "*�������ӷ�����...";
    sockaddr_in serverAddress;
    serverAddress.sin_family = AF_INET;
    serverAddress.sin_port = htons(8080);  // ʹ�÷������Ķ˿ں�
    inet_pton(AF_INET, serverIP.c_str(), &(serverAddress.sin_addr));
    if (connect(clientSocket, (sockaddr*)&serverAddress, sizeof(serverAddress)) == SOCKET_ERROR) {
        cerr << "ʧ�ܣ��޷����ӵ������� Unable to connect to server \n";
        closesocket(clientSocket);
        WSACleanup();
        return -1;
    }
    else {
        cout << "�ɹ�\n";
    }

    ///////////////////////////////////////////////////////////////

sign2P://2Pǩ��Э�鿪ʼ------------------------------------------------------------------
    cout << "\n\n///////////////////////////////////////////////////////////////\n";
    cout << "*2Pǩ��Э������*\n";


    // 1.������˽Կ d1  ---------------------------- 
    BIGNUM* one = BN_new();
    BIGNUM* d1 = BN_new();
    string ur1 = rand256();//���ɷ�ȷ���������;
    string ur2 = rand256();
    BN_set_word(one, 1);
    string d1_str = hmac_prbg(ur1, ur2, one, n);//d1 = [1, n)
    BN_hex2bn(&d1, d1_str.c_str());//��ֵ˽Կ d1

    // P1 = inv(d1) * G
    EC_POINT* P1 = EC_POINT_new(group);
    BIGNUM* inv_d1 = BN_new();
    BN_mod_inverse(inv_d1, d1, n, ctx);
    EC_POINT_mul(group, P1, inv_d1, nullptr, nullptr, ctx);

    // �����˷��� P1
    BIGNUM* P1x = BN_new();
    BIGNUM* P1y = BN_new();
    EC_POINT_get_affine_coordinates(group, P1, P1x, P1y, ctx);
    string P1_x = BN_bn2hex(P1x);
    string P1_y = BN_bn2hex(P1y);
    BN_free(P1x);
    BN_free(P1y);

    string P1_str = P1_x + P1_y;
    send(clientSocket, P1_str.c_str(), P1_str.size() + 1, 0);
    cout << ">�����˷���P1:(" << P1_x << " , " << P1_y << ")\n";


    ///////////////////////////////////////////////////////////////

    // 3.���� k1, e, Q1

    // �ӿ���̨�����ǩ������Ϣ message
    string message;
    cout << "������ ��ǩ������Ϣ message��\n";
    cout << ">>> ";
    getline(cin, message);

    string Z = "id of myself.";

    string M = Z + message;
    string e = _sm3(M);

    // ���� k1 
    BIGNUM* k1 = BN_new();
    ur1 = rand256();//���ɷ�ȷ���������;
    ur2 = rand256();
    BN_set_word(one, 1);
    string k1_str = hmac_prbg(ur1, ur2, one, n);//k1 = [1, n)
    BN_hex2bn(&k1, k1_str.c_str());//��ֵ k1

    // Q1 = k1 * G
    EC_POINT* Q1 = EC_POINT_new(group);
    EC_POINT_mul(group, Q1, k1, nullptr, nullptr, ctx);
    BIGNUM* Q1x = BN_new();
    BIGNUM* Q1y = BN_new();
    EC_POINT_get_affine_coordinates(group, Q1, Q1x, Q1y, ctx);
    string Q1_x = BN_bn2hex(Q1x);
    string Q1_y = BN_bn2hex(Q1y);
    BN_free(Q1x);
    BN_free(Q1y);

    // �����˷��� Q1, e
    string sss = Q1_x + Q1_y + e;
    send(clientSocket, sss.c_str(), sss.size() + 1, 0);
    cout << ">�����˷���Q1:(" << Q1_x << ", " << Q1_y << ")\n e:" << e << "\n";

    ///////////////////////////////////////////////////////////////

        // 5.���� ����һ��ǩ�� s

    char input[256];
    // ���շ���˷����Ĳ���ǩ��
    ZeroMemory(input, sizeof(input));
    int bytesReceived = recv(clientSocket, input, sizeof(input), 0);
    if (bytesReceived <= 0) {
        cout << "������������ӶϿ� Disconnect from server\n";
        return 0;
    }
    //���յ����ַ�������ת������
    string input_ = input;
    string r_str = input_.substr(0, 64);
    string s2_str = input_.substr(64, 64);
    string s3_str = input_.substr(128, 64);
    BIGNUM* r = BN_new();
    BIGNUM* s2 = BN_new();
    BIGNUM* s3 = BN_new();
    BN_hex2bn(&r, r_str.c_str());
    BN_hex2bn(&s2, s2_str.c_str());
    BN_hex2bn(&s3, s3_str.c_str());
    cout << "<�յ����Է���˵Ĳ���ǩ��:\n r:" << r_str << "\n s2:" << s2_str << "\n s3:" << s3_str << "\n";

    // s = (d1 * k1) * s2 + d1 * s3 - r mod n
    BIGNUM* s = BN_new();

    BIGNUM* t1 = BN_new();
    BIGNUM* t2 = BN_new();
    BIGNUM* t3 = BN_new();
    BIGNUM* t4 = BN_new();
    BN_mod_mul(t1, d1, k1, n, ctx); // t1 = d1 * k1
    BN_mod_mul(t2, t1, s2, n, ctx); // t2 = t1 * s2
    BN_mod_mul(t3, d1, s3, n, ctx); // t3 = d1 * s3
    BN_mod_add(t4, t2, t3, n, ctx); // t4 = t2 + t3
    BN_mod_sub(s, t4, r, n, ctx);
    BN_free(t1);
    BN_free(t2);
    BN_free(t3);
    BN_free(t4);

    // aa = n - r
    BIGNUM* aa = BN_new();
    BN_mod_sub(aa, n, r, n, ctx);

    string s_str = BN_bn2hex(s);
    cout << ">�����˷�����һ��ǩ�� s:" << s_str << "\n";

    string a_str = BN_bn2hex(aa);
    cout << "n - r :" << a_str << "\n";

    cout << BN_is_zero(s) << endl;
    cout << BN_cmp(s, aa) << endl;

    if (BN_is_zero(s) == 1 && BN_cmp(s, aa) == 0) {
        cout << "����ǩ��ʧ�ܣ�\n";

        // �رտͻ����׽���
        closesocket(clientSocket);

        // �ͷ� Winsock ��Դ
        WSACleanup();

        return 0;
    }

    

    // �����˷��ͱ��ع�Կ
    send(clientSocket, s_str.c_str(), s_str.size() + 1, 0);
    cout << ">�����˷�����һ��ǩ�� s:" << s_str << "\n";

    cout << "\n****����ǩ�����¹�����\nr: " << r_str << "\ns: " << s_str << "\n";

    cout << "\n*2Pǩ������*\n";
    cout << "///////////////////////////////////////////////////////////////\n\n";

    // �رտͻ����׽���
    closesocket(clientSocket);

    // �ͷ� Winsock ��Դ
    WSACleanup();

    return 0;
}
