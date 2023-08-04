
#include"sm2.h"
#include <WS2tcpip.h>  // ���� Windows ƽ̨��������ͷ�ļ�

#pragma comment(lib, "ws2_32.lib")  // ���ӵ� ws2_32.lib ���ļ�


string serverIP = "192.168.1.5";//�����IP��ַ��ע����IP�������޸�


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

enc2P://2P����Э�鿪ʼ------------------------------------------------------------------
    cout << "\n\n///////////////////////////////////////////////////////////////\n";
    cout << "*2P����Э������*\n";


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

    char CC[512];
    // ���շ���˷��������� C
    ZeroMemory(CC, sizeof(CC));
    int bytesReceived = recv(clientSocket, CC, sizeof(CC), 0);
    if (bytesReceived <= 0) {
        cout << "������������ӶϿ� Disconnect from server\n";
        return 0;
    }
    // 2. ��ȡ���� C = C1||C2||C3
    string C_str = CC;
    string C1_x = C_str.substr(0, 64);
    string C1_y = C_str.substr(64, 64);
    string C2_str = C_str.substr(128, C_str.length() - 192);
    string C3_str = C_str.substr(C_str.length() - 64, 64);

    BIGNUM* C1x = BN_new();
    BIGNUM* C1y = BN_new();
    BN_hex2bn(&C1x, C1_x.c_str());
    BN_hex2bn(&C1y, C1_y.c_str());
    EC_POINT* C1 = EC_POINT_new(group);
    EC_POINT_set_affine_coordinates(group, C1, C1x, C1y, ctx);
    cout << "<�յ����Է���˵�����: \n C1:(" << C1_x << " , " << C1_y << ")\n C2:" << C2_str << "\n C3:" << C3_str << "\n";
    cout << "\n*2P���ܽ���*\n";



dec2P://2P����Э�鿪ʼ------------------------------------------------------------------
    cout << "\n\n///////////////////////////////////////////////////////////////\n";
    cout << "*2P����Э������*\n";
    
    ///////////////////////////////////////////////////////////////

    //���C1 != 0
    cout << "*���C1�Ƿ�Ϸ�...";
    if (!EC_POINT_is_on_curve(group, C1, ctx)) {
        cout << "����C1���������ϣ�\n���Ĵ���\n";
        return 0;
    }
    else if (BN_is_zero(C1x)) {
        cout << "����C1==0��\n";
        return 0;
    }
    else {
        cout << "*ͨ����*\n";
    }

    // T1 = inv(d1) * C1
    EC_POINT* T1 = EC_POINT_new(group);
    BN_mod_inverse(inv_d1, d1, n, ctx);
    EC_POINT_mul(group, T1, nullptr, C1, inv_d1, ctx);
    BN_free(inv_d1);

    // �����˷��� T1
    BIGNUM* T1x = BN_new();
    BIGNUM* T1y = BN_new();
    EC_POINT_get_affine_coordinates(group, T1, T1x, T1y, ctx);
    string T1_x = BN_bn2hex(T1x);
    string T1_y = BN_bn2hex(T1y);
    BN_free(T1x);
    BN_free(T1y);

    string T1_str = T1_x + T1_y;
    send(clientSocket, T1_str.c_str(), T1_str.size() + 1, 0);
    cout << ">�����˷���T1: (" << T1_x << " , " << T1_y << ")\n";


    ///////////////////////////////////////////////////////////////

    char input[256];
    // ���շ���˷�����T2
    ZeroMemory(input, sizeof(input));
    bytesReceived = recv(clientSocket, input, sizeof(input), 0);
    if (bytesReceived <= 0) {
        cout << "������������ӶϿ� Disconnect from server\n";
        return 0;
    }
    //���յ����ַ�������ת������
    string T2_str = input;
    string T2_x = T2_str.substr(0, 64);
    string T2_y = T2_str.substr(64, 64);
    BIGNUM* T2x = BN_new();
    BIGNUM* T2y = BN_new();
    BN_hex2bn(&T2x, T2_x.c_str());
    BN_hex2bn(&T2y, T2_y.c_str());
    EC_POINT* T2 = EC_POINT_new(group);
    EC_POINT_set_affine_coordinates(group, T2, T2x, T2y, ctx);
    cout << "<�յ����Է���˵�T2: (" << T2_x << " , " << T2_y << ")\n";

    ///////////////////////////////////////////////////////////////

    // 4.�ָ�����
    cout << "*��ʼ����...";


    // T2 - C1 = (x2, y2) = [inv(d1 * d2) - 1] * C1 = k * P
    EC_POINT* XY2 = EC_POINT_new(group);
    EC_POINT* invC1 = EC_POINT_new(group);
    EC_POINT_copy(invC1, C1); // �Ƚ� invC1 ��ʼ��Ϊ C1
    EC_POINT_invert(group, invC1, ctx); // ȡ�෴��
    EC_POINT_add(group, XY2, T2, invC1, ctx); // T2 - C1
    EC_POINT_free(invC1);

    // ��ȡ (x2, y2)
    BIGNUM* x2 = BN_new();
    BIGNUM* y2 = BN_new();
    EC_POINT_get_affine_coordinates(group, XY2, x2, y2, ctx);
    string x2_str = BN_bn2hex(x2);
    string y2_str = BN_bn2hex(y2);

    //�������ַ�����ʾ��16���ƣ���Ҫ����Ϊbit�ֽ���
    string c2;
    hex2bit(c2, C2_str);

    // t = KDF(x2||y2, meln)
    size_t mlen = c2.length();
    string t = HKDF(mlen, x2_str, y2_str);

    // M = C2 ^ t
    string M(mlen, 0x00);
    for (size_t i = 0; i < mlen; i++) {
        M[i] = c2[i] ^ t[i];
    }

    // u = Hash(x2||M||y2)
    string U = _sha256(x2_str + M + y2_str);
    
    //�жϣ�U==C3��
    if (U != C3_str)
    {
        cout << "ʧ�ܣ�U != C3\n";
    }
    else {
        cout << "�ɹ���\n<<<���������" << M << endl;
    }

    cout << "\n*2P���ܽ���*\n";
    cout << "///////////////////////////////////////////////////////////////\n\n";

    // �رտͻ����׽���
    closesocket(clientSocket);

    // �ͷ� Winsock ��Դ
    WSACleanup();

    return 0;
}
