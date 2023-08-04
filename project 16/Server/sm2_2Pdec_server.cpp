
#include"sm2.h"
#include <WS2tcpip.h>  // ���� Windows ƽ̨��������ͷ�ļ�

#pragma comment(lib, "ws2_32.lib")  // ���ӵ� ws2_32.lib ���ļ�

int main() {

    // ��ʼ�� Winsock
    cout << "*���ڳ�ʼ�� Winsock...";
    WSADATA wsData;
    WORD version = MAKEWORD(2, 2);
    int wsResult = WSAStartup(version, &wsData);
    if (wsResult != 0) {
        cerr << "ʧ�ܣ��޷���ʼ�� Winsock\n";
        return -1;
    }
    else {
        cout << "�ɹ�\n";
    }


    while (true) {

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


        // �������������׽���
        cout << "*���ڴ����׽���...";
        SOCKET listeningSocket = socket(AF_INET, SOCK_STREAM, 0);
        if (listeningSocket == INVALID_SOCKET) {
            cerr << "ʧ�ܣ��޷������׽���\n";
            WSACleanup();
            return -1;
        }
        else {
            cout << "�ɹ�\n";
        }

        // �󶨷�������ַ�Ͷ˿�
        cout << "*���ڰ��׽���...";
        sockaddr_in serverAddress;
        serverAddress.sin_family = AF_INET;
        serverAddress.sin_port = htons(8080);  // ʹ��ָ���Ķ˿ں�
        serverAddress.sin_addr.s_addr = INADDR_ANY;

        if (bind(listeningSocket, (sockaddr*)&serverAddress, sizeof(serverAddress)) == SOCKET_ERROR) {
            cerr << "ʧ�ܣ��޷����׽���\n";
            closesocket(listeningSocket);
            WSACleanup();
            return -1;
        }
        else {
            cout << "�ɹ�\n";
        }

        // ��ʼ������������
        cout << "��ʼ����...\n";

        if (listen(listeningSocket, SOMAXCONN) == SOCKET_ERROR) {
            cerr << "����ʧ��\n";
            closesocket(listeningSocket);
            WSACleanup();
            return -1;
        }

        // �ȴ��ͻ�������
        sockaddr_in clientAddress;
        int clientAddressSize = sizeof(clientAddress);
        SOCKET clientSocket = accept(listeningSocket, (sockaddr*)&clientAddress, &clientAddressSize);
        if (clientSocket == INVALID_SOCKET) {
            cerr << "�޷����ܿͻ�������\n";
            closesocket(listeningSocket);
            WSACleanup();
            return -1;
        }

        char clientIP[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &(clientAddress.sin_addr), clientIP, INET_ADDRSTRLEN);

        cout << "*�յ���������*\n������IP��ַ��" << clientIP << endl;  // ��ʾ������IP��ַ

        // �رռ����׽��֣���Ϊ����ֻ����һ���ͻ�������
        closesocket(listeningSocket);

        ///////////////////////////////////////////////////////////////

    enc2P://2P����Э�鿪ʼ------------------------------------------------------------------
        cout << "\n\n///////////////////////////////////////////////////////////////\n";
        cout << "*2P����Э������*\n";

        // 1.������˽Կ d2  ---------------------------- 
        BIGNUM* one = BN_new();
        BIGNUM* d2 = BN_new();
        string ur1 = rand256();//���ɷ�ȷ���������;
        string ur2 = rand256();
        BN_set_word(one, 1);
        string d2_str = hmac_prbg(ur1, ur2, one, n);//d2 = [1, n)
        BN_hex2bn(&d2, d2_str.c_str());//��ֵ˽Կ d2

        char input[256];
        // ���տͻ��˷����� P1
        ZeroMemory(input, sizeof(input));
        int bytesReceived = recv(clientSocket, input, sizeof(input), 0);
        if (bytesReceived <= 0) {
            cout << "�ͻ��˶Ͽ�����\n";
            continue;
        }

        //���յ����ַ�������ת������
        string P1_str = input;
        string P1x = P1_str.substr(0, 64);
        string P1y = P1_str.substr(64, 64);
        BIGNUM* P1_x = BN_new();
        BIGNUM* P1_y = BN_new();
        BN_hex2bn(&P1_x, P1x.c_str());
        BN_hex2bn(&P1_y, P1y.c_str());
        EC_POINT* P1 = EC_POINT_new(group);
        EC_POINT_set_affine_coordinates(group, P1, P1_x, P1_y, ctx);
        cout << "<�յ����������� " << clientIP << " ��P1:(" << P1x << ", " << P1y << ")\n";

        ///////////////////////////////////////////////////////////////

        // 2.���ɹ���Կ P = inv(d2) * P1 - G 
        EC_POINT* P = EC_POINT_new(group);

        EC_POINT* temp = EC_POINT_new(group);
        BIGNUM* inv_d2 = BN_new();
        BN_mod_inverse(inv_d2, d2, n, ctx);
        EC_POINT_mul(group, temp, nullptr, P1, inv_d2, ctx);

        EC_POINT* invG = EC_POINT_new(group);
        EC_POINT_copy(invG, G); // �Ƚ� invG ��ʼ��Ϊ G
        EC_POINT_invert(group, invG, ctx); // ȡ�෴��
        EC_POINT_add(group, P, temp, invG, ctx);

        EC_POINT_free(temp);
        EC_POINT_free(invG);

        // ����Կ��ӡ����
        BIGNUM* Px = BN_new();
        BIGNUM* Py = BN_new();
        EC_POINT_get_affine_coordinates(group, P, Px, Py, ctx);
        string P_x = BN_bn2hex(Px);
        string P_y = BN_bn2hex(Py);

        cout << "\n****���ɹ���Կ P = (" << P_x << " , " << P_y << ")\n\n";

        BN_free(Px);
        BN_free(Py);

        /////////////////////////////////////////////////////////////////////

        
        // �ӿ���̨�����ǩ������Ϣ message
        string message;
        cout << "������ �����ܵ���Ϣ��\n";
        cout << ">>> ";
        getline(cin, message);
        string Z = "{id of myself.}:";
        string M = Z + message;

        vector<string> PK;
        PK.push_back(P_x);
        PK.push_back(P_y);

        //��������
        vector<string> C;
        sm2_enc(C, M, PK);

        //��������
        string CC = C[0] + C[1] + C[2];
        send(clientSocket, CC.c_str(), CC.size() + 1, 0);
        cout << ">�������� " << clientIP << " ��������: " << CC << "\n";

        cout << "\n*2P���ܽ���*\n";


    dec2P://2P����Э�鿪ʼ------------------------------------------------------------------
        cout << "///////////////////////////////////////////////////////////////\n";
        cout << "*2P����Э������*\n";


        char input2[256];
        // ���տͻ��˷����� T1
        ZeroMemory(input2, sizeof(input2));
        bytesReceived = recv(clientSocket, input2, sizeof(input2), 0);
        if (bytesReceived <= 0) {
            cout << "�ͻ��˶Ͽ�����\n";
            continue;
        }

        //���յ����ַ�������ת������
        string T1_str = input2;
        string T1x = T1_str.substr(0, 64);
        string T1y = T1_str.substr(64, 64);
        BIGNUM* T1_x = BN_new();
        BIGNUM* T1_y = BN_new();
        BN_hex2bn(&T1_x, T1x.c_str());
        BN_hex2bn(&T1_y, T1y.c_str());
        EC_POINT* T1 = EC_POINT_new(group);
        EC_POINT_set_affine_coordinates(group, T1, T1_x, T1_y, ctx);
        cout << "<�յ����������� " << clientIP << " ��T1: (" << T1x << ", " << T1y << ")\n";

        ///////////////////////////////////////////////////////////////

        // 3.���� T2 = inv(d2) * T1
        EC_POINT* T2 = EC_POINT_new(group);
        BN_mod_inverse(inv_d2, d2, n, ctx);
        EC_POINT_mul(group, T2, nullptr, T1, inv_d2, ctx);
        BN_free(inv_d2);

        // ׼������T2
        BIGNUM* T2_x = BN_new();
        BIGNUM* T2_y = BN_new();
        EC_POINT_get_affine_coordinates(group, T2, T2_x, T2_y, ctx);
        string T2x = BN_bn2hex(T2_x);
        string T2y = BN_bn2hex(T2_y);
        BN_free(T2_x);
        BN_free(T2_y);

        // ��ͻ��˷��� T2
        string T2_str = T2x + T2y;
        send(clientSocket, T2_str.c_str(), T2_str.size() + 1, 0);
        cout << ">�������� " << clientIP << " ����T2: (" << T2x << ", " << T2y << ")\n";


        /////////////////////////////////////////////////////////////////////

        cout << "\n*2P���ܽ���*\n";
        cout << "///////////////////////////////////////////////////////////////\n\n";


    }

    return 0;
}