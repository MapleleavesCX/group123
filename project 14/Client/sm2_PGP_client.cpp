#include"aes128.h"
#include"sm2.h"

/////////////////��Ҫ��������������IP��ַ///////////////////////
string serverIP = "192.168.1.5";
//////////////////////////////////////////////////////////////

// ѡ�����еķ�����

//#define Client_PGP1
#define Client_PGP2

#ifdef Client_PGP1

#include <WS2tcpip.h>  // ���� Windows ƽ̨��������ͷ�ļ�

#pragma comment(lib, "ws2_32.lib")  // ���ӵ� ws2_32.lib ���ļ�

int main() {

    //����sm2��Կ����
    string sk;
    vector<string> pk;
    rfc6979_sm2_getKey(sk, pk);
    cout << "*����sm2��Կ����*\n";

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

PGP://PGPЭ�鿪ʼ------------------------------------------------------------------
    cout << "PGPЭ������\n";
    

    //�����ع�Կת��Ϊһ���ַ���
    string c_pk = pk[0] + pk[1];

    // �����˷��ͱ��ع�Կ
    send(clientSocket, c_pk.c_str(), c_pk.size() + 1, 0);
    cout << ">�����˷��ͱ��ع�Կ:(" << pk[0] << ", " << pk[1] << ")\n";

    char input[256];
    // ���շ���˷����Ĺ�Կ
    ZeroMemory(input, sizeof(input));
    int bytesReceived = recv(clientSocket, input, sizeof(input), 0);
    if (bytesReceived <= 0) {
        cout << "������������ӶϿ� Disconnect from server\n";
        return 0;
    }

    //���յ����ַ�������ת������
    string input_ = input;
    vector<string> s_pk;
    s_pk.push_back(input_.substr(0, 64));
    s_pk.push_back(input_.substr(64, 64));
    cout << "<�յ����Է���˵Ĺ�Կ:(" << s_pk[0] << ", " << s_pk[1] << ")\n";

    
    cout << "*��Կ�����׶ν���*\n\n";



    // ��������ѭ��
    char buffer[4096];
    string userInput;

    // ���պͷ�����Ϣ
    while (true) {
        // �ӿ���̨������Ϣ�����͸�������
        cout << ">>> ";
        getline(cin, userInput);

        if (userInput == "quit") {
            cout << "�˳����ؿͻ���... Exit Local Client...\n";
            break;
        }

        // sm2������Ϣ
        vector<string> c123;
        sm2_enc(c123, userInput, s_pk);
        string C = c123[0] + c123[1] + c123[2];

        //sm2����Ϣǩ��
        vector<string> sign;
        rfc6979_sm2_sign(sign, C, sk);

        //ת��ǩ��
        string Sign = sign[0] + sign[1];

        string Sendmessage = Sign + C;


        int sendResult = send(clientSocket, Sendmessage.c_str(), Sendmessage.size() + 1, 0);
        if (sendResult == SOCKET_ERROR) {
            cerr << "�޷�������Ϣ�������� Unable to send message to server" << endl;
            break;
        }
        else {
            cout << ">�ѷ�������: " << Sendmessage << "\n\n";
        }

        // ���շ��������ص���Ϣ
        cout << "�ȴ��Է�����...\n";
        ZeroMemory(buffer, sizeof(buffer));
        int bytesReceived = recv(clientSocket, buffer, sizeof(buffer), 0);
        if (bytesReceived <= 0) {
            cerr << "������������ӶϿ� Disconnect from server" << endl;
            break;
        }

        cout << "���Է����� Server ��ԭʼ����: " << buffer << endl;

        //��֤ǩ��
        string Buffer = buffer;
        vector<string> s_sign;
        s_sign.push_back(Buffer.substr(0, 64));
        s_sign.push_back(Buffer.substr(64, 64));
        string s_C = Buffer.substr(128, Buffer.length() - 128);

        if (rfc6979_sm2_verify(s_C, s_sign, s_pk)) {
            cout << "*ǩ��ͨ��*\n";
        }
        else {
            cout << "������ǩ��δͨ��������\n*���������Ͽ�����*\n";
            cout << "���˳����ؿͻ���... Exit Local Client...\n";
            break;
        }

        //������Ϣ
        string s_M;
        vector<string> serverC;
        serverC.push_back(s_C.substr(0, 128));
        serverC.push_back(s_C.substr(128, s_C.size() - 192));
        serverC.push_back(s_C.substr(s_C.size() - 64, 64));

        if (sm2_dec(s_M, sk, serverC))
        {
            cout << "*���ܳɹ���*\n";
            cout << "���Է�������ģ�" << s_M << "\n\n";
        }
        else
            cout << "����ʧ�ܣ�\n";
    }

    // �رտͻ����׽���
    closesocket(clientSocket);

    // �ͷ� Winsock ��Դ
    WSACleanup();

    return 0;
}

#endif

////////////////////////////////////////////////////////////////////////////////////////

#ifdef Client_PGP2

#include <WS2tcpip.h>  // ���� Windows ƽ̨��������ͷ�ļ�

#pragma comment(lib, "ws2_32.lib")  // ���ӵ� ws2_32.lib ���ļ�

int main() {

    //����AES��Կ����
    
    // ʹ������豸��Ϊ����
    random_device rd;
    // ʹ�� Mersenne Twister ����
    mt19937 gen(rd());
    // ����һ����Χ�� 0 �� 255�����������������
    uniform_int_distribution<> dis(0, 255);

    string SymmetricKey, iv;
    for (uint32_t i = 0; i < 16; i++) {
        uint8_t r = (uint8_t)dis(gen);
        SymmetricKey.push_back(r);
    }
    for (uint32_t i = 0; i < 16; i++) {
        uint8_t r = (uint8_t)dis(gen);
        iv.push_back(r);
    }

    string key_iv = SymmetricKey + iv;
    cout << "*����AES-128 ��Կ+iv ����*\n";

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

PGP://PGPЭ�鿪ʼ------------------------------------------------------------------
    cout << "PGPЭ������\n";


    // �����˷���PGP����
    string req = "PGP";
    send(clientSocket, req.c_str(), req.size() + 1, 0);
    cout << ">�����˷���PGP����\n";

    char input[256];
    // ���շ���˷����Ĺ�Կ
    ZeroMemory(input, sizeof(input));
    int bytesReceived = recv(clientSocket, input, sizeof(input), 0);
    if (bytesReceived <= 0) {
        cout << "������������ӶϿ� Disconnect from server\n";
        return 0;
    }

    //���յ����ַ�������ת������
    string input_ = input;
    vector<string> s_pk;
    s_pk.push_back(input_.substr(0, 64));
    s_pk.push_back(input_.substr(64, 64));
    cout << "<�յ����Է���˵Ĺ�Կ:(" << s_pk[0] << ", " << s_pk[1] << ")\n";

    
    vector<string> c123;
    sm2_enc(c123, key_iv, s_pk);
    
    // �����˷�����sm2���ܹ���AES��Կ��IV
    string c1c2c3 = c123[0] + c123[1] + c123[2];
    send(clientSocket, c1c2c3.c_str(), c1c2c3.size() + 1, 0);
    cout << ">�����˷��ͼ��ܺ��AES��Կ��IV��\n c1 = " << c123[0] << "\n c2 = " << c123[1] << "\n c3 = " << c123[2] << endl;
    cout << "c123:" << c1c2c3 << endl;

    cout << "*��Կ�����׶ν���*\n\n";



    // ��������ѭ��
    char buffer[4096];
    string userInput;

    // ���պͷ�����Ϣ
    while (true) {
        // �ӿ���̨������Ϣ�����͸�������
        cout << ">>> ";
        getline(cin, userInput);

        if (userInput == "quit") {
            cout << "�˳����ؿͻ���... Exit Local Client...\n";
            break;
        }

        //AES����
        string Sendmessage;
        aes128(Sendmessage, userInput, SymmetricKey, iv, CTR_enc);

        int sendResult = send(clientSocket, Sendmessage.c_str(), Sendmessage.size() + 1, 0);
        if (sendResult == SOCKET_ERROR) {
            cerr << "�޷�������Ϣ�������� Unable to send message to server" << endl;
            break;
        }
        else {
            cout << ">�ѷ�������: " << Sendmessage << "\n\n";
        }

        // ���շ��������ص���Ϣ
        cout << "�ȴ��Է�����...\n";
        ZeroMemory(buffer, sizeof(buffer));
        int bytesReceived = recv(clientSocket, buffer, sizeof(buffer), 0);
        if (bytesReceived <= 0) {
            cerr << "������������ӶϿ� Disconnect from server" << endl;
            break;
        }

        cout << "���Է����� Server ��ԭʼ����: " << buffer << endl;


        //������Ϣ
        string s_M;
        string serverC = buffer;
        cout << "*���ڽ���...";
        if (aes128(s_M, serverC, SymmetricKey, iv, CTR_dec))
        {
            cout << "���ܳɹ���*\n";
            cout << "���Է�������ģ�" << s_M << "\n\n";
        }
        else
            cout << "����ʧ�ܣ�\n";
    }

    // �رտͻ����׽���
    closesocket(clientSocket);

    // �ͷ� Winsock ��Դ
    WSACleanup();

    return 0;
}

#endif