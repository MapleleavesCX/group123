#include"sm2.h"
#include"aes128.h"

// ѡ�����еķ�����

//#define Server_PGP1
#define Server_PGP2


#ifdef Server_PGP1

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
        cerr << "ʧ�ܣ��޷���ʼ�� Winsock\n";
        return -1;
    }
    else {
        cout << "�ɹ�\n";
    }


    while (true) {

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

        
    PGP://PGPЭ�鿪ʼ------------------------------------------------------------------
        cout << "PGPЭ������\n";

        char input[256];
        // ���տͻ��˷����Ĺ�Կ
        ZeroMemory(input, sizeof(input));
        int bytesReceived = recv(clientSocket, input, sizeof(input), 0);
        if (bytesReceived <= 0) {
            cout << "�ͻ��˶Ͽ�����\n";
            continue;
        }
        
        //���յ����ַ�������ת������
        string input_ = input;
        vector<string> c_pk;
        c_pk.push_back(input_.substr(0, 64));
        c_pk.push_back(input_.substr(64, 64));
        cout << "<�յ����������� " << clientIP << " �Ĺ�Կ:(" << c_pk[0] << ", " << c_pk[1] << ")\n";
        
        //�����ع�Կת��Ϊһ���ַ���
        string s_pk = pk[0] + pk[1];

        // ��ͻ��˷��ͱ��ع�Կ
        send(clientSocket, s_pk.c_str(), s_pk.size() + 1, 0);
        cout << ">�������� " << clientIP << " ���ͱ��ع�Կ:(" << pk[0] << ", " << pk[1] << ")\n";

        cout << "*��Կ�����׶ν���*\n\n";

        // ��������ѭ��
        char buffer[4096];
        string userInput;

        while (true) {
            // ���տͻ��˷��͵���Ϣ
            cout << "�ȴ��Է�����...\n";
            ZeroMemory(buffer, sizeof(buffer));
            int bytesReceived = recv(clientSocket, buffer, sizeof(buffer), 0);
            if (bytesReceived <= 0) {
                cout << "�ͻ��˶Ͽ�����\n";
                break;
            }

            cout << "<���Կͻ��� " << clientIP << " ��ԭʼ����: " << buffer << endl;

            //��֤ǩ��
            string Buffer = buffer;
            vector<string> c_sign;
            c_sign.push_back(Buffer.substr(0, 64));
            c_sign.push_back(Buffer.substr(64, 64));
            string c_C = Buffer.substr(128, Buffer.length() - 128);

            if (rfc6979_sm2_verify(c_C, c_sign, c_pk)) {
                cout << "*ǩ��ͨ��*\n";
            }
            else {
                cout << "������ǩ��δͨ��������\n*���������Ͽ�����*\n";
                cout << "���ط�����Ѿܾ�" << clientIP << "����\n";
                break;
            }

            //������Ϣ
            string c_M;
            vector<string> clientC;
            clientC.push_back(c_C.substr(0, 128));
            clientC.push_back(c_C.substr(128, c_C.size() - 192));
            clientC.push_back(c_C.substr(c_C.size() - 64, 64));

            if (sm2_dec(c_M, sk, clientC))
            {
                cout << "*���ܳɹ���*\n";
                cout << "���Է�������ģ�" << c_M << "\n\n";
            }
            else
                cout << "����ʧ�ܣ�\n";


            // �ӿ���̨������Ϣ�����͸��ͻ���
            cout << ">>> ";
            getline(cin, userInput);

            if (userInput == "refuse") {
                cout << "���ط�����Ѿܾ�" << clientIP << "����\n";
                closesocket(clientSocket);
                break;
            }
            if (userInput == "quit") {
                cout << "���ط���˹ر�...\n";
                // �ͷ� Winsock ��Դ
                WSACleanup();
                return 0;
            }

            // sm2������Ϣ
            vector<string> c123;
            sm2_enc(c123, userInput, c_pk);
            string C = c123[0] + c123[1] + c123[2];

            //sm2����Ϣ����ǩ��
            vector<string> sign;
            rfc6979_sm2_sign(sign, C, sk);

            //ת��ǩ��
            string Sign = sign[0] + sign[1];

            string Sendmessage = Sign + C;

            int sendResult = send(clientSocket, Sendmessage.c_str(), Sendmessage.size() + 1, 0);
            if (sendResult == SOCKET_ERROR) {
                cerr << "�޷�������Ϣ���ͻ��� " << clientIP << "\n";
                break;
            }
            else {
                cout << ">�ѷ�������: " << Sendmessage << "\n\n";
            }
        }
    }

    return 0;
}

#endif


/////////////////////////////////////////////////////////////////////////////////////////

#ifdef Server_PGP2

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
        cerr << "ʧ�ܣ��޷���ʼ�� Winsock\n";
        return -1;
    }
    else {
        cout << "�ɹ�\n";
    }


    while (true) {

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


    PGP://PGPЭ�鿪ʼ------------------------------------------------------------------
        cout << "PGPЭ������\n";

        char input[256];
        // ���տͻ��˷����Ĺ�Կ
        ZeroMemory(input, sizeof(input));
        int bytesReceived = recv(clientSocket, input, sizeof(input), 0);
        if (bytesReceived <= 0) {
            cout << "�ͻ��˶Ͽ�����\n";
            continue;
        }

        //���յ����ַ�������ת������
        string input_ = input;
        cout << "<�յ����������� " << clientIP << " ������:" << input_ << "\n";

        //�����ع�Կת��Ϊһ���ַ���
        string s_pk = pk[0] + pk[1];

        // ��ͻ��˷��ͱ��ع�Կ
        send(clientSocket, s_pk.c_str(), s_pk.size() + 1, 0);
        cout << ">�������� " << clientIP << " ���ͱ��ع�Կ:(" << pk[0] << ", " << pk[1] << ")\n";

        char input2[1024];
        // ���տͻ��˷����ļ�����Ϣ-->���ܳ�˫���ĶԳ���Կ
        ZeroMemory(input2, sizeof(input2));
        int bytesReceived2 = recv(clientSocket, input2, sizeof(input2), 0);
        if (bytesReceived2 <= 0) {
            cout << "�ͻ��˶Ͽ�����\n";
            continue;
        }
        //���յ����ַ�������ת������
        string input2_ = input2;
        vector<string> c123;

        c123.push_back(input2_.substr(0, 128));
        c123.push_back(input2_.substr(128, input2_.size() - 192));
        c123.push_back(input2_.substr(input2_.size() - 64, 64));

        cout << "<�յ����������� " << clientIP << " ������:(" << c123[0] << ", " << c123[1] << ", " << c123[2] << ")\n";

        //˽Կ����
        string key_iv;
        string skey, iv;
        if (sm2_dec(key_iv, sk, c123))
        {
            cout << "*���ܳɹ���*\n";
            skey = key_iv.substr(0, 16);
            iv = key_iv.substr(16, 16);
            cout << "��ù����AES-128����Կ��" << skey << "\n";
            cout << "��ù����AES-128��iv��" << iv << "\n\n";
        }
        else
        {
            cout << "����ʧ�ܣ�Э����ֹ\n";
            continue;
        }

        cout << "*��Կ�����׶ν���*\n\n";

        // ��������ѭ��
        char buffer[4096];
        string userInput;

        while (true) {
            // ���տͻ��˷��͵���Ϣ
            cout << "�ȴ��Է�����...\n";
            ZeroMemory(buffer, sizeof(buffer));
            int bytesReceived = recv(clientSocket, buffer, sizeof(buffer), 0);
            if (bytesReceived <= 0) {
                cout << "�ͻ��˶Ͽ�����\n";
                break;
            }

            cout << "<���Կͻ��� " << clientIP << " ��ԭʼ����: " << buffer << endl;


            string c_C = buffer;

            //������Ϣ
            cout << "*���ڽ���...";
            string c_M;
            if (aes128(c_M, c_C, skey, iv, CTR_dec))
            {
                cout << "���ܳɹ���*\n";
                cout << "���Կͻ��� " << clientIP << " �����ģ�" << c_M << "\n\n";
            }
            else
                cout << "����ʧ�ܣ�\n";


            // �ӿ���̨������Ϣ�����͸��ͻ���
            cout << ">>> ";
            getline(cin, userInput);

            if (userInput == "refuse") {
                cout << "���ط�����Ѿܾ�" << clientIP << "����\n";
                closesocket(clientSocket);
                break;
            }
            if (userInput == "quit") {
                cout << "���ط���˹ر�...\n";
                // �ͷ� Winsock ��Դ
                WSACleanup();
                return 0;
            }

            // sm2������Ϣ
            string Sendmessage;
            aes128(Sendmessage, userInput, skey, iv, CTR_enc);

            int sendResult = send(clientSocket, Sendmessage.c_str(), Sendmessage.size() + 1, 0);
            if (sendResult == SOCKET_ERROR) {
                cerr << "�޷�������Ϣ���ͻ��� " << clientIP << "\n";
                break;
            }
            else {
                cout << ">�ѷ�������: " << Sendmessage << "\n\n";
            }
        }
    }

    return 0;
}

#endif