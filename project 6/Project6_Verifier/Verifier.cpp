

#include"sm2.h"
#include <WS2tcpip.h>  // ���� Windows ƽ̨��������ͷ�ļ�

#pragma comment(lib, "ws2_32.lib")  // ���ӵ� ws2_32.lib ���ļ�

int main() {

    printf("\n******* Verifier *******\n\n");

    //////////////////////���������趨�����޸ģ�//////////////////////

    string Trusted_Issuer_ADDR = "192.168.1.5";//���ŵ�������IP��ַ

    ///////////////////////////////////////////////////////////////



    // ��ʼ�� Winsock
    cout << "*���ڳ�ʼ�� Winsock...";
    WSADATA wsData;
    WORD version = MAKEWORD(2, 2);
    int wsResult = WSAStartup(version, &wsData);
    if (wsResult != 0) {
        cerr << "ʧ�ܣ��޷���ʼ�� Winsock\n";
        return 0;
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
        return 0;
    }
    else {
        cout << "�ɹ�\n";
    }

    // ���ӵ� Trusted Issuer ����ˣ� �˴�Ҫ�����Ӧ�ĵ�ַ
    
    cout << "*�������ӵ� Trusted Issuer �����:" << Trusted_Issuer_ADDR << endl;

    cout << "*�������ӷ�����...";
    sockaddr_in serverAddress;
    serverAddress.sin_family = AF_INET;
    serverAddress.sin_port = htons(8080);  // ʹ�÷������Ķ˿ں�
    inet_pton(AF_INET, Trusted_Issuer_ADDR.c_str(), &(serverAddress.sin_addr));
    if (connect(clientSocket, (sockaddr*)&serverAddress, sizeof(serverAddress)) == SOCKET_ERROR) {
        cerr << "ʧ�ܣ��޷����ӵ������� Unable to connect to server \n";
        closesocket(clientSocket);
        WSACleanup();
        return 0;
    }
    else {
        cout << "�ɹ�\n";
    }

    string req2 = "ASK";
    send(clientSocket, req2.c_str(), req2.size() + 1, 0);
    cout << ">�� Trusted Issuer ����Կ\n";

    printf("�ȴ� Trusted Issuer �ظ�...");

    char input1[512];
    // ���շ���˷����Ĺ�Կ
    ZeroMemory(input1, sizeof(input1));
    int bytesReceived1 = recv(clientSocket, input1, sizeof(input1), 0);
    if (bytesReceived1 <= 0) {
        cout << "����������������ӶϿ� Disconnect from server\n";
        closesocket(clientSocket);
        WSACleanup();
        return 0;
    }
    else
    {
        cout << "�ɹ��յ����� " << Trusted_Issuer_ADDR << " �Ļظ���\n";
    }

    //������ Trusted Issuer ��ͨ��
    closesocket(clientSocket);
    //WSACleanup();

    //���յ����ַ�������ת������
    string input_1 = input1;
    if (input_1 == "Error") {
        cout << "������Ϣ��" << input_1 << "\n��Ϣ��Ч��\n";
        printf("*����\n\n");
        return 0;
    }

    vector<string> P;
    P.push_back(input_1.substr(0, 64));
    P.push_back(input_1.substr(64, 64));

    cout << "<���յ����� Trusted Issuer �Ĺ�Կ��\nP = (" << P[0] << ", " << P[1] << ")\n";

    cout << "*���\n\n";

    ///////////////////////////////////////////////////////////////
    string chose;
    cout << "��������֤�߷������������\n";
    while(true){
        getline(cin, chose);
        if (chose == "go") {
            break;
        }
        else {
            cout << "*�������������\n";
        }
    }

    cout << "*��֤�߱��ط���������\n";

    while (true) {

        

        // ��ʼ�� Winsock
        cout << "*���ڳ�ʼ�� Winsock...";
        WSADATA wsData2;
        WORD version2 = MAKEWORD(2, 2);
        int wsResult2 = WSAStartup(version2, &wsData2);
        if (wsResult2 != 0) {
            cerr << "ʧ�ܣ��޷���ʼ�� Winsock\n";
            return 0;
        }
        else {
            cout << "�ɹ�\n";
        }

        // �������������׽���
        cout << "*���ڴ����׽���...";
        SOCKET listeningSocket = socket(AF_INET, SOCK_STREAM, 0);
        if (listeningSocket == INVALID_SOCKET) {
            cerr << "ʧ�ܣ��޷������׽���\n";
            WSACleanup();
            return 0;
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
            return 0;
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
            return 0;
        }

        // �ȴ��ͻ�������
        sockaddr_in clientAddress;
        int clientAddressSize = sizeof(clientAddress);
        SOCKET clientSocket = accept(listeningSocket, (sockaddr*)&clientAddress, &clientAddressSize);
        if (clientSocket == INVALID_SOCKET) {
            cerr << "�޷����ܿͻ�������\n";
            closesocket(listeningSocket);
            WSACleanup();
            return 0;
        }

        char clientIP[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &(clientAddress.sin_addr), clientIP, INET_ADDRSTRLEN);

        cout << "*�յ���������*\n������IP��ַ��" << clientIP << endl;  // ��ʾ������IP��ַ

        // �رռ����׽��֣���Ϊ����ֻ����һ���ͻ�������
        closesocket(listeningSocket);

        ///////////////////////////////////////////////////////////////

        

        char input[512];
        // ���տͻ��˷�������Ϣ
        ZeroMemory(input, sizeof(input));
        int bytesReceived = recv(clientSocket, input, sizeof(input), 0);
        if (bytesReceived <= 0) {
            cout << "�ͻ��˶Ͽ�����\n";
            continue;
        }

        //���յ����ַ�������ת������
        string input_ = input;
        string req = input_.substr(0, 3);
        
        
        cout << "<�յ����������� " << clientIP << " ������" << req << endl;

        if (req == "PRO") {

            cout << "��ʼ��֤��\n";

            string yy = input_.substr(3, 2);
            uint8_t h = input_[3];
            uint8_t l = input_[4];
            uint32_t yyproof = h * 256 + l;

            string p = input_.substr(5, 64);
            vector<string> sig_c;
            sig_c.push_back(input_.substr(69, 64));
            sig_c.push_back(input_.substr(133, 64));

            cout << "<������Ϣ��\np = " << p << "\nsig_c = (" << sig_c[0] << ", " << sig_c[1] << ")\n";
            cout << "������ݣ�" << yyproof << endl;
            

            //���� d1 = 2100 - yyproof, ���� c' = (Hash1(p))^d1
            cout << "���㣺 d1 = 2100 - yyproof, ���� c' = (Hash1(p))^d1\n";
            uint32_t d1 = 2100 - yyproof;
            string c_ = p, t;
            if (d1 <= 0) {
                cout << "���󣡽���֤������ݳ���2100�꣡\n";
                string sendM = "Error";
                send(clientSocket, sendM.c_str(), sendM.size() + 1, 0);
                continue;
            }
            for (uint32_t i = 0; i < d1; i++) {
                t = _sm3(c_);
                c_ = t;
            }
            cout << "*��������������� ��c' = " << c_ << endl;

            //��֤ǩ��
            cout << "*��֤��sig_c�Ƿ�Ϊ c' ��ǩ��:";

            string verify;

            if (rfc6979_sm2_verify(c_, sig_c, P)) {
                verify = "yes";
            }
            else {
                verify = "no";
            }
            cout << verify << endl;


            //���ͽ��
            send(clientSocket, verify.c_str(), verify.size() + 1, 0);
            printf("*����\n\n");
            continue;
        }
        else {
            cout << "ָ��������󣡾ܾ����룡\n";
            string sendM = "Error";
            send(clientSocket, sendM.c_str(), sendM.size() + 1, 0);
            continue;
        }
    }
    WSACleanup();
    return 0;
}