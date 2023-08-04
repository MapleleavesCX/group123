

#include"sm2.h"
#include <WS2tcpip.h>  // ���� Windows ƽ̨��������ͷ�ļ�

#pragma comment(lib, "ws2_32.lib")  // ���ӵ� ws2_32.lib ���ļ�

int main() {

    printf("\n******* Trust Lssuer *******\n\n");

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

    //���ɱ��ع�˽Կ
    printf("�������ɱ��ع�˽Կ...");
    vector<string> P;
    string d;
    rfc6979_sm2_getKey(d, P);
    printf("�ɹ���\n");

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
            continue;
        }

        char clientIP[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &(clientAddress.sin_addr), clientIP, INET_ADDRSTRLEN);

        cout << "*�յ���������*\n������IP��ַ��" << clientIP << endl;  // ��ʾ������IP��ַ

        // �رռ����׽��֣���Ϊ����ֻ����һ���ͻ�������
        closesocket(listeningSocket);

        ///////////////////////////////////////////////////////////////

    

        char input[512];
        // ���տͻ��˷��������� ask
        ZeroMemory(input, sizeof(input));
        int bytesReceived = recv(clientSocket, input, sizeof(input), 0);
        if (bytesReceived <= 0) {
            cout << "�ͻ��˶Ͽ�����\n";
            continue;
        }

        string receive = input;
        string req = receive.substr(0, 3);

        if (req == "SIG") {

            uint8_t h = receive[3];
            uint8_t l = receive[4];

            uint32_t burn_year = h * 256 + l;
            cout << "���յ����õ��û��ĳ�����ݣ�" << burn_year << endl;

            if (burn_year <= 0 || burn_year >= 2100) {
                cout << "������ݳ��ޣ��޷����㣡\n";
                printf("*����\n\n");
                continue;
            }

            //������ַ�����ʾ��16���ƴ���256bit->64��
            string seed256 = rand256();

            //���� s = Hash0(seed��
            string s = _sha256(seed256);

            //���� k = 2100 - ������ݣ� Ȼ��ѭ��hash2  k ��
            uint32_t k = 2100 - burn_year;
            string c = s, t;
            for (uint32_t i = 0; i < k; i++) {
                t = _sm3(c);
                c = t;
            }

            //��Trust Issuer��˽ԿΪ c ǩ������
            vector<string> sig_c;
            rfc6979_sm2_sign(sig_c, c, d);

            //��ͻ��˷��� s �� c || sig_c
            string sendM = s + sig_c[0] + sig_c[1];
            send(clientSocket, sendM.c_str(), sendM.size() + 1, 0);
            cout << ">�������� " << clientIP << " �������ǩ��:\ns = " << s << "\nsign of c:(" << sig_c[0] << ", " << sig_c[1] << ")\n";

            printf("*����\n\n");
            continue;
        }
        else if (req == "ASK") {

            string sendM = P[0] + P[1];
            send(clientSocket, sendM.c_str(), sendM.size() + 1, 0);
            cout << ">�������� " << clientIP << " ���ͱ��ع�Կ:\nP = (" << P[0] << ", " << P[1] << ")\n";
            printf("*����\n\n");
            continue;
        }
        else {
            cout << "ָ��������󣡾ܾ����룡\n";
            string sendM = "Error";
            send(clientSocket, sendM.c_str(), sendM.size() + 1, 0);
            printf("*����\n\n");
            continue;
        }

    }
    WSACleanup();
    return 0;
}