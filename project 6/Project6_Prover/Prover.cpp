
#include"sm2.h"
#include <WS2tcpip.h>  // ���� Windows ƽ̨��������ͷ�ļ�

#pragma comment(lib, "ws2_32.lib")  // ���ӵ� ws2_32.lib ���ļ�

int main() {

    printf("\n******* Prover *******\n\n");

    //////////////////////���������趨�����޸ģ�//////////////////////
    uint32_t burn_year = 1978;//�趨֤���ߵĳ������
    string Trusted_Issuer_ADDR = "192.168.1.5";//���ŵ�������IP��ַ
    string Verifier_ADDR = "192.168.1.5";//��֤����IP��ַ
    ///////////////////////////////////////////////////////////////

    cout << "֤���߳�ʼ�趨�ĳ�����ݣ�" << burn_year << endl;


    // ��ʼ�� Winsock
    cout << "*���ڳ�ʼ�� Winsock...";
    WSADATA wsData;
    WORD version = MAKEWORD(2, 2);
    int wsResult = WSAStartup(version, &wsData);
    if (wsResult != 0) {
        cerr << "ʧ�ܣ��޷���ʼ�� Winsock  Unable to initialize Winsock\n";
        return 0;
    }
    else {
        cout << "�ɹ�\n";
    }

    // �����ͻ����׽���
    cout << "*���ڴ����׽���...";
    SOCKET clientSocket1 = socket(AF_INET, SOCK_STREAM, 0);
    if (clientSocket1 == INVALID_SOCKET) {
        cerr << "ʧ�ܣ��޷������׽��� Unable to create socket\n";
        WSACleanup();
        return 0;;
    }
    else {
        cout << "�ɹ�\n";
    }


    // ���ӵ� Trusted Issuer ����ˣ� �˴�Ҫ�����Ӧ�ĵ�ַ
    
    cout << "*�������ӵ� Trusted Issuer �����:" << Trusted_Issuer_ADDR << endl;

    cout << "*�������ӷ�����...";
    sockaddr_in serverAddress1;
    serverAddress1.sin_family = AF_INET;
    serverAddress1.sin_port = htons(8080);  // ʹ�÷������Ķ˿ں�
    inet_pton(AF_INET, Trusted_Issuer_ADDR.c_str(), &(serverAddress1.sin_addr));
    if (connect(clientSocket1, (sockaddr*)&serverAddress1, sizeof(serverAddress1)) == SOCKET_ERROR) {
        cerr << "ʧ�ܣ��޷����ӵ������� Unable to connect to server \n";
        closesocket(clientSocket1);
        WSACleanup();
        return 0;
    }
    else {
        cout << "�ɹ�\n";
    }

    string burn(2, 0x00);
    burn[0] = burn_year / 256;
    burn[1] = burn_year % 256;

    string req1 = "SIG" + burn;
    send(clientSocket1, req1.c_str(), req1.size() + 1, 0);
    cout << ">�� Trusted Issuer ����ǩ��\n";

    printf("�ȴ� Trusted Issuer �ظ�...");

    char input1[512];
    // ���շ���˷����Ĺ�Կ
    ZeroMemory(input1, sizeof(input1));
    int bytesReceived1 = recv(clientSocket1, input1, sizeof(input1), 0);
    if (bytesReceived1 <= 0) {
        cout << "����������������ӶϿ� Disconnect from server\n";
        closesocket(clientSocket1);
        WSACleanup();
        return 0;
    }
    else
    {
        cout << "�ɹ��յ����� Trusted Issuer:" << Trusted_Issuer_ADDR << " �Ļظ���\n";
    }

    //������ Trusted Issuer ��ͨ��
    closesocket(clientSocket1);

    ///////////////////////////////////////////////////////////////

    string input1_ = input1;
    string s = input1_.substr(0, 64);
    string sig_c = input1_.substr(64, 128);

   
    cout << "<���յ����� Trusted Issuer ����Ϣ��\ns = " << s << "\nsig_c = " << sig_c << "\n";

    //�趨һ����ݣ�Ĭ��Ϊ2000��
    uint32_t yyproof = 2000;

    while(true){
        cout << ">����������֤�������(1900 < y < 2100)��";
        cin >> yyproof;

        cout << "*������...";

        if (yyproof <= burn_year || yyproof >= 2100) {
            cout << "������ݳ��ޣ��޷����㣡\n";
            printf("*������\n");
            continue;
        }
        else {
            break;
        }
    }

    cout << "���㣺d0 = yyproof - burn_year, p = (Hash1(s))^d0\n";
    // d0 = yyproof - burn_year, p = (Hash1(s))^d0
    uint32_t d0 = yyproof - burn_year;
    string p = s, t;
    for (uint32_t i = 0; i < d0; i++) {
        t = _sm3(p);
        p = t;
    }

    cout << "*��ϣ�\n\n";

    ///////////////////////////////////////////////////////////////

    cout << "*׼������֤�߷�������������...\n";


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
    
    cout << "*�������ӵ� Verifier �����:" << Verifier_ADDR << endl;

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

    ///////////////////////////////////////////////////////////////

    string time(2, 0x00);
    time[0] = yyproof / 256;
    time[1] = yyproof % 256;

    string req2 = "PRO" + time + p + sig_c;
    send(clientSocket, req2.c_str(), req2.size() + 1, 0);
    cout << ">�� Verifier ������֤����\n";
    cout << " ----��֤�������£�\n  ��֤ʹ����� = " << yyproof << "\n  p = " << p << "\n  sig_c = " << sig_c << endl;

    printf("�ȴ� Verifier �ظ�...");

    char input[512];
    // ���շ���˷����Ĺ�Կ
    ZeroMemory(input, sizeof(input));
    int bytesReceived = recv(clientSocket, input, sizeof(input), 0);
    if (bytesReceived <= 0) {
        cout << "����������������ӶϿ� Disconnect from server\n";
        closesocket(clientSocket);
        WSACleanup();
        return 0;
    }
    else
    {
        cout << "�ɹ��յ����� Verifier:" << Verifier_ADDR << " �Ļظ���\n";
    }

    //������ Trusted Issuer ��ͨ��
    closesocket(clientSocket);

    //���յ����ַ�������ת������
    string input_ = input;
    if (input_ == "yes") {
        cout << "������Ϣ��" << input_ << "\n��֤�ɹ���\n";
        printf("*����\n\n");
    }
    else if (input_ == "no") {
        cout << "������Ϣ��" << input_ << "\n��֤ʧ�ܣ�\n";
        printf("*����\n\n");
    }
    else{
        cout << "������Ϣ��" << input_ << "\n��Ϣ��Ч��\n";
        printf("*����\n\n");
    }

    // �ͷ� Winsock ��Դ
    WSACleanup();

    return 0;
}
