
#include"sm2.h"
#include <WS2tcpip.h>  // 包含 Windows 平台的网络编程头文件

#pragma comment(lib, "ws2_32.lib")  // 链接到 ws2_32.lib 库文件

int main() {

    printf("\n******* Prover *******\n\n");

    //////////////////////基础参数设定（可修改）//////////////////////
    uint32_t burn_year = 1978;//设定证明者的出生年份
    string Trusted_Issuer_ADDR = "192.168.1.5";//可信第三方的IP地址
    string Verifier_ADDR = "192.168.1.5";//验证方的IP地址
    ///////////////////////////////////////////////////////////////

    cout << "证明者初始设定的出生年份：" << burn_year << endl;


    // 初始化 Winsock
    cout << "*正在初始化 Winsock...";
    WSADATA wsData;
    WORD version = MAKEWORD(2, 2);
    int wsResult = WSAStartup(version, &wsData);
    if (wsResult != 0) {
        cerr << "失败！无法初始化 Winsock  Unable to initialize Winsock\n";
        return 0;
    }
    else {
        cout << "成功\n";
    }

    // 创建客户端套接字
    cout << "*正在创建套接字...";
    SOCKET clientSocket1 = socket(AF_INET, SOCK_STREAM, 0);
    if (clientSocket1 == INVALID_SOCKET) {
        cerr << "失败！无法创建套接字 Unable to create socket\n";
        WSACleanup();
        return 0;;
    }
    else {
        cout << "成功\n";
    }


    // 连接到 Trusted Issuer 服务端， 此处要输入对应的地址
    
    cout << "*请求连接到 Trusted Issuer 服务端:" << Trusted_Issuer_ADDR << endl;

    cout << "*正在连接服务器...";
    sockaddr_in serverAddress1;
    serverAddress1.sin_family = AF_INET;
    serverAddress1.sin_port = htons(8080);  // 使用服务器的端口号
    inet_pton(AF_INET, Trusted_Issuer_ADDR.c_str(), &(serverAddress1.sin_addr));
    if (connect(clientSocket1, (sockaddr*)&serverAddress1, sizeof(serverAddress1)) == SOCKET_ERROR) {
        cerr << "失败！无法连接到服务器 Unable to connect to server \n";
        closesocket(clientSocket1);
        WSACleanup();
        return 0;
    }
    else {
        cout << "成功\n";
    }

    string burn(2, 0x00);
    burn[0] = burn_year / 256;
    burn[1] = burn_year % 256;

    string req1 = "SIG" + burn;
    send(clientSocket1, req1.c_str(), req1.size() + 1, 0);
    cout << ">向 Trusted Issuer 请求签名\n";

    printf("等待 Trusted Issuer 回复...");

    char input1[512];
    // 接收服务端发来的公钥
    ZeroMemory(input1, sizeof(input1));
    int bytesReceived1 = recv(clientSocket1, input1, sizeof(input1), 0);
    if (bytesReceived1 <= 0) {
        cout << "错误！与服务器的连接断开 Disconnect from server\n";
        closesocket(clientSocket1);
        WSACleanup();
        return 0;
    }
    else
    {
        cout << "成功收到来自 Trusted Issuer:" << Trusted_Issuer_ADDR << " 的回复！\n";
    }

    //结束与 Trusted Issuer 的通信
    closesocket(clientSocket1);

    ///////////////////////////////////////////////////////////////

    string input1_ = input1;
    string s = input1_.substr(0, 64);
    string sig_c = input1_.substr(64, 128);

   
    cout << "<接收到来自 Trusted Issuer 的信息：\ns = " << s << "\nsig_c = " << sig_c << "\n";

    //设定一个年份，默认为2000；
    uint32_t yyproof = 2000;

    while(true){
        cout << ">请输入用于证明的年份(1900 < y < 2100)：";
        cin >> yyproof;

        cout << "*处理中...";

        if (yyproof <= burn_year || yyproof >= 2100) {
            cout << "错误！年份超限，无法计算！\n";
            printf("*请重试\n");
            continue;
        }
        else {
            break;
        }
    }

    cout << "运算：d0 = yyproof - burn_year, p = (Hash1(s))^d0\n";
    // d0 = yyproof - burn_year, p = (Hash1(s))^d0
    uint32_t d0 = yyproof - burn_year;
    string p = s, t;
    for (uint32_t i = 0; i < d0; i++) {
        t = _sm3(p);
        p = t;
    }

    cout << "*完毕！\n\n";

    ///////////////////////////////////////////////////////////////

    cout << "*准备与验证者服务器建立连接...\n";


    // 创建客户端套接字
    cout << "*正在创建套接字...";
    SOCKET clientSocket = socket(AF_INET, SOCK_STREAM, 0);
    if (clientSocket == INVALID_SOCKET) {
        cerr << "失败！无法创建套接字 Unable to create socket\n";
        WSACleanup();
        return 0;
    }
    else {
        cout << "成功\n";
    }

    // 连接到 Trusted Issuer 服务端， 此处要输入对应的地址
    
    cout << "*请求连接到 Verifier 服务端:" << Verifier_ADDR << endl;

    cout << "*正在连接服务器...";
    sockaddr_in serverAddress;
    serverAddress.sin_family = AF_INET;
    serverAddress.sin_port = htons(8080);  // 使用服务器的端口号
    inet_pton(AF_INET, Trusted_Issuer_ADDR.c_str(), &(serverAddress.sin_addr));
    if (connect(clientSocket, (sockaddr*)&serverAddress, sizeof(serverAddress)) == SOCKET_ERROR) {
        cerr << "失败！无法连接到服务器 Unable to connect to server \n";
        closesocket(clientSocket);
        WSACleanup();
        return 0;
    }
    else {
        cout << "成功\n";
    }

    ///////////////////////////////////////////////////////////////

    string time(2, 0x00);
    time[0] = yyproof / 256;
    time[1] = yyproof % 256;

    string req2 = "PRO" + time + p + sig_c;
    send(clientSocket, req2.c_str(), req2.size() + 1, 0);
    cout << ">向 Verifier 发送验证请求\n";
    cout << " ----验证内容如下：\n  验证使用年份 = " << yyproof << "\n  p = " << p << "\n  sig_c = " << sig_c << endl;

    printf("等待 Verifier 回复...");

    char input[512];
    // 接收服务端发来的公钥
    ZeroMemory(input, sizeof(input));
    int bytesReceived = recv(clientSocket, input, sizeof(input), 0);
    if (bytesReceived <= 0) {
        cout << "错误！与服务器的连接断开 Disconnect from server\n";
        closesocket(clientSocket);
        WSACleanup();
        return 0;
    }
    else
    {
        cout << "成功收到来自 Verifier:" << Verifier_ADDR << " 的回复！\n";
    }

    //结束与 Trusted Issuer 的通信
    closesocket(clientSocket);

    //将收到的字符串进行转化翻译
    string input_ = input;
    if (input_ == "yes") {
        cout << "接收信息：" << input_ << "\n验证成功！\n";
        printf("*结束\n\n");
    }
    else if (input_ == "no") {
        cout << "接收信息：" << input_ << "\n验证失败！\n";
        printf("*结束\n\n");
    }
    else{
        cout << "接收信息：" << input_ << "\n信息无效！\n";
        printf("*结束\n\n");
    }

    // 释放 Winsock 资源
    WSACleanup();

    return 0;
}
