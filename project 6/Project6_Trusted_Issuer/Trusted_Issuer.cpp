

#include"sm2.h"
#include <WS2tcpip.h>  // 包含 Windows 平台的网络编程头文件

#pragma comment(lib, "ws2_32.lib")  // 链接到 ws2_32.lib 库文件

int main() {

    printf("\n******* Trust Lssuer *******\n\n");

    // 初始化 Winsock
    cout << "*正在初始化 Winsock...";
    WSADATA wsData;
    WORD version = MAKEWORD(2, 2);
    int wsResult = WSAStartup(version, &wsData);
    if (wsResult != 0) {
        cerr << "失败！无法初始化 Winsock\n";
        return -1;
    }
    else {
        cout << "成功\n";
    }

    //生成本地公私钥
    printf("正在生成本地公私钥...");
    vector<string> P;
    string d;
    rfc6979_sm2_getKey(d, P);
    printf("成功！\n");

    while (true) {

        // 创建服务器端套接字
        cout << "*正在创建套接字...";
        SOCKET listeningSocket = socket(AF_INET, SOCK_STREAM, 0);
        if (listeningSocket == INVALID_SOCKET) {
            cerr << "失败！无法创建套接字\n";
            WSACleanup();
            return -1;
        }
        else {
            cout << "成功\n";
        }

        // 绑定服务器地址和端口
        cout << "*正在绑定套接字...";
        sockaddr_in serverAddress;
        serverAddress.sin_family = AF_INET;
        serverAddress.sin_port = htons(8080);  // 使用指定的端口号
        serverAddress.sin_addr.s_addr = INADDR_ANY;

        if (bind(listeningSocket, (sockaddr*)&serverAddress, sizeof(serverAddress)) == SOCKET_ERROR) {
            cerr << "失败！无法绑定套接字\n";
            closesocket(listeningSocket);
            WSACleanup();
            return -1;
        }
        else {
            cout << "成功\n";
        }

        // 开始监听连接请求
        cout << "开始监听...\n";

        if (listen(listeningSocket, SOMAXCONN) == SOCKET_ERROR) {
            cerr << "监听失败\n";
            closesocket(listeningSocket);
            WSACleanup();
            return -1;
        }

        // 等待客户端连接
        sockaddr_in clientAddress;
        int clientAddressSize = sizeof(clientAddress);
        SOCKET clientSocket = accept(listeningSocket, (sockaddr*)&clientAddress, &clientAddressSize);
        if (clientSocket == INVALID_SOCKET) {
            cerr << "无法接受客户端连接\n";
            closesocket(listeningSocket);
            continue;
        }

        char clientIP[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &(clientAddress.sin_addr), clientIP, INET_ADDRSTRLEN);

        cout << "*收到来访请求*\n来访者IP地址：" << clientIP << endl;  // 显示来访者IP地址

        // 关闭监听套接字，因为我们只处理一个客户端连接
        closesocket(listeningSocket);

        ///////////////////////////////////////////////////////////////

    

        char input[512];
        // 接收客户端发来的请求 ask
        ZeroMemory(input, sizeof(input));
        int bytesReceived = recv(clientSocket, input, sizeof(input), 0);
        if (bytesReceived <= 0) {
            cout << "客户端断开连接\n";
            continue;
        }

        string receive = input;
        string req = receive.substr(0, 3);

        if (req == "SIG") {

            uint8_t h = receive[3];
            uint8_t l = receive[4];

            uint32_t burn_year = h * 256 + l;
            cout << "接收到来访的用户的出生年份：" << burn_year << endl;

            if (burn_year <= 0 || burn_year >= 2100) {
                cout << "错误！年份超限，无法计算！\n";
                printf("*结束\n\n");
                continue;
            }

            //获得以字符串表示的16进制串，256bit->64长
            string seed256 = rand256();

            //计算 s = Hash0(seed）
            string s = _sha256(seed256);

            //计算 k = 2100 - 出身年份， 然后循环hash2  k 次
            uint32_t k = 2100 - burn_year;
            string c = s, t;
            for (uint32_t i = 0; i < k; i++) {
                t = _sm3(c);
                c = t;
            }

            //用Trust Issuer的私钥为 c 签名背书
            vector<string> sig_c;
            rfc6979_sm2_sign(sig_c, c, d);

            //向客户端发送 s 和 c || sig_c
            string sendM = s + sig_c[0] + sig_c[1];
            send(clientSocket, sendM.c_str(), sendM.size() + 1, 0);
            cout << ">向来访者 " << clientIP << " 发送年份签名:\ns = " << s << "\nsign of c:(" << sig_c[0] << ", " << sig_c[1] << ")\n";

            printf("*结束\n\n");
            continue;
        }
        else if (req == "ASK") {

            string sendM = P[0] + P[1];
            send(clientSocket, sendM.c_str(), sendM.size() + 1, 0);
            cout << ">向来访者 " << clientIP << " 发送本地公钥:\nP = (" << P[0] << ", " << P[1] << ")\n";
            printf("*结束\n\n");
            continue;
        }
        else {
            cout << "指令请求错误！拒绝接入！\n";
            string sendM = "Error";
            send(clientSocket, sendM.c_str(), sendM.size() + 1, 0);
            printf("*结束\n\n");
            continue;
        }

    }
    WSACleanup();
    return 0;
}