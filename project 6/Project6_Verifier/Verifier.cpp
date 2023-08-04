

#include"sm2.h"
#include <WS2tcpip.h>  // 包含 Windows 平台的网络编程头文件

#pragma comment(lib, "ws2_32.lib")  // 链接到 ws2_32.lib 库文件

int main() {

    printf("\n******* Verifier *******\n\n");

    //////////////////////基础参数设定（可修改）//////////////////////

    string Trusted_Issuer_ADDR = "192.168.1.5";//可信第三方的IP地址

    ///////////////////////////////////////////////////////////////



    // 初始化 Winsock
    cout << "*正在初始化 Winsock...";
    WSADATA wsData;
    WORD version = MAKEWORD(2, 2);
    int wsResult = WSAStartup(version, &wsData);
    if (wsResult != 0) {
        cerr << "失败！无法初始化 Winsock\n";
        return 0;
    }
    else {
        cout << "成功\n";
    }

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
    
    cout << "*请求连接到 Trusted Issuer 服务端:" << Trusted_Issuer_ADDR << endl;

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

    string req2 = "ASK";
    send(clientSocket, req2.c_str(), req2.size() + 1, 0);
    cout << ">向 Trusted Issuer 请求公钥\n";

    printf("等待 Trusted Issuer 回复...");

    char input1[512];
    // 接收服务端发来的公钥
    ZeroMemory(input1, sizeof(input1));
    int bytesReceived1 = recv(clientSocket, input1, sizeof(input1), 0);
    if (bytesReceived1 <= 0) {
        cout << "错误！与服务器的连接断开 Disconnect from server\n";
        closesocket(clientSocket);
        WSACleanup();
        return 0;
    }
    else
    {
        cout << "成功收到来自 " << Trusted_Issuer_ADDR << " 的回复！\n";
    }

    //结束与 Trusted Issuer 的通信
    closesocket(clientSocket);
    //WSACleanup();

    //将收到的字符串进行转化翻译
    string input_1 = input1;
    if (input_1 == "Error") {
        cout << "接收信息：" << input_1 << "\n信息无效！\n";
        printf("*结束\n\n");
        return 0;
    }

    vector<string> P;
    P.push_back(input_1.substr(0, 64));
    P.push_back(input_1.substr(64, 64));

    cout << "<接收到来自 Trusted Issuer 的公钥：\nP = (" << P[0] << ", " << P[1] << ")\n";

    cout << "*完毕\n\n";

    ///////////////////////////////////////////////////////////////
    string chose;
    cout << "请输入验证者服务器启动口令：\n";
    while(true){
        getline(cin, chose);
        if (chose == "go") {
            break;
        }
        else {
            cout << "*口令错误！请重试\n";
        }
    }

    cout << "*验证者本地服务器启动\n";

    while (true) {

        

        // 初始化 Winsock
        cout << "*正在初始化 Winsock...";
        WSADATA wsData2;
        WORD version2 = MAKEWORD(2, 2);
        int wsResult2 = WSAStartup(version2, &wsData2);
        if (wsResult2 != 0) {
            cerr << "失败！无法初始化 Winsock\n";
            return 0;
        }
        else {
            cout << "成功\n";
        }

        // 创建服务器端套接字
        cout << "*正在创建套接字...";
        SOCKET listeningSocket = socket(AF_INET, SOCK_STREAM, 0);
        if (listeningSocket == INVALID_SOCKET) {
            cerr << "失败！无法创建套接字\n";
            WSACleanup();
            return 0;
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
            return 0;
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
            return 0;
        }

        // 等待客户端连接
        sockaddr_in clientAddress;
        int clientAddressSize = sizeof(clientAddress);
        SOCKET clientSocket = accept(listeningSocket, (sockaddr*)&clientAddress, &clientAddressSize);
        if (clientSocket == INVALID_SOCKET) {
            cerr << "无法接受客户端连接\n";
            closesocket(listeningSocket);
            WSACleanup();
            return 0;
        }

        char clientIP[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &(clientAddress.sin_addr), clientIP, INET_ADDRSTRLEN);

        cout << "*收到来访请求*\n来访者IP地址：" << clientIP << endl;  // 显示来访者IP地址

        // 关闭监听套接字，因为我们只处理一个客户端连接
        closesocket(listeningSocket);

        ///////////////////////////////////////////////////////////////

        

        char input[512];
        // 接收客户端发来的信息
        ZeroMemory(input, sizeof(input));
        int bytesReceived = recv(clientSocket, input, sizeof(input), 0);
        if (bytesReceived <= 0) {
            cout << "客户端断开连接\n";
            continue;
        }

        //将收到的字符串进行转化翻译
        string input_ = input;
        string req = input_.substr(0, 3);
        
        
        cout << "<收到来自来访者 " << clientIP << " 的请求：" << req << endl;

        if (req == "PRO") {

            cout << "开始验证：\n";

            string yy = input_.substr(3, 2);
            uint8_t h = input_[3];
            uint8_t l = input_[4];
            uint32_t yyproof = h * 256 + l;

            string p = input_.substr(5, 64);
            vector<string> sig_c;
            sig_c.push_back(input_.substr(69, 64));
            sig_c.push_back(input_.substr(133, 64));

            cout << "<接收信息：\np = " << p << "\nsig_c = (" << sig_c[0] << ", " << sig_c[1] << ")\n";
            cout << "测试年份：" << yyproof << endl;
            

            //计算 d1 = 2100 - yyproof, 计算 c' = (Hash1(p))^d1
            cout << "计算： d1 = 2100 - yyproof, 计算 c' = (Hash1(p))^d1\n";
            uint32_t d1 = 2100 - yyproof;
            string c_ = p, t;
            if (d1 <= 0) {
                cout << "错误！接收证明用年份超过2100年！\n";
                string sendM = "Error";
                send(clientSocket, sendM.c_str(), sendM.size() + 1, 0);
                continue;
            }
            for (uint32_t i = 0; i < d1; i++) {
                t = _sm3(c_);
                c_ = t;
            }
            cout << "*计算结束，计算结果 ：c' = " << c_ << endl;

            //验证签名
            cout << "*验证：sig_c是否为 c' 的签名:";

            string verify;

            if (rfc6979_sm2_verify(c_, sig_c, P)) {
                verify = "yes";
            }
            else {
                verify = "no";
            }
            cout << verify << endl;


            //发送结果
            send(clientSocket, verify.c_str(), verify.size() + 1, 0);
            printf("*结束\n\n");
            continue;
        }
        else {
            cout << "指令请求错误！拒绝接入！\n";
            string sendM = "Error";
            send(clientSocket, sendM.c_str(), sendM.size() + 1, 0);
            continue;
        }
    }
    WSACleanup();
    return 0;
}