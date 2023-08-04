#include"aes128.h"
#include"sm2.h"

/////////////////需要输入服务端主机的IP地址///////////////////////
string serverIP = "192.168.1.5";
//////////////////////////////////////////////////////////////

// 选择运行的方案：

//#define Client_PGP1
#define Client_PGP2

#ifdef Client_PGP1

#include <WS2tcpip.h>  // 包含 Windows 平台的网络编程头文件

#pragma comment(lib, "ws2_32.lib")  // 链接到 ws2_32.lib 库文件

int main() {

    //本地sm2密钥生成
    string sk;
    vector<string> pk;
    rfc6979_sm2_getKey(sk, pk);
    cout << "*本地sm2密钥生成*\n";

    // 初始化 Winsock
    cout << "*正在初始化 Winsock...";
    WSADATA wsData;
    WORD version = MAKEWORD(2, 2);
    int wsResult = WSAStartup(version, &wsData);
    if (wsResult != 0) {
        cerr << "失败！无法初始化 Winsock  Unable to initialize Winsock\n";
        return -1;
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
        return -1;
    }
    else {
        cout << "成功\n";
    }

    // 连接到服务器
    cout << "*正在连接服务器...";
    sockaddr_in serverAddress;
    serverAddress.sin_family = AF_INET;
    serverAddress.sin_port = htons(8080);  // 使用服务器的端口号
    inet_pton(AF_INET, serverIP.c_str(), &(serverAddress.sin_addr));
    if (connect(clientSocket, (sockaddr*)&serverAddress, sizeof(serverAddress)) == SOCKET_ERROR) {
        cerr << "失败！无法连接到服务器 Unable to connect to server \n";
        closesocket(clientSocket);
        WSACleanup();
        return -1;
    }
    else {
        cout << "成功\n";
    }

PGP://PGP协议开始------------------------------------------------------------------
    cout << "PGP协议启动\n";
    

    //将本地公钥转化为一个字符串
    string c_pk = pk[0] + pk[1];

    // 向服务端发送本地公钥
    send(clientSocket, c_pk.c_str(), c_pk.size() + 1, 0);
    cout << ">向服务端发送本地公钥:(" << pk[0] << ", " << pk[1] << ")\n";

    char input[256];
    // 接收服务端发来的公钥
    ZeroMemory(input, sizeof(input));
    int bytesReceived = recv(clientSocket, input, sizeof(input), 0);
    if (bytesReceived <= 0) {
        cout << "与服务器的连接断开 Disconnect from server\n";
        return 0;
    }

    //将收到的字符串进行转化翻译
    string input_ = input;
    vector<string> s_pk;
    s_pk.push_back(input_.substr(0, 64));
    s_pk.push_back(input_.substr(64, 64));
    cout << "<收到来自服务端的公钥:(" << s_pk[0] << ", " << s_pk[1] << ")\n";

    
    cout << "*公钥交换阶段结束*\n\n";



    // 进入聊天循环
    char buffer[4096];
    string userInput;

    // 接收和发送消息
    while (true) {
        // 从控制台输入消息并发送给服务器
        cout << ">>> ";
        getline(cin, userInput);

        if (userInput == "quit") {
            cout << "退出本地客户端... Exit Local Client...\n";
            break;
        }

        // sm2加密消息
        vector<string> c123;
        sm2_enc(c123, userInput, s_pk);
        string C = c123[0] + c123[1] + c123[2];

        //sm2对消息签名
        vector<string> sign;
        rfc6979_sm2_sign(sign, C, sk);

        //转换签名
        string Sign = sign[0] + sign[1];

        string Sendmessage = Sign + C;


        int sendResult = send(clientSocket, Sendmessage.c_str(), Sendmessage.size() + 1, 0);
        if (sendResult == SOCKET_ERROR) {
            cerr << "无法发送消息到服务器 Unable to send message to server" << endl;
            break;
        }
        else {
            cout << ">已发送密文: " << Sendmessage << "\n\n";
        }

        // 接收服务器返回的消息
        cout << "等待对方发送...\n";
        ZeroMemory(buffer, sizeof(buffer));
        int bytesReceived = recv(clientSocket, buffer, sizeof(buffer), 0);
        if (bytesReceived <= 0) {
            cerr << "与服务器的连接断开 Disconnect from server" << endl;
            break;
        }

        cout << "来自服务器 Server 的原始密文: " << buffer << endl;

        //验证签名
        string Buffer = buffer;
        vector<string> s_sign;
        s_sign.push_back(Buffer.substr(0, 64));
        s_sign.push_back(Buffer.substr(64, 64));
        string s_C = Buffer.substr(128, Buffer.length() - 128);

        if (rfc6979_sm2_verify(s_C, s_sign, s_pk)) {
            cout << "*签名通过*\n";
        }
        else {
            cout << "！！！签名未通过！！！\n*即将主动断开连接*\n";
            cout << "已退出本地客户端... Exit Local Client...\n";
            break;
        }

        //解密消息
        string s_M;
        vector<string> serverC;
        serverC.push_back(s_C.substr(0, 128));
        serverC.push_back(s_C.substr(128, s_C.size() - 192));
        serverC.push_back(s_C.substr(s_C.size() - 64, 64));

        if (sm2_dec(s_M, sk, serverC))
        {
            cout << "*解密成功！*\n";
            cout << "来自服务端明文：" << s_M << "\n\n";
        }
        else
            cout << "解密失败！\n";
    }

    // 关闭客户端套接字
    closesocket(clientSocket);

    // 释放 Winsock 资源
    WSACleanup();

    return 0;
}

#endif

////////////////////////////////////////////////////////////////////////////////////////

#ifdef Client_PGP2

#include <WS2tcpip.h>  // 包含 Windows 平台的网络编程头文件

#pragma comment(lib, "ws2_32.lib")  // 链接到 ws2_32.lib 库文件

int main() {

    //本地AES密钥生成
    
    // 使用随机设备作为种子
    random_device rd;
    // 使用 Mersenne Twister 引擎
    mt19937 gen(rd());
    // 生成一个范围在 0 到 255（包括）的随机整数
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
    cout << "*本地AES-128 密钥+iv 生成*\n";

    // 初始化 Winsock
    cout << "*正在初始化 Winsock...";
    WSADATA wsData;
    WORD version = MAKEWORD(2, 2);
    int wsResult = WSAStartup(version, &wsData);
    if (wsResult != 0) {
        cerr << "失败！无法初始化 Winsock  Unable to initialize Winsock\n";
        return -1;
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
        return -1;
    }
    else {
        cout << "成功\n";
    }

    // 连接到服务器
    cout << "*正在连接服务器...";
    sockaddr_in serverAddress;
    serverAddress.sin_family = AF_INET;
    serverAddress.sin_port = htons(8080);  // 使用服务器的端口号
    inet_pton(AF_INET, serverIP.c_str(), &(serverAddress.sin_addr));
    if (connect(clientSocket, (sockaddr*)&serverAddress, sizeof(serverAddress)) == SOCKET_ERROR) {
        cerr << "失败！无法连接到服务器 Unable to connect to server \n";
        closesocket(clientSocket);
        WSACleanup();
        return -1;
    }
    else {
        cout << "成功\n";
    }

PGP://PGP协议开始------------------------------------------------------------------
    cout << "PGP协议启动\n";


    // 向服务端发送PGP请求
    string req = "PGP";
    send(clientSocket, req.c_str(), req.size() + 1, 0);
    cout << ">向服务端发送PGP请求\n";

    char input[256];
    // 接收服务端发来的公钥
    ZeroMemory(input, sizeof(input));
    int bytesReceived = recv(clientSocket, input, sizeof(input), 0);
    if (bytesReceived <= 0) {
        cout << "与服务器的连接断开 Disconnect from server\n";
        return 0;
    }

    //将收到的字符串进行转化翻译
    string input_ = input;
    vector<string> s_pk;
    s_pk.push_back(input_.substr(0, 64));
    s_pk.push_back(input_.substr(64, 64));
    cout << "<收到来自服务端的公钥:(" << s_pk[0] << ", " << s_pk[1] << ")\n";

    
    vector<string> c123;
    sm2_enc(c123, key_iv, s_pk);
    
    // 向服务端发送由sm2加密过的AES密钥和IV
    string c1c2c3 = c123[0] + c123[1] + c123[2];
    send(clientSocket, c1c2c3.c_str(), c1c2c3.size() + 1, 0);
    cout << ">向服务端发送加密后的AES密钥和IV：\n c1 = " << c123[0] << "\n c2 = " << c123[1] << "\n c3 = " << c123[2] << endl;
    cout << "c123:" << c1c2c3 << endl;

    cout << "*密钥交换阶段结束*\n\n";



    // 进入聊天循环
    char buffer[4096];
    string userInput;

    // 接收和发送消息
    while (true) {
        // 从控制台输入消息并发送给服务器
        cout << ">>> ";
        getline(cin, userInput);

        if (userInput == "quit") {
            cout << "退出本地客户端... Exit Local Client...\n";
            break;
        }

        //AES加密
        string Sendmessage;
        aes128(Sendmessage, userInput, SymmetricKey, iv, CTR_enc);

        int sendResult = send(clientSocket, Sendmessage.c_str(), Sendmessage.size() + 1, 0);
        if (sendResult == SOCKET_ERROR) {
            cerr << "无法发送消息到服务器 Unable to send message to server" << endl;
            break;
        }
        else {
            cout << ">已发送密文: " << Sendmessage << "\n\n";
        }

        // 接收服务器返回的消息
        cout << "等待对方发送...\n";
        ZeroMemory(buffer, sizeof(buffer));
        int bytesReceived = recv(clientSocket, buffer, sizeof(buffer), 0);
        if (bytesReceived <= 0) {
            cerr << "与服务器的连接断开 Disconnect from server" << endl;
            break;
        }

        cout << "来自服务器 Server 的原始密文: " << buffer << endl;


        //解密消息
        string s_M;
        string serverC = buffer;
        cout << "*正在解密...";
        if (aes128(s_M, serverC, SymmetricKey, iv, CTR_dec))
        {
            cout << "解密成功！*\n";
            cout << "来自服务端明文：" << s_M << "\n\n";
        }
        else
            cout << "解密失败！\n";
    }

    // 关闭客户端套接字
    closesocket(clientSocket);

    // 释放 Winsock 资源
    WSACleanup();

    return 0;
}

#endif