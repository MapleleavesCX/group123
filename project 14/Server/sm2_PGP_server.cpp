#include"sm2.h"
#include"aes128.h"

// 选择运行的方案：

//#define Server_PGP1
#define Server_PGP2


#ifdef Server_PGP1

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
        cerr << "失败！无法初始化 Winsock\n";
        return -1;
    }
    else {
        cout << "成功\n";
    }


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
            WSACleanup();
            return -1;
        }

        char clientIP[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &(clientAddress.sin_addr), clientIP, INET_ADDRSTRLEN);

        cout << "*收到来访请求*\n来访者IP地址：" << clientIP << endl;  // 显示来访者IP地址

        // 关闭监听套接字，因为我们只处理一个客户端连接
        closesocket(listeningSocket);

        
    PGP://PGP协议开始------------------------------------------------------------------
        cout << "PGP协议启动\n";

        char input[256];
        // 接收客户端发来的公钥
        ZeroMemory(input, sizeof(input));
        int bytesReceived = recv(clientSocket, input, sizeof(input), 0);
        if (bytesReceived <= 0) {
            cout << "客户端断开连接\n";
            continue;
        }
        
        //将收到的字符串进行转化翻译
        string input_ = input;
        vector<string> c_pk;
        c_pk.push_back(input_.substr(0, 64));
        c_pk.push_back(input_.substr(64, 64));
        cout << "<收到来自来访者 " << clientIP << " 的公钥:(" << c_pk[0] << ", " << c_pk[1] << ")\n";
        
        //将本地公钥转化为一个字符串
        string s_pk = pk[0] + pk[1];

        // 向客户端发送本地公钥
        send(clientSocket, s_pk.c_str(), s_pk.size() + 1, 0);
        cout << ">向来访者 " << clientIP << " 发送本地公钥:(" << pk[0] << ", " << pk[1] << ")\n";

        cout << "*公钥交换阶段结束*\n\n";

        // 进入聊天循环
        char buffer[4096];
        string userInput;

        while (true) {
            // 接收客户端发送的消息
            cout << "等待对方发送...\n";
            ZeroMemory(buffer, sizeof(buffer));
            int bytesReceived = recv(clientSocket, buffer, sizeof(buffer), 0);
            if (bytesReceived <= 0) {
                cout << "客户端断开连接\n";
                break;
            }

            cout << "<来自客户端 " << clientIP << " 的原始密文: " << buffer << endl;

            //验证签名
            string Buffer = buffer;
            vector<string> c_sign;
            c_sign.push_back(Buffer.substr(0, 64));
            c_sign.push_back(Buffer.substr(64, 64));
            string c_C = Buffer.substr(128, Buffer.length() - 128);

            if (rfc6979_sm2_verify(c_C, c_sign, c_pk)) {
                cout << "*签名通过*\n";
            }
            else {
                cout << "！！！签名未通过！！！\n*即将主动断开连接*\n";
                cout << "本地服务端已拒绝" << clientIP << "接入\n";
                break;
            }

            //解密消息
            string c_M;
            vector<string> clientC;
            clientC.push_back(c_C.substr(0, 128));
            clientC.push_back(c_C.substr(128, c_C.size() - 192));
            clientC.push_back(c_C.substr(c_C.size() - 64, 64));

            if (sm2_dec(c_M, sk, clientC))
            {
                cout << "*解密成功！*\n";
                cout << "来自服务端明文：" << c_M << "\n\n";
            }
            else
                cout << "解密失败！\n";


            // 从控制台输入消息并发送给客户端
            cout << ">>> ";
            getline(cin, userInput);

            if (userInput == "refuse") {
                cout << "本地服务端已拒绝" << clientIP << "接入\n";
                closesocket(clientSocket);
                break;
            }
            if (userInput == "quit") {
                cout << "本地服务端关闭...\n";
                // 释放 Winsock 资源
                WSACleanup();
                return 0;
            }

            // sm2加密消息
            vector<string> c123;
            sm2_enc(c123, userInput, c_pk);
            string C = c123[0] + c123[1] + c123[2];

            //sm2对消息密文签名
            vector<string> sign;
            rfc6979_sm2_sign(sign, C, sk);

            //转换签名
            string Sign = sign[0] + sign[1];

            string Sendmessage = Sign + C;

            int sendResult = send(clientSocket, Sendmessage.c_str(), Sendmessage.size() + 1, 0);
            if (sendResult == SOCKET_ERROR) {
                cerr << "无法发送消息到客户端 " << clientIP << "\n";
                break;
            }
            else {
                cout << ">已发送密文: " << Sendmessage << "\n\n";
            }
        }
    }

    return 0;
}

#endif


/////////////////////////////////////////////////////////////////////////////////////////

#ifdef Server_PGP2

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
        cerr << "失败！无法初始化 Winsock\n";
        return -1;
    }
    else {
        cout << "成功\n";
    }


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
            WSACleanup();
            return -1;
        }

        char clientIP[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &(clientAddress.sin_addr), clientIP, INET_ADDRSTRLEN);

        cout << "*收到来访请求*\n来访者IP地址：" << clientIP << endl;  // 显示来访者IP地址

        // 关闭监听套接字，因为我们只处理一个客户端连接
        closesocket(listeningSocket);


    PGP://PGP协议开始------------------------------------------------------------------
        cout << "PGP协议启动\n";

        char input[256];
        // 接收客户端发来的公钥
        ZeroMemory(input, sizeof(input));
        int bytesReceived = recv(clientSocket, input, sizeof(input), 0);
        if (bytesReceived <= 0) {
            cout << "客户端断开连接\n";
            continue;
        }

        //将收到的字符串进行转化翻译
        string input_ = input;
        cout << "<收到来自来访者 " << clientIP << " 的请求:" << input_ << "\n";

        //将本地公钥转化为一个字符串
        string s_pk = pk[0] + pk[1];

        // 向客户端发送本地公钥
        send(clientSocket, s_pk.c_str(), s_pk.size() + 1, 0);
        cout << ">向来访者 " << clientIP << " 发送本地公钥:(" << pk[0] << ", " << pk[1] << ")\n";

        char input2[1024];
        // 接收客户端发来的加密信息-->解密出双方的对称密钥
        ZeroMemory(input2, sizeof(input2));
        int bytesReceived2 = recv(clientSocket, input2, sizeof(input2), 0);
        if (bytesReceived2 <= 0) {
            cout << "客户端断开连接\n";
            continue;
        }
        //将收到的字符串进行转化翻译
        string input2_ = input2;
        vector<string> c123;

        c123.push_back(input2_.substr(0, 128));
        c123.push_back(input2_.substr(128, input2_.size() - 192));
        c123.push_back(input2_.substr(input2_.size() - 64, 64));

        cout << "<收到来自来访者 " << clientIP << " 的密文:(" << c123[0] << ", " << c123[1] << ", " << c123[2] << ")\n";

        //私钥解密
        string key_iv;
        string skey, iv;
        if (sm2_dec(key_iv, sk, c123))
        {
            cout << "*解密成功！*\n";
            skey = key_iv.substr(0, 16);
            iv = key_iv.substr(16, 16);
            cout << "获得共享的AES-128的密钥：" << skey << "\n";
            cout << "获得共享的AES-128的iv：" << iv << "\n\n";
        }
        else
        {
            cout << "解密失败！协议终止\n";
            continue;
        }

        cout << "*密钥交换阶段结束*\n\n";

        // 进入聊天循环
        char buffer[4096];
        string userInput;

        while (true) {
            // 接收客户端发送的消息
            cout << "等待对方发送...\n";
            ZeroMemory(buffer, sizeof(buffer));
            int bytesReceived = recv(clientSocket, buffer, sizeof(buffer), 0);
            if (bytesReceived <= 0) {
                cout << "客户端断开连接\n";
                break;
            }

            cout << "<来自客户端 " << clientIP << " 的原始密文: " << buffer << endl;


            string c_C = buffer;

            //解密消息
            cout << "*正在解密...";
            string c_M;
            if (aes128(c_M, c_C, skey, iv, CTR_dec))
            {
                cout << "解密成功！*\n";
                cout << "来自客户端 " << clientIP << " 的明文：" << c_M << "\n\n";
            }
            else
                cout << "解密失败！\n";


            // 从控制台输入消息并发送给客户端
            cout << ">>> ";
            getline(cin, userInput);

            if (userInput == "refuse") {
                cout << "本地服务端已拒绝" << clientIP << "接入\n";
                closesocket(clientSocket);
                break;
            }
            if (userInput == "quit") {
                cout << "本地服务端关闭...\n";
                // 释放 Winsock 资源
                WSACleanup();
                return 0;
            }

            // sm2加密消息
            string Sendmessage;
            aes128(Sendmessage, userInput, skey, iv, CTR_enc);

            int sendResult = send(clientSocket, Sendmessage.c_str(), Sendmessage.size() + 1, 0);
            if (sendResult == SOCKET_ERROR) {
                cerr << "无法发送消息到客户端 " << clientIP << "\n";
                break;
            }
            else {
                cout << ">已发送密文: " << Sendmessage << "\n\n";
            }
        }
    }

    return 0;
}

#endif