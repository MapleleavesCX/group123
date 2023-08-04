
#include"sm2.h"
#include <WS2tcpip.h>  // 包含 Windows 平台的网络编程头文件

#pragma comment(lib, "ws2_32.lib")  // 链接到 ws2_32.lib 库文件

int main() {

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

        //初始化椭圆曲线相关参数

        BN_CTX* ctx = BN_CTX_new();

        //初始化——确定选择sm2椭圆曲线
        EC_GROUP* group = EC_GROUP_new_by_curve_name(NID_sm2);
        if (group == NULL)cout << "初始化曲线失败\n";

        //获取椭圆曲线的阶 n
        BIGNUM* n = BN_new();
        EC_GROUP_get_order(group, n, ctx);
        if (n == NULL)cout << "获取椭圆曲线的阶 n 失败\n";

        // 获取基点 G
        const EC_POINT* G = EC_GROUP_get0_generator(group);


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

        ///////////////////////////////////////////////////////////////

    enc2P://2P加密协议开始------------------------------------------------------------------
        cout << "\n\n///////////////////////////////////////////////////////////////\n";
        cout << "*2P加密协议启动*\n";

        // 1.生成子私钥 d2  ---------------------------- 
        BIGNUM* one = BN_new();
        BIGNUM* d2 = BN_new();
        string ur1 = rand256();//生成非确定性随机数;
        string ur2 = rand256();
        BN_set_word(one, 1);
        string d2_str = hmac_prbg(ur1, ur2, one, n);//d2 = [1, n)
        BN_hex2bn(&d2, d2_str.c_str());//赋值私钥 d2

        char input[256];
        // 接收客户端发来的 P1
        ZeroMemory(input, sizeof(input));
        int bytesReceived = recv(clientSocket, input, sizeof(input), 0);
        if (bytesReceived <= 0) {
            cout << "客户端断开连接\n";
            continue;
        }

        //将收到的字符串进行转化翻译
        string P1_str = input;
        string P1x = P1_str.substr(0, 64);
        string P1y = P1_str.substr(64, 64);
        BIGNUM* P1_x = BN_new();
        BIGNUM* P1_y = BN_new();
        BN_hex2bn(&P1_x, P1x.c_str());
        BN_hex2bn(&P1_y, P1y.c_str());
        EC_POINT* P1 = EC_POINT_new(group);
        EC_POINT_set_affine_coordinates(group, P1, P1_x, P1_y, ctx);
        cout << "<收到来自来访者 " << clientIP << " 的P1:(" << P1x << ", " << P1y << ")\n";

        ///////////////////////////////////////////////////////////////

        // 2.生成共享公钥 P = inv(d2) * P1 - G 
        EC_POINT* P = EC_POINT_new(group);

        EC_POINT* temp = EC_POINT_new(group);
        BIGNUM* inv_d2 = BN_new();
        BN_mod_inverse(inv_d2, d2, n, ctx);
        EC_POINT_mul(group, temp, nullptr, P1, inv_d2, ctx);

        EC_POINT* invG = EC_POINT_new(group);
        EC_POINT_copy(invG, G); // 先将 invG 初始化为 G
        EC_POINT_invert(group, invG, ctx); // 取相反数
        EC_POINT_add(group, P, temp, invG, ctx);

        EC_POINT_free(temp);
        EC_POINT_free(invG);

        // 将公钥打印出来
        BIGNUM* Px = BN_new();
        BIGNUM* Py = BN_new();
        EC_POINT_get_affine_coordinates(group, P, Px, Py, ctx);
        string P_x = BN_bn2hex(Px);
        string P_y = BN_bn2hex(Py);

        cout << "\n****生成共享公钥 P = (" << P_x << " , " << P_y << ")\n\n";

        BN_free(Px);
        BN_free(Py);

        /////////////////////////////////////////////////////////////////////

        
        // 从控制台输入待签名的消息 message
        string message;
        cout << "请输入 待加密的消息：\n";
        cout << ">>> ";
        getline(cin, message);
        string Z = "{id of myself.}:";
        string M = Z + message;

        vector<string> PK;
        PK.push_back(P_x);
        PK.push_back(P_y);

        //加密明文
        vector<string> C;
        sm2_enc(C, M, PK);

        //发送密文
        string CC = C[0] + C[1] + C[2];
        send(clientSocket, CC.c_str(), CC.size() + 1, 0);
        cout << ">向来访者 " << clientIP << " 发送密文: " << CC << "\n";

        cout << "\n*2P加密结束*\n";


    dec2P://2P解密协议开始------------------------------------------------------------------
        cout << "///////////////////////////////////////////////////////////////\n";
        cout << "*2P解密协议启动*\n";


        char input2[256];
        // 接收客户端发来的 T1
        ZeroMemory(input2, sizeof(input2));
        bytesReceived = recv(clientSocket, input2, sizeof(input2), 0);
        if (bytesReceived <= 0) {
            cout << "客户端断开连接\n";
            continue;
        }

        //将收到的字符串进行转化翻译
        string T1_str = input2;
        string T1x = T1_str.substr(0, 64);
        string T1y = T1_str.substr(64, 64);
        BIGNUM* T1_x = BN_new();
        BIGNUM* T1_y = BN_new();
        BN_hex2bn(&T1_x, T1x.c_str());
        BN_hex2bn(&T1_y, T1y.c_str());
        EC_POINT* T1 = EC_POINT_new(group);
        EC_POINT_set_affine_coordinates(group, T1, T1_x, T1_y, ctx);
        cout << "<收到来自来访者 " << clientIP << " 的T1: (" << T1x << ", " << T1y << ")\n";

        ///////////////////////////////////////////////////////////////

        // 3.计算 T2 = inv(d2) * T1
        EC_POINT* T2 = EC_POINT_new(group);
        BN_mod_inverse(inv_d2, d2, n, ctx);
        EC_POINT_mul(group, T2, nullptr, T1, inv_d2, ctx);
        BN_free(inv_d2);

        // 准备发送T2
        BIGNUM* T2_x = BN_new();
        BIGNUM* T2_y = BN_new();
        EC_POINT_get_affine_coordinates(group, T2, T2_x, T2_y, ctx);
        string T2x = BN_bn2hex(T2_x);
        string T2y = BN_bn2hex(T2_y);
        BN_free(T2_x);
        BN_free(T2_y);

        // 向客户端发送 T2
        string T2_str = T2x + T2y;
        send(clientSocket, T2_str.c_str(), T2_str.size() + 1, 0);
        cout << ">向来访者 " << clientIP << " 发送T2: (" << T2x << ", " << T2y << ")\n";


        /////////////////////////////////////////////////////////////////////

        cout << "\n*2P解密结束*\n";
        cout << "///////////////////////////////////////////////////////////////\n\n";


    }

    return 0;
}