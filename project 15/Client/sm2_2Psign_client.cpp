
#include"sm2.h"
#include <WS2tcpip.h>  // 包含 Windows 平台的网络编程头文件

#pragma comment(lib, "ws2_32.lib")  // 链接到 ws2_32.lib 库文件


string serverIP = "192.168.1.5";//注意修改IP


int main() {

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

    ///////////////////////////////////////////////////////////////

sign2P://2P签名协议开始------------------------------------------------------------------
    cout << "\n\n///////////////////////////////////////////////////////////////\n";
    cout << "*2P签名协议启动*\n";


    // 1.生成子私钥 d1  ---------------------------- 
    BIGNUM* one = BN_new();
    BIGNUM* d1 = BN_new();
    string ur1 = rand256();//生成非确定性随机数;
    string ur2 = rand256();
    BN_set_word(one, 1);
    string d1_str = hmac_prbg(ur1, ur2, one, n);//d1 = [1, n)
    BN_hex2bn(&d1, d1_str.c_str());//赋值私钥 d1

    // P1 = inv(d1) * G
    EC_POINT* P1 = EC_POINT_new(group);
    BIGNUM* inv_d1 = BN_new();
    BN_mod_inverse(inv_d1, d1, n, ctx);
    EC_POINT_mul(group, P1, inv_d1, nullptr, nullptr, ctx);

    // 向服务端发送 P1
    BIGNUM* P1x = BN_new();
    BIGNUM* P1y = BN_new();
    EC_POINT_get_affine_coordinates(group, P1, P1x, P1y, ctx);
    string P1_x = BN_bn2hex(P1x);
    string P1_y = BN_bn2hex(P1y);
    BN_free(P1x);
    BN_free(P1y);

    string P1_str = P1_x + P1_y;
    send(clientSocket, P1_str.c_str(), P1_str.size() + 1, 0);
    cout << ">向服务端发送P1:(" << P1_x << " , " << P1_y << ")\n";


    ///////////////////////////////////////////////////////////////

    // 3.生成 k1, e, Q1

    // 从控制台输入待签名的消息 message
    string message;
    cout << "请输入 待签名的消息 message：\n";
    cout << ">>> ";
    getline(cin, message);

    string Z = "id of myself.";

    string M = Z + message;
    string e = _sm3(M);

    // 生成 k1 
    BIGNUM* k1 = BN_new();
    ur1 = rand256();//生成非确定性随机数;
    ur2 = rand256();
    BN_set_word(one, 1);
    string k1_str = hmac_prbg(ur1, ur2, one, n);//k1 = [1, n)
    BN_hex2bn(&k1, k1_str.c_str());//赋值 k1

    // Q1 = k1 * G
    EC_POINT* Q1 = EC_POINT_new(group);
    EC_POINT_mul(group, Q1, k1, nullptr, nullptr, ctx);
    BIGNUM* Q1x = BN_new();
    BIGNUM* Q1y = BN_new();
    EC_POINT_get_affine_coordinates(group, Q1, Q1x, Q1y, ctx);
    string Q1_x = BN_bn2hex(Q1x);
    string Q1_y = BN_bn2hex(Q1y);
    BN_free(Q1x);
    BN_free(Q1y);

    // 向服务端发送 Q1, e
    string sss = Q1_x + Q1_y + e;
    send(clientSocket, sss.c_str(), sss.size() + 1, 0);
    cout << ">向服务端发送Q1:(" << Q1_x << ", " << Q1_y << ")\n e:" << e << "\n";

    ///////////////////////////////////////////////////////////////

        // 5.生成 另外一半签名 s

    char input[256];
    // 接收服务端发来的部分签名
    ZeroMemory(input, sizeof(input));
    int bytesReceived = recv(clientSocket, input, sizeof(input), 0);
    if (bytesReceived <= 0) {
        cout << "与服务器的连接断开 Disconnect from server\n";
        return 0;
    }
    //将收到的字符串进行转化翻译
    string input_ = input;
    string r_str = input_.substr(0, 64);
    string s2_str = input_.substr(64, 64);
    string s3_str = input_.substr(128, 64);
    BIGNUM* r = BN_new();
    BIGNUM* s2 = BN_new();
    BIGNUM* s3 = BN_new();
    BN_hex2bn(&r, r_str.c_str());
    BN_hex2bn(&s2, s2_str.c_str());
    BN_hex2bn(&s3, s3_str.c_str());
    cout << "<收到来自服务端的部分签名:\n r:" << r_str << "\n s2:" << s2_str << "\n s3:" << s3_str << "\n";

    // s = (d1 * k1) * s2 + d1 * s3 - r mod n
    BIGNUM* s = BN_new();

    BIGNUM* t1 = BN_new();
    BIGNUM* t2 = BN_new();
    BIGNUM* t3 = BN_new();
    BIGNUM* t4 = BN_new();
    BN_mod_mul(t1, d1, k1, n, ctx); // t1 = d1 * k1
    BN_mod_mul(t2, t1, s2, n, ctx); // t2 = t1 * s2
    BN_mod_mul(t3, d1, s3, n, ctx); // t3 = d1 * s3
    BN_mod_add(t4, t2, t3, n, ctx); // t4 = t2 + t3
    BN_mod_sub(s, t4, r, n, ctx);
    BN_free(t1);
    BN_free(t2);
    BN_free(t3);
    BN_free(t4);

    // aa = n - r
    BIGNUM* aa = BN_new();
    BN_mod_sub(aa, n, r, n, ctx);

    string s_str = BN_bn2hex(s);
    cout << ">向服务端发送另一半签名 s:" << s_str << "\n";

    string a_str = BN_bn2hex(aa);
    cout << "n - r :" << a_str << "\n";

    cout << BN_is_zero(s) << endl;
    cout << BN_cmp(s, aa) << endl;

    if (BN_is_zero(s) == 1 && BN_cmp(s, aa) == 0) {
        cout << "错误！签名失败！\n";

        // 关闭客户端套接字
        closesocket(clientSocket);

        // 释放 Winsock 资源
        WSACleanup();

        return 0;
    }

    

    // 向服务端发送本地公钥
    send(clientSocket, s_str.c_str(), s_str.size() + 1, 0);
    cout << ">向服务端发送另一半签名 s:" << s_str << "\n";

    cout << "\n****完整签名如下公布：\nr: " << r_str << "\ns: " << s_str << "\n";

    cout << "\n*2P签名结束*\n";
    cout << "///////////////////////////////////////////////////////////////\n\n";

    // 关闭客户端套接字
    closesocket(clientSocket);

    // 释放 Winsock 资源
    WSACleanup();

    return 0;
}
