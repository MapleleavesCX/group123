
#define Merkle_Patricia_Tree

#ifdef Merkle_Patricia_Tree

#include"MPT.h"

string sha256(const string& input);
string buildMerkleTree(const vector<string>& Hash);


// Main函数执行选择：需要执行哪一项就取消注释该项，然后其余项注释掉（避免多个主调函数造成冲突）

#define test_main
//#define Inclusion_Proof
//#define Exclusion_Proof


//用于构建树的字符串数据，每32个字符拆分为一个初始节点，可任意修改（不可为空字符）
//foafhceosfhw88028y4rf0f3g02g9fg29hdholhdolih173243554yihfwdv13iuhrgewfqir1o23ugfr1rr23gevfwcqfey1dfuy434y43879r68qwtfcvdeuwr2117
string DATA = "foafhceosfhw88028y4rf0f3g02g9fg29hdholhdolih173243554yihfwdv13iuhrgewfqir1o23ugfr1rr23gevfwcqfey1dfuy434y43879r68qwtfcvdeuwr2117";


#ifdef test_main

int main() {

    cout << "DATA长度："<<DATA.size();

    //版本1：输入data每32字符的hash值列表，
    //奇数个节点处理方式：复制末尾节点补齐为偶数，
    //返回首节点
    //{
    //    cout << "第一版 Merkle Patricia Tree 仅输出首节点版本：\n";

    //    //将完整的一串字符串以32字节分组并Hash
    //    vector<string> Hashblock;
    //    int sign = 0;
    //    int len = DATA.size();
    //    int i = 0;
    //    while (len - sign >= 32) {
    //        Hashblock.push_back(sha256(DATA.substr(sign, 32)));
    //        sign += 32;
    //        i++;
    //    }
    //    if (len - sign < 32) {
    //        Hashblock.push_back(sha256(DATA.substr(sign, len - sign)));
    //    }

    //    // 构建Merkle树——版本1
    //    string rootHash = buildMerkleTree(Hashblock);

    //    cout << "Root Hash: " << rootHash << endl << endl;

    //    cout << "结束\n\n";
    //}

    //版本2：输入data每32字符的hash值列表，
    //奇数个节点处理方式：复制末尾节点补齐为偶数，
    //返回整个树
    {
        cout << "第二版 Merkle Patricia Tree：\n奇数个节点处理方式：复制末尾节点补齐为偶数\n";

        vector<line> Hash;
        //拆分节点分别hash
        NodeHashInital2(Hash, DATA);

        uint32_t s1 = Hash.size() % 2 == 0 ? Hash.size() : Hash.size() + 1;
        

        // 构建Merkle树——版本2
        timing(buildMerkleTree2, Hash);

        //输出全部节点
        printf_tree2(Hash, s1);

    }


    // 版本3：输入data每32字符的hash值列表，
    // 奇数个节点处理方式：末尾节点不处理，忽略到下一层，直到下一层补齐为偶数，
    // 返回整个树
    {
        cout << "第三版 Merkle Patricia Tree ：\n奇数个节点处理方式：末尾节点不处理，忽略到下一层，直到下一层补齐为偶数\n";
        vector<line> Hash;
        //拆分节点分别hash
        NodeHashInital3(Hash, DATA);
        
        uint32_t s1 = Hash.size();//树最底层

        // 构建Merkle树——版本3
        timing(buildMerkleTree3, Hash);

        //输出全部节点
        printf_tree3(Hash, s1);
        
    }

    return 0;
}

#endif

#ifdef Inclusion_Proof

int main() {

    {
        
        vector<line> Hash;
        //拆分节点分别hash
        NodeHashInital2(Hash, DATA);

        uint32_t s1 = Hash.size() % 2 == 0 ? Hash.size() : Hash.size() + 1;


        // 构建Merkle树——版本2
        buildMerkleTree2(Hash);

        cout << "****第二版 Merkle Patricia Tree 包含证明：\n";

        string chose;
        while (true) {
            uint32_t i = 0;
            cout << "\n请输入需要验证的节点序号i (0 <= i < " << s1 << "):";
            cin >> i;
            while (true) {
                if (Hash[i].father == 0xFFFF) {
                    cout << "顶层节点: " << i << "\n";
                    cout << "顶层节点的Hash值：" << Hash[i].st << endl;
                    break;
                }
                cout << "节点" << i << "的Hash值：" << Hash[i].st << endl;
                cout << "节点" << i << "的父级节点：" << Hash[i].father << endl;
                i = Hash[i].father;
            }
            cout << "是否继续[y/n]:";
            cin >> chose;
            if (chose == "n")
                break;

        }

        cout << "结束\n\n";

    }


    {
        vector<line> Hash;
        //拆分节点分别hash
        NodeHashInital3(Hash, DATA);

        uint32_t s1 = Hash.size();//树最底层

        // 构建Merkle树——版本3
        buildMerkleTree3(Hash);

        cout << "****第三版 Merkle Patricia Tree 包含证明：\n";
        string chose = "";
        while (true) {
            uint32_t i = 0;
            cout << "\n请输入需要验证的节点序号i (0 <= i < " << s1 << "):";
            cin >> i;
            while (true) {
                if (Hash[i].father == 0xFFFF) {
                    cout << "顶层节点: " << i << "\n";
                    cout << "顶层节点的Hash值：" << Hash[i].st << endl;
                    break;
                }
                cout << "节点" << i << "的Hash值：" << Hash[i].st << endl;
                cout << "节点" << i << "的父级节点：" << Hash[i].father << endl;
                i = Hash[i].father;
            }
            cout << "是否继续[y/n]:";
            cin >> chose;
            if (chose == "n")
                break;
        }

        cout << "结束\n\n";
    
    }
    return 0;

}

#endif


#ifdef Exclusion_Proof

#include<random>

int main() {

    {

        vector<line> Hash;
        //拆分节点分别hash
        NodeHashInital2(Hash, DATA);

        uint32_t s1 = Hash.size() % 2 == 0 ? Hash.size() : Hash.size() + 1;


        // 构建Merkle树——版本2
        buildMerkleTree2(Hash);

        cout << "****第二版 Merkle Patricia Tree 排除证明：\n";

        string chose;
        while (true) {
            string exclusion;
            vector<uint32_t> I;

            cout << "\n请输入想要证明不在 Merkle Tree 中的目标元素（可以是不与DATA有重合的任意字符）：";
            cin >> exclusion;

            string exhash = sha256(exclusion);
            cout << "得到hash值：" << exhash << endl;

            cout << "从顶层节点开始搜索：\n";
            uint32_t i = Hash.size() - 1;
            while (true) {
                if (i == 0xFFFF) {
                    cout << "已到达叶子节点，搜索结束\n";
                    cout << "本次搜索路径如下：";
                    for (const auto xx : I)
                        cout << " -> "<< xx;
                    cout << "\n";
                    break;
                }

                if (Hash[i].st == exhash) {
                    cout << "发现节点" << exclusion << "存在!\n位置：[" << i << "]\n";
                }
                else {
                    I.push_back(i);
                    cout << "节点[" << i << "] hash:" << Hash[i].st << endl;
                    
                    // 使用随机设备作为种子
                    random_device rd;

                    // 使用 Mersenne Twister 引擎
                    mt19937 gen(rd());

                    // 生成一个范围在 0 到 1（包括）的随机整数
                    uniform_int_distribution<> dis(0, 1);

                    if ((uint32_t)dis(gen) == 0) {
                        i = Hash[i].right;
                    }
                    else {
                        i = Hash[i].left;
                    }
                    
                }
            }
            cout << "是否继续[y/n]:";
            cin >> chose;
            if (chose == "n")
                break;

        }

        cout << "结束\n\n";

    }


    {
        vector<line> Hash;
        //拆分节点分别hash
        NodeHashInital3(Hash, DATA);

        uint32_t s1 = Hash.size();//树最底层

        // 构建Merkle树——版本3
        buildMerkleTree3(Hash);

        cout << "****第三版 Merkle Patricia Tree 排除证明：\n";
        
        string chose;
        while (true) {
            string exclusion;
            vector<uint32_t> I;

            cout << "\n请输入想要证明不在 Merkle Tree 中的目标元素（可以是不与DATA有重合的任意字符）：";
            cin >> exclusion;

            string exhash = sha256(exclusion);
            cout << "得到hash值：" << exhash << endl;

            cout << "从顶层节点开始搜索：\n";
            uint32_t i = Hash.size() - 1;
            while (true) {
                if (i == 0xFFFF) {
                    cout << "已到达叶子节点，搜索结束\n";
                    cout << "本次搜索路径如下：";
                    for (const auto xx : I)
                        cout << " -> " << xx;
                    cout << "\n";
                    break;
                }

                if (Hash[i].st == exhash) {
                    cout << "发现节点" << exclusion << "存在!\n位置：[" << i << "]\n";
                }
                else {
                    I.push_back(i);
                    cout << "节点[" << i << "] hash:" << Hash[i].st << endl;
                    
                    // 使用随机设备作为种子
                    random_device rd;

                    // 使用 Mersenne Twister 引擎
                    mt19937 gen(rd());

                    // 生成一个范围在 0 到 1（包括）的随机整数
                    uniform_int_distribution<> dis(0, 1);

                    if ((uint32_t)dis(gen) == 0) {
                        i = Hash[i].right;
                    }
                    else {
                        i = Hash[i].left;
                    }

                }
            }
            cout << "是否继续[y/n]:";
            cin >> chose;
            if (chose == "n")
                break;

        }

        cout << "结束\n\n";

    }
    return 0;

}
#endif


#endif
