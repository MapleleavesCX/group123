#pragma once
#include <openssl/evp.h>
#include <iostream>
#include <iomanip>
#include <sstream>
#include<vector>
#include <chrono>
using namespace std;


template<typename Func, typename... Args>
void timing(Func func, Args&&... args)
{
    auto start = chrono::system_clock::now();
    func(args...);
    auto end = chrono::system_clock::now();
    auto duration = chrono::duration_cast<chrono::microseconds>(end - start);
    cout << "执行时间：" << duration.count() << " 微秒" << endl;

}







// 输入任意串，输出为字符串表示的十六进制数，长度64（每个字符代表4bit）
string sha256(const string& input) {
    EVP_MD_CTX* mdctx;
    const EVP_MD* md;
    unsigned char hash[EVP_MAX_MD_SIZE];
    unsigned int hash_len;

    md = EVP_sha256();
    mdctx = EVP_MD_CTX_new();
    EVP_DigestInit_ex(mdctx, md, NULL);
    EVP_DigestUpdate(mdctx, input.c_str(), input.length());
    EVP_DigestFinal_ex(mdctx, hash, &hash_len);
    EVP_MD_CTX_free(mdctx);

    stringstream ss;
    for (int i = 0; i < hash_len; i++) {
        ss << hex << setw(2) << setfill('0') << (int)hash[i];
    }

    return ss.str();
}

// 构建Merkle树——版本1——输入为叶节点Hash值
string buildMerkleTree(const vector<string>& Hash) {
    vector<string> merkleTree = Hash;

    while (merkleTree.size() > 1) {
        vector<string> newLevel;

        // 如果节点个数为奇数，复制最后一个节点，补齐为偶数
        if (merkleTree.size() % 2 != 0) {
            merkleTree.push_back(merkleTree.back());
        }

        for (int i = 0; i < merkleTree.size(); i += 2) {
            string combinedHash = sha256(merkleTree[i] + merkleTree[i + 1]);
            newLevel.push_back(combinedHash);
        }

        merkleTree = newLevel;
    }

    return merkleTree[0];
}

struct line
{
    uint32_t father;
    uint32_t left;
    uint32_t right;
    string st;
    line() {
        father = 0xFFFF;
        left = 0xFFFF;
        right = 0xFFFF;
    }
};

// 构建Merkle树——版本2——输入为叶节点Hash值
void buildMerkleTree2(vector<line>& Hash) {
    vector<line> merkleTree = Hash;
    uint32_t len = 0;

    while (merkleTree.size() > 1) {
        vector<line> newLevel;

        // 如果节点个数为奇数，复制最后一个节点，补齐为偶数
        if (merkleTree.size() % 2 != 0) {
            merkleTree.push_back(merkleTree.back());
            Hash.push_back(merkleTree.back());
        }

        for (int i = 0; i < merkleTree.size(); i += 2) {
            line combinedHash;
            combinedHash.st = sha256(merkleTree[i].st + merkleTree[i + 1].st);
            Hash[len + i].father = Hash.size() + i / 2;
            Hash[len + i + 1].father = Hash.size() + i / 2;
            combinedHash.left = len + i;
            combinedHash.right = len + i + 1;
            newLevel.push_back(combinedHash);
        }
        len += merkleTree.size();
        Hash.insert(Hash.end(), newLevel.begin(), newLevel.end());
        merkleTree = newLevel;
    }
}

//构建构建Merkle树——版本3——输入为叶节点Hash值
void buildMerkleTree3(vector<line>& Hash) {
    vector<line> merkleTree = Hash;
    uint32_t len = 0;
    while (merkleTree.size() > 1) {
        vector<line> newLevel(merkleTree.size() / 2);
        
        for (uint32_t i = 0; i < merkleTree.size() - 1; i += 2) {
            string a = merkleTree[i].st;
            string b = merkleTree[i+1].st;
            newLevel[i / 2].st = sha256(a + b);
            newLevel[i / 2].left = len + i;
            newLevel[i / 2].right = len + i + 1;
            Hash[len + i].father = Hash.size() + i / 2;
            Hash[len + i + 1].father = Hash.size() + i / 2;
        }


        // 如果节点个数为奇数，忽略到下一层
        if (merkleTree.size() % 2 != 0) {
            newLevel.push_back(merkleTree.back());
            Hash.back().father = Hash.size() + newLevel.size() - 1;
            newLevel.back().left = Hash.size() - 1;
            newLevel.back().right = Hash.size() - 1;
        }



        len += merkleTree.size();
        Hash.insert(Hash.end(), newLevel.begin(), newLevel.end());
        merkleTree = newLevel;
    }

}


void NodeHashInital2(vector<line>& Hash, string data) {
    int sign = 0;
    int len = data.size();
    int i = 0;
    while (len - sign >= 32) {
        line ttt;
        ttt.st = sha256(data.substr(sign, 32));
        Hash.push_back(ttt);
        sign += 32;
        i++;
    }
    if (len - sign < 32) {
        line last;
        last.st = sha256(data.substr(sign, len - sign));
        Hash.push_back(last);
    }
}


void NodeHashInital3(vector<line>& Hash_out, string data) {
    vector<line> Hash(data.size() / 32 + 1);

    uint32_t sign = 0;
    uint32_t len = data.size();
    uint32_t i = 0;
    while (len - sign >= 32) {
        Hash[i].st = sha256(data.substr(sign, 32));
        sign += 32;
        i++;
    }
    if (len - sign < 32) {
        Hash[i].st = sha256(data.substr(sign, len - sign));
    }
    Hash_out = Hash;
}

void printf_tree2(vector<line>& Hash, uint32_t s1) {

    uint32_t c = s1;
    cout << "最底层：\n";
    for (uint32_t i = 0; i < Hash.size(); i++) {

        if (i == s1) {
            cout << "\n下一层：\n";
            c /= 2;
            c = c % 2 == 0 ? c : c + 1;
            s1 += c;
        }
        cout << "[" << i << "] " << Hash[i].st << endl << endl;
    }

    cout << "结束\n\n";
}

void printf_tree3(vector<line>& Hash, uint32_t s1) {

    uint32_t c = s1;
    cout << "最底层：\n";
    for (uint32_t i = 0; i < Hash.size(); i++) {

        if (i == s1) {
            cout << "\n下一层：\n";
            if (c % 2 == 0)
            {
                c = c / 2;
                s1 += c;
            }
            else
            {
                c = c / 2 + 1;
                s1 += c;
            }
        }
        cout << "[" << i << "] " << Hash[i].st << endl << endl;
    }
}
