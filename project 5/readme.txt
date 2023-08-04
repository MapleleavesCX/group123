项目5：按照RFC6962实现Merkle树


【运行环境】

1.代码语言为C++，采用 Visual Studio 2022 环境进行编程；

2.代码部分使用了外部密码库OpenSSL，版本：win64-3.3.1；代码项目的默认包含链接地址：D:\OpenSSL-Win64\include ； 默认库链接地址：D:\OpenSSL-Win64\lib . 若外部的OpenSSL安装地址发生更改，请修改项目的链接地址；

3.操作系统：windows64位


【操作指南】
1.main.cpp是主调文件，使用#ifdef、#endif语句划分为三个分区，每个分区有一个main函数，运行哪个分区则反注释哪个分区定义名。代码中有详细注释说明，此处不赘述。