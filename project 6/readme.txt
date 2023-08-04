Project 6: Range Proof With Hash Function .impl this protocol with actual network communication
项目6：使用hash函数的范围证明，在真实网络环境中实现这个方案

【运行环境】

1.代码语言为C++，采用 Visual Studio 2022 环境进行编程；

2.笔者在本项目中采用了windows系统的网络编程，请确保代码运行在windows系统下；

3.代码大量使用了外部密码库OpenSSL，版本：win64-3.3.1；代码项目的默认包含链接地址：D:\OpenSSL-Win64\include ； 默认库链接地址：D:\OpenSSL-Win64\lib . 若外部的OpenSSL安装地址发生更改，请修改项目的链接地址；


【操作指南】

1.项目6本身包含三个子项目“Project6_Trusted_Issuer”、“Project6_Prover”以及“Project6_Verifier”，主调函数所在文件分别为：
*Trusted_Issuer.cpp
*Prover.cpp
*Verifier.cpp
其中Prover.cpp和Verifier.cpp都需要初始设定好IP地址等参数，详见各自cpp文件的main函数开头；

为模拟真实网络环境，应分别在三台不同地址的主机上运行，若可以满足三台主机的联网测试需求，请阅读第2条；若不满足，请阅读第3条；

2. 若可以满足三台主机的联网测试的条件，我们分别简称为主机1、2、3，与第一点子项目列出顺序一一对应。
（1）主机1、3的IP地址需要在三台主机之间公布，作为服务端接收客户端的接入请求；
（2）主机运行顺序：1->3（启动本地服务端后）->2;
（3）“Project6_Prover”验证用的年份输入：默认为2000，可根据需要更改；“Project6_Verifier”的服务端启动口令为：go

3. 若在单台主机上运行三个子项目，则需要有一个严格的启动顺序：首先运行“Project6_Trusted_Issuer”，其次“Project6_Prover”或者“Project6_Verifier”，然后查看“Project6_Prover”显示等待输入年份以及“Project6_Verifier”显示等待输入口令时，关闭“Project6_Trusted_Issuer”（因为同一主机不能同时运行两个服务端），在“Project6_Verifier”的窗口输入启动口令：go ， 最后在“Project6_Prover”窗口输入用于证明的年份，默认为2000，可根据需要更改；
三个子项目都在单台主机运行，所以需要把所有IP都修改为本地IP。
