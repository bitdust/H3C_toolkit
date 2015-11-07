# H3C_toolkit
针对 H3C inode 802.1x 认证服务的开发工具组
参照了liuqun的[njit8021xclient](https://github.com/liuqun/njit8021xclient)认证客户端以及[tengattack的windows分支](https://github.com/tengattack/8021xclient-for-windows)完成开发。

目前包括工具：dummy_H3C、version_sniffer
## version_sniffer
inode客户端版本捕获及解码工具

用于全自动嗅探出当前主机的inode客户端认证版本号。可以输出：
* ASCII格式
* 16进制表示，用于核对是否包含隐藏符号
* C语言格式，用于第三方客户端开发。

![截图](https://cloud.githubusercontent.com/assets/6072743/11017213/62e1d762-85d3-11e5-988c-ecf27cce0058.png)

### 使用方法
0. 安装winpcap；
1. 完全退出inode；
2. 编译运行 version_sniffer ；
3. 选择网卡；
4. 等待程序准备完毕后，打开inode，开始登录；
5. 耐心等待输出结果。

## dummy_H3C
802.1x服务器/交换机虚拟工具，用于第三方iNode客户端的开发与调试。
### 使用方法
1. 使用Wireshark抓取iNode认证流程；
2. 修改dummy_H3C代码，使其模拟交换机进行发包；
3. 编译运行dummy_H3C,选择网卡；
4. 打开你的inode/第三方认证客户端，进行调试。

## 编译&依赖
编译环境为 Visual Studio 2013

依赖 winpcap，请从官方网站下载 

[Winpcap二进制安装包](http://www.winpcap.org/install/default.htm) 

以及

[Winpcap开发包](http://www.winpcap.org/devel.htm),并将其解压放置于Wpdpack文件夹中。
