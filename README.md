# H3C iNode Client for Linux

<br>

## 1. 说明
适用于H3C iNode客户端的替代登录器，此版本源代码分支于liuqun的h3c，对 iNode 7.0.0102 (E0102) 版本进行修改。

<br>

## 2. 源码目录
#### 1. 文件列表
* core.c&emsp;&emsp; -&emsp;&emsp;核心算法以及认证函数
* main.c&emsp;&emsp;-&emsp;&emsp;程序入口
* MD5.c&emsp;&emsp;-&emsp;&emsp;MD5算法实现
* MD5.h&emsp;&emsp;-&emsp;&emsp;MD5算法实现(头文件)
* makefile&emsp; -&emsp;&emsp;用于make的文件

#### 2. 编译
1. 复制项目到本地 git clone https://github.com/QCute/H3C.git
2. 进入目录 cd H3C
3. 编译及链接目标文件 make
4. 安装 sudo make install
5. 如需进行交叉编译，请先修改makefile中交叉编译器(CC)的定义，再进行编译。

<br>

## 3. 使用

#### 1. 参数列表 device(name) username password
* device(name)&emsp;&ensp;-&emsp;&emsp;设备名
* username&emsp;&emsp;&ensp;&nbsp;&nbsp;-&emsp;&emsp;用户名
* password&emsp;&emsp;&emsp; -&emsp;&emsp;密码

**必须提供全部并且有效的参数才能运行**

<br>

## 4. 附加说明

* 源代码使用Linux Raw Socket和BPF过滤机制，以及添加本地MD5库，不依赖libpcap和openssl开发库，可方便快速移植于OpenWRT等嵌入式Linux环境下。

* 此源代码仅适用于iNode 7.0.0102(E0102)版本，如非此版本，可自行修改版本号再进行测试，版本号定义在core.c文件中FillClientVersionArea函数下的H3C_VERSION中。

* 由于iNode客户端的心跳报文算法复杂多样，在此源代码中，只针对其中一种进行研究，其他情况可使用WireShark抓包作对比分析。

* 对于心跳报文，其算法因客户端版本不同而变化。但心跳报文总是每隔一分钟发送一次，如交换机(或服务器)累计七次未收到心跳报文就会主动断开连接。

* 对于在心跳报文算法未能获悉的情况下，客户端可以不发送心跳报文，在交换机(或服务器)主动断开之前，重新进行一次认证，这样便可继续使用。

* 如需帮助，可联系BALDOOR@qq.com获取帮助
