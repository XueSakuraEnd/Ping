/*用于监听网络数据包的代码，实现了一个基于原始套接字的IP包捕获程序，可以用于获取网络流量的信息.
使用了Winsock和pcap库。定义了IP、TCP、UDP和ICMP协议头的结构体，通过收到的数据包的协议类型来调用相应的解包函数。
同时还有缓存数据包的变量、文件输出标志位等。最后使用Socket的recvfrom函数来接收数据包。*/

// 宏定义和常量设置
// 这些宏和常量用于定义各种套接字操作所需的额外信息，并将其编译为链接库。
#define RCVALL_ON 1                    // 定义了一个常量 RCVALL_ON，值为1,用于打开所有IP包的接收,用于设置socket的接收模式
#define MAX_ADDR_LEN 16                // 点分十进制地址的最大长度
#define MAX_PROTO_TEXT_LEN 16          // 子协议名称(如"TCP")最大长度
#define WINSOCK_VERSION MAKEWORD(2, 2) // 用于指定 Winsock 库的版本号
#pragma comment(lib, "Ws2_32.lib")     // pragma comment 指令链接所需的库文件。
#pragma comment(lib, "wpcap.lib")
#pragma comment(lib, "iphlpapi.lib")
#pragma warning(disable : 4996) // 指令用于禁用警告信息,禁用某些编译器警告

// 导入需要的头文件
// 这些头文件包含了程序所用到的各种系统函数和库函数。
#include <stdio.h>
#include <WinSock2.h>
#include <Windows.h>
#include <stdlib.h>
#include <string.h>
#include <pcap.h>
#include <time.h>
#include <ctype.h>
#include <mstcpip.h>
#include <conio.h>
#include <ws2tcpip.h>
#include <iphlpapi.h>

// 结构体定义：定义了 IP、TCP、UDP、ICMP 协议的数据包头部的结构体
typedef struct iphdr // 定义IP首部
{
    unsigned char h_lenver;        // 4位首部长度+4位IP版本号
    unsigned char tos;             // 8位服务类型TOS
    unsigned short total_len;      // 16位总长度（字节）
    unsigned short ident;          // 16位标识
    unsigned short frag_and_flags; // 3位标志位
    unsigned char ttl;             // 8位生存时间 TTL
    unsigned char proto;           // 8位协议 (TCP, UDP 或其他)
    unsigned short checksum;       // 16位IP首部校验和
    unsigned int sourceIP;         // 32位源IP地址
    unsigned int destIP;           // 32位目的IP地址
} IPHeader;
typedef struct _tcphdr // 定义TCP首部
{
    USHORT th_sport;         // 16位源端口
    USHORT th_dport;         // 16位目的端口
    unsigned int th_seq;     // 32位序列号
    unsigned int th_ack;     // 32位确认号
    unsigned char th_lenres; // 4位首部长度/6位保留字
    unsigned char th_flag;   // 6位标志位
    USHORT th_win;           // 16位窗口大小
    USHORT th_sum;           // 16位校验和
    USHORT th_urp;           // 16位紧急数据偏移量
} TCP_HEADER;
typedef struct _udphdr // 定义UDP首部
{
    unsigned short uh_sport; // 16位源端口
    unsigned short uh_dport; // 16位目的端口
    unsigned short uh_len;   // 16位长度
    unsigned short uh_sum;   // 16位校验和
} UDP_HEADER;
typedef struct _icmphdr // 定义ICMP首部
{
    BYTE i_type;     // 8位类型
    BYTE i_code;     // 8位代码
    USHORT i_cksum;  // 16位校验和
    USHORT i_id;     // 识别号（一般用进程号作为识别号）
    USHORT i_seq;    // 报文序列号
    ULONG timestamp; // 时间戳
} ICMP_HEADER;

/*(全局变量定义)定义了一些变量，其中 iTTL 表示生存时间，iLEN 表示长度，iBYTES 表示字节数，szSourceIP 和 szDestIP 分别表示源IP地址和目的IP地址，
 iSourcePort 和 iDestPort 分别表示源端口号和目的端口号，fflag 表示文件输出标志位。
 这些全局变量在程序中用于存储捕获的IP数据包的相关信息。*/
int iTTL, iLEN, iBYTES;
char szSourceIP[MAX_ADDR_LEN], szDestIP[MAX_ADDR_LEN]; // 定义了两个字符数组，MAX_ADDR_LEN 是这两个数组(点分十进制地址)的最大长度
int iSourcePort, iDestPort;
int fflag = 0;                               // file flag
#define PACKAGE_SIZE sizeof(IPHeader) + 1000 // 定义宏其名为 PACKAGE_SIZE，值为 IPHeader 结构体的大小加1000 字节。用于定义一个缓冲区大小以便在截取网络数据包时存储数据。

// 函数声明:这些函数是程序中实现对不同数据包类型的解析和处理的核心函数，其中HandleError()用于处理错误信息。
// functions  声明了一个函数 HandleError，用于处理错误。
void HandleError(char *func);            // 参数是一个指向 char 类型的指针
int DecodeTcpPack(char *, int, FILE *);  // TCP解包函数
int DecodeUdpPack(char *, int, FILE *);  // UDP解包函数
int DecodeIcmpPack(char *, int, FILE *); // ICMP解包函数

// MAIN主函数
/*在函数中主要完成以下操作：
①初始化Winsock库。
②创建原始套接字。
③绑定套接字。
④设置SOCK_RAW为SIO_RCVALL以便接收所有到达的IP数据包。
⑤监听IP数据包。
⑥根据数据包类型调用对应的解包函数。
⑦关闭文件并释放套接字，退出程序。*/
int main(int argc, char *argv[]) // 第一个参数是参数个数，第二个参数是一个字符串数组
{
    SOCKADDR_IN saSource, saDest; // 定义了一些变量和函数，其中 SOCKADDR_IN 是一个结构体，代表一个 socket 地址，在这里用来表示源地址和目的地址
    WSADATA wsaData;              // WSADATA 结构体用于初始化 Winsock 库

    /*Winsock 是 Windows 中用于 socket 编程的 API，它提供了一组函数和数据结构，使程序员可以使用 TCP/IP 和 UDP/IP 协议进行网络通信。
    在使用 Winsock API 之前，需要调用 WSAStartup 函数来初始化 Winsock 库。
    WSADATA 结构体包含了 Winsock 库的详细信息，WSAStartup 函数将这些信息填充到 WSADATA 结构体中。*/

    char buf[PACKAGE_SIZE];                // buf 数组用于存储接收到的数据包
    WSAStartup(WINSOCK_VERSION, &wsaData); // WSAStartup 函数用于初始化 Winsock 库

    /*在使用Winsock库进行网络编程时，首先要调用WSAStartup函数来初始化Winsock库。该函数的第一个参数是Winsock库的版本号，
    第二个参数是指向WSADATA结构的指针.用来存储初始化后的Winsock库的信息*/

    SOCKET sock = socket(AF_INET, SOCK_RAW, IPPROTO_IP); // socket() 函数用于创建一个新的 原始套接字socket，
    // 第一个参数指定地址族为IPv4，第二个参数指定 socket 类型为原始套接字，第三个参数指定协议类型为IP协议。

    /*使用 Winsock API 创建套接字
    //这个 if 语句判断 socket 是否创建成功，如果失败，则调用 HandleError() 函数输出错误信息并清理 Winsock(AP环境) 库，并返回 -1。*/
    if (sock == SOCKET_ERROR)
    {
        HandleError("socket");
        WSACleanup();
        return -1;
    }

    // 获取本机IP地址
    /*这几行代码用于绑定 socket 到一个本地 IP 地址和端口/
    gethostname() 函数用于获取本机名称，
    gethostbyname() 函数用于获取该主机的 IP 地址列表，memcpy() 函数用于将 IP 地址复制到 addr.sin_addr.S_un.S_addr 字段中，
    bind() 函数将 socket 绑定到本地地址和端口，AF_INET 表示 IPv4 地址族。*/
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr)); // 结构体清零，&addr 是一个结构体地址，sizeof(addr) 是结构体的大小，将 addr 结构体中的所有成员都设置为 0
    // addr.sin_addr.S_un.S_addr = inet_addr("192.168.1.101");
    char name[256];    // 字符数组，存储主机名
    PHOSTENT hostinfo; // 定义了一个 PHOSTENT 类型的指针变量 hostinfo，用于存储获取到的主机信息
    if (gethostname(name, sizeof(name)) == 0)
    // 使用 gethostname 函数获取本机主机名并存入 name 数组(存储主机名的缓冲区)中
    // sizeof(name)返回的是name数组的大小，即缓冲区大小.
    // gethostname函数执行成功，返回0，否则返回-1。若成功获取本地主机名，则执行下一步操作
    {
        if ((hostinfo = gethostbyname(name)) != NULL)
        // 调用 gethostbyname 函数获取该主机名对应的 IP 地址，并将其存入 hostinfo 结构体中
        // 如果获取成功，返回值不为 NULL。将 IP 地址复制到 addr 结构体的 sin_addr 字段中
        /*memcpy 函数的作用是将 hostinfo->h_addr_list 指向的 IPv4 地址复制到 sockaddr_in 结构体的 sin_addr 字段：addr.sin_addr.S_un.S_addr 中。
        注意，在 Windows 平台下，sin_addr 是一个联合体，因此需要使用 S_un.S_addr 来访问其中的 in_addr 结构体*/

        /*使用了 memcpy 函数将 hostinfo->h_addr_list 中的 struct in_addr 结构体中的地址复制到 addr.sin_addr.S_un.S_addr 中。
hostinfo->h_addr_list 存储了一个主机的 IP 地址列表，其中每个 IP 地址都是一个 struct in_addr 结构体。
而 addr.sin_addr.S_un.S_addr 是一个 in_addr_t 类型的变量，表示网络字节序的 IP 地址。
因为 memcpy 函数只能复制内存中的数据，所以需要将 hostinfo->h_addr_list 中的指针强制转换为 struct in_addr* 类型，从而获取每个 IP 地址的内存地址，
再将这个地址的内容复制到 addr.sin_addr.S_un.S_addr 中。同时，使用 sizeof((struct in_addr*)*hostinfo->h_addr_list)
来获取 hostinfo->h_addr_list 中 struct in_addr* 类型指针的大小，并将这个大小作为 memcpy 函数的第三个参数，确保只复制了一个 struct in_addr 结构体的大小*/

        {
            memcpy(&(addr.sin_addr.S_un.S_addr), (struct in_addr *)*hostinfo->h_addr_list, sizeof((struct in_addr *)*hostinfo->h_addr_list));
        }
    }
    addr.sin_family = AF_INET; // 设置一个套接字地址结构中的地址族成员:将地址族设置为 AF_INET（IPv4）
    // 套接字地址结构是用于在网络编程中表示一个套接字的地址和端口的结构体。

    if (bind(sock, (struct sockaddr *)&addr, sizeof(addr)) == SOCKET_ERROR) // 调用 bind 函数将套接字和本地IP地址和端口号绑定。如果绑定失败，调用 HandleError 函数进行处理。
    {                                                                       // sock 是一个已创建并初始化的套接字，addr 是一个 sockaddr 类型的结构体变量，存储了要绑定的 IP 地址和端口号信息。
        // 如果绑定成功，bind 函数会返回 0，否则返回 SOCKET_ERROR
        HandleError("bind");
    }

    // 设置SOCK_RAW为SIO_RCVALL，以便接收所有的IP包,所有通过网卡的数据包，而不仅仅是目标地址是本机的数据包
    // 用于设置 socket 为混杂模式，打开 WinPcap 库的混杂模式,即接收所有的传输层协议数据包。WSAIoctl() 函数用于设置 socket 属性
    int on = RCVALL_ON;
    DWORD num;                                                                                  // 无符号整数变量，用来存储一个数值。
    if (WSAIoctl(sock, SIO_RCVALL, &on, sizeof(on), NULL, 0, &num, NULL, NULL) == SOCKET_ERROR) // 调用了 Windows 套接字 API 的 WSAIoctl 函数
    /*SIO_RCVALL 常量作为第一个参数传入。 SIO_RCVALL 常量用于设置套接字的接收模式，它允许套接字接收本地网络接口收到的所有数据包，而不仅仅是目标地址与套接字绑定的数据包
    2nd指向 on 变量的指针，该变量用于指定是否启用 SIO_RCVALL 模式。如果 on 变量的值为 0，则禁用 SIO_RCVALL 模式，如果 on 变量的值为非零，则启用 SIO_RCVALL 模式
    3rd指向 num 变量的指针，用于指定接收到的数据包的数量,若该参数不为 NULL，则函数将 num 变量设置为接收到的数据包的数量
    如果 SIO_RCVALL 模式启用成功，则函数返回值为零；否则，返回 SOCKET_ERROR。如果函数返回 SOCKET_ERROR，则可以调用 WSAGetLastError 函数以获取错误代码*/
    {
        HandleError("wsaIoctl set");
    }

    // 这里定义了一个 sockaddr_in 结构体，用于接收传入数据包的源地址信息。fopen() 函数打开一个名为"log.txt"文件，并将文件指针保存在指针变量fp中
    // 如果文件打开失败，则将 fflag 变量设置为 1。
    // 文件打开方式为"w+"，表示以读写方式打开文件，若文件不存在则创建新文件
    struct sockaddr_in from;
    int fromlen;
    int size;
    FILE *fp;
    if ((fp = fopen("log.txt", "w+")) == NULL)
    {
        printf("open file errer,can't save list to file");
        fflag = 1;
    }

    // 侦听IP报文
    /*这个代码段用于循环接收传入的数据包
    memset() 函数用于清空缓冲区，recvfrom() 函数用于接收数据包，如果接收失败则调用 HandleError() 函数输出错误信息，然后继续循环。*/
    IPHeader *iph = (IPHeader *)buf; // 将 buf(接收到的数据包的缓冲区地址) 强制转换为了 IPHeader 结构体指针，用于解析网络数据包中的 IP 头信息。
    while (!kbhit())                 //,kbhit() 函数用于判断是否有键盘输入，如果有则跳出循环。没有则进入循环，等待接收网络数据包
    {
        // void* memset(void* s, int c, size_t n);
        // s：表示要清零的内存地址。c：表示要设置的值，一般为 0。n：表示要清零的字节数。该函数的作用是将 s 指向的内存区域的前 n 个字节全部设置为值 c
        memset(buf, 0, sizeof(num)); // 使用 memset 函数将 buf 数组和 from 结构体清零，避免出现脏数据
        memset(&from, 0, sizeof(from));
        fromlen = sizeof(from);
        size = recvfrom(sock, buf, PACKAGE_SIZE, 0, (struct sockaddr *)&from, &fromlen);
        // 调用 recvfrom 函数接收网络数据包:接收数据的套接字,缓冲区,缓冲区大小,数据包源地址信息(发送数据的主机的地址和端口号),地址信息长度
        // recvfrom 函数会一直阻塞程序，直到接收到数据包。函数返回值 size 表示接收到的数据包大小
        /*SOCKET_ERROR 是一个返回值，表示函数执行失败。如果函数返回值等于 SOCKET_ERROR，那么就需要检查错误码，
        如果错误码是 WSAEMSGSIZE，说明接收缓冲区不足以存放接收到的数据报，需要重新调整接收缓冲区的大小，然后重新接收数据。
        如果错误码不是 WSAEMSGSIZE，就调用 HandleError 函数进行错误处理*/

        if (size == SOCKET_ERROR)
        {
            if (WSAGetLastError() == WSAEMSGSIZE)
            {
                HandleError("recvfrom");
                continue;
            }
        }

        // 此代码段用于解析 IP 数据包，将源地址、目的地址和 TTL 存储到相应的变量中，inet_ntoa() 函数用于将 IP 地址转换成字符串格式
        // IPHeader 结构体用于解析 IP 数据包。
        IPHeader *iph = (IPHeader *)buf;
        /**/
        // 源地址
        saSource.sin_addr.s_addr = iph->sourceIP; // 源 IP 地址设置给 saSource.sin_addr.s_addr
        // saSource 是sockaddr_in 结构体，用于存储 IP 地址和端口号信息.sin_addr 是in_addr 结构体. s_addr 是一个 32 位无符号整数，表示 IP 地址的二进制形式
        strncpy(szSourceIP, inet_ntoa(saSource.sin_addr), MAX_ADDR_LEN);
        /*将 saSource.sin_addr 指向的 IP 地址转换成字符串形式并复制到 szSourceIP 数组中，其中 MAX_ADDR_LEN 是 szSourceIP 数组的最大长度。
        inet_ntoa() 是一个库函数，它将一个 sockaddr_in 结构体中的 IP 地址转换成点分十进制的字符串形式。
        saSource.sin_addr 是一个 in_addr 类型的结构体变量，它包含了待转换的 IP 地址，即该变量的 s_addr 成员变量。
        strncpy() 是一个库函数，它可以将源缓冲区中指定长度的数据复制到目标缓冲区中，以确保不会出现缓冲区溢出的情况*/

        // 目的地址
        saDest.sin_addr.s_addr = iph->destIP;
        strncpy(szDestIP, inet_ntoa(saDest.sin_addr), MAX_ADDR_LEN);
        iTTL = iph->ttl; // iph 是指向 IP 头部的指针，ttl 是 IP 头部中的 TTL 字段。将 TTL 字段的值赋给变量 iTTL
        /*IP 头部是 Internet 协议中定义的一种数据结构，用于在网络中传输 IP 数据包。
        TTL 字段表示数据包在网络中可以通过的最大跳数，每经过一个路由器，TTL 值就会减一，当 TTL 值为零时，数据包就会被丢弃*/

        // 计算IP首部的长度
        int IpHeadLen = 4 * (iph->h_lenver & 0xf);
        /*h_lenver 是该结构体中的一个字段，用于存储 IP 数据包头部长度和版本号信息。
        通过将 h_lenver 与 0xf（即二进制的 1111）进行按位与运算，可以得到 IP 数据包头部长度所占的 4 字节的个数。
        因为一个字节占 8 位，所以将这个值乘以 4 就可以得到 IP 数据包头部实际的字节数*/

        // 根据协议类型分别调用相应的解包函数:
        // 其中 IPPROTO_ICMP 表示 ICMP 协议类型，IPPROTO_IGMP 表示 IGMP 协议类型，IPPROTO_TCP 表示 TCP 协议类型，IPPROTO_UDP 表示 UDP 协议类型
        switch (iph->proto) // proto 是 IP 报文中的协议字段，用于标识上层协议,如UDP,TCP
        {
        case IPPROTO_ICMP:
            DecodeIcmpPack(buf + IpHeadLen, size, fp);
            /*buf + IpHeadLen 表示一个指向 ICMP 报文的指针，IpHeadLen 是 IP 报文头部长度，加上这个长度就可以跳过 IP 报文头部，指向 ICMP 报文的内容部分
            fp 是一个文件指针，用于将 ICMP 报文的信息写入文件中*/
            break;
        case IPPROTO_IGMP:
            printf("IGMP ");
            printf("%15s: ->%15s: ", szSourceIP, szDestIP);
            printf("%d", size);
            printf("%s\n", buf);
            break;
        case IPPROTO_TCP:
            DecodeTcpPack((buf + IpHeadLen), size, fp);
            break;
        case IPPROTO_UDP:
            DecodeUdpPack(buf + IpHeadLen, size, fp);
            break;
        default:
            printf("unknown datagram from %s/n", inet_ntoa(from.sin_addr)); // 打印未知协议的来源 IP 地址，使用了 inet_ntoa 函数将二进制的 IP 地址转换成可读的字符串格式
            printf("%s\n", buf);                                            // 打印出 buf 字符串，它是指向未知协议报文的指针
            break;
        }              // end switch
        Sleep(200);    // 程序休眠 200 毫秒
    }                  // end while
    fclose(fp);        // 关闭文件指针 fp 所指向的文件
    closesocket(sock); // 关闭套接字，即断开与网络的连接
    WSACleanup();      // 清理 Winsock 库，即释放动态链接库所占用的资源
    printf("Stopped!/n");
    getch(); // 等待用户输入一个字符，用来暂停程序的执行，以便查看输出结果
    return 0;
} // end of main
// TCP解包程序
int DecodeTcpPack(char *TcpBuf, int iBufSize, FILE *fp) // 3参：指向 TCP 数据包的缓冲区、缓冲区大小和一个指向文件的指针
{
    unsigned char FlagMask;
    FlagMask = 1;
    int i;
    TCP_HEADER *tcph;
    tcph = (TCP_HEADER *)TcpBuf;
    /*定义了一个指向 TCP 头部的指针 tcph，并将其指向一个名为 TcpBuf 的缓冲区。
这个缓冲区中应该是一个完整的 TCP 数据包，通过将指针指向 TCP 头部的方式，可以对 TCP 头部进行解析和分析*/

    // 计算TCP首部长度
    /*TcpBuf 是指向完整的网络数据包的指针。TcpHeadLen 用于存储 TCP 协议头部的长度，通过将 tcph->th_lenres 右移 4 位，可以得到 TCP 协议头部长度的值。
    由于这个长度值是以 4 字节为单位的，所以需要乘以 sizeof(unsigned long) 得到实际的字节数。TcpData 指向 TCP 数据部分的指针，即网络数据包中 TCP 协议头部之后的部分。
    iSourcePort 和 iDestPort 分别存储源端口和目的端口，可以通过 ntohs() 函数将网络字节序转换为主机字节序。*/
    int TcpHeadLen = tcph->th_lenres >> 4;
    TcpHeadLen *= sizeof(unsigned long);
    char *TcpData = TcpBuf + TcpHeadLen;
    iSourcePort = ntohs(tcph->th_sport); // 将网络字节序（big-endian）的源端口号转换为本地字节序（little-endian）的一个无符号短整型数值
    iDestPort = ntohs(tcph->th_dport);

    // 输出
    printf("TCP ");
    printf("%15s:%5d ->%15s:%5d ", szSourceIP, iSourcePort, szDestIP, iDestPort);
    printf("TTL=%3d ", iTTL);
    if (fflag == 1) // FlagMask 是一个掩码，用于逐个检查标志位是否被设置
        // 判断TCP标志位
        /*首先检查当前标志位是否被设置，如果被设置则输出 1，否则输出 0，然后将掩码左移一位，以检查下一个标志位。
        最终输出的结果是一个 6 位二进制数，可以通过将其转换为十进制数来判断 TCP 报文头部的状态*/
        for (i = 0; i < 6; i++)
        {
            if ((tcph->th_flag) & FlagMask) // 每次循环都将 FlagMask 左移一位，并与标志位进行与运算
                printf("1");
            else
                printf("0");
            FlagMask = FlagMask << 1;
        }
    printf(" bytes=%4d", iBufSize);
    printf("\n");
    if (fflag = 1) // fflag 变量的值为 1 时才会写入文件
        fprintf(fp, "TCP %15s:%5d ->%15s:%5d TTL=%3d ------ bytes=%4d\n", szSourceIP, iSourcePort, szDestIP, iDestPort, iTTL, iBufSize);
    return 0;
}
// UDP解包程序
int DecodeUdpPack(char *UdpBuf, int iBufSize, FILE *fp)
{
    UDP_HEADER *udph;
    udph = (UDP_HEADER *)UdpBuf;
    iSourcePort = ntohs(udph->uh_sport);
    iDestPort = ntohs(udph->uh_dport);
    // 输出
    printf("UDP ");
    printf("%15s:%5d ->%15s:%5d ", szSourceIP, iSourcePort, szDestIP, iDestPort);
    printf("TTL=%3d ", iTTL);
    printf("Len=%4d ", ntohs(udph->uh_len));
    printf("bytes=%4d", iBufSize);
    printf("/n");
    if (fflag = 1) // 写入文件
        fprintf(fp, "UDP %15s:%5d ->%15s:%5d TTL=%3d Len=%4d bytes=%4d/n", szSourceIP, iSourcePort, szDestIP, iDestPort, iTTL, ntohs(udph->uh_len), iBufSize);
    return 0;
}
// ICMP解包程序
int DecodeIcmpPack(char *IcmpBuf, int iBufSize, FILE *fp)
{
    ICMP_HEADER *icmph;
    icmph = (ICMP_HEADER *)IcmpBuf;
    int iIcmpType = icmph->i_type; // i_type 和 i_code 是 ICMP 协议报文头中的两个字段。iIcmpType 和 iIcmpCode 是用来存储获取到的类型和代码字段的整型变量
    int iIcmpCode = icmph->i_code;
    // 输出
    printf("ICMP ");
    printf("%15s ->%15s ", szSourceIP, szDestIP);
    printf("TTL=%3d ", iTTL);
    printf("Type%2d,%d ", iIcmpType, iIcmpCode);
    printf("bytes=%4d", iBufSize);
    printf("/n");
    if (fflag = 1) // 写入文件
        fprintf(fp, "ICMP %15s ->%15s TTL=%3d Type%2d,%d bytes=%4d", szSourceIP, szDestIP, iTTL, iIcmpType, iIcmpCode, iBufSize);
    return 0;
}

// 此函数用于输出错误信息，_snprintf() 函数用于将格式化的字符串输出到指定的缓冲区中，WSAGetLastError() 函数用于获取上一个 Winsock 函数调用的错误代码。
// 用于处理套接字操作中出现的错误信息并将其输出
void HandleError(char *func) // func 参数是调用 Winsock API 函数的函数名
/*接受一个指向字符数组的指针 func，表示出错的函数名或操作，然后会在控制台输出一个错误信息，指明出错的函数或操作，并退出程序*/
{
    char info[65] = {0};
    /*定义了一个长度为 65 的字符数组 info，并将其所有元素初始化为 0。
    这个数组可以用来存储字符串，最多可以存储 64 个字符，因为最后一个字符需要留给字符串的终止符 \0。*/
    _snprintf(info, 64, "%s: %d\n", func, WSAGetLastError());
    /*_snprintf 函数将格式化的字符串输出到 info 缓冲区中。具体来说，这行代码的作用是将 func 和 WSAGetLastError() 函数的返回值格式化为一个字符串，
    并将其存储在 info 缓冲区中，最大长度为 64 个字符,func 是一个字符串变量*/

    // WSAGetLastError() 函数是一个 Windows Sockets API 函数,可以获取最近一次 Winsock API 调用失败的错误码，然后将错误码和函数名格式化输出到控制台。
    printf(info);
}
