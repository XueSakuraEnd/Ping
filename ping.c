#include <stdio.h>
#include <winsock2.h>
#include <windows.h>
#include <iphlpapi.h>
#include <icmpapi.h>
#include <stdbool.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <time.h>
#include <process.h>
#define ICMP_ECHOREPLY 0 // ICMP 回应答复
#define ICMP_ECHOREQ 8   // ICMP 回应请求
#define REQ_DATASIZE 32  // 请求数据报大小
#define MAXTIME 10000    // 限定最大回复时间
// 加载静态库
#pragma comment(lib, "ws2_32.lib")
// 定义 IP 首部格式
typedef struct IPHeader
{
    unsigned char VIHL;        // 版本和首部长度 8
    unsigned char ToS;         // 服务类型 8
    unsigned short TotalLen;   // 总长度 16
    unsigned short ID;         // 标识号 16
    unsigned short Frag_Flags; // 片偏移量 16
    unsigned char TTL;         // 生存时间 8
    unsigned char Protocol;    // 协议 8
    unsigned short Checksum;   // 首部校验和 16
    struct in_addr SrcIP;      // 源 IP 地址 32
    struct in_addr DestIP;     // 目的地址 32
} IPHDR, *PIPHDR;

// 定义 ICMP 首部格式
typedef struct ICMPHeader
{
    unsigned char Type;      // 类型 8
    unsigned char Code;      // 代码 8
    unsigned short Checksum; // 首部校验和 16
    unsigned short ID;       // 标识 16
    unsigned short Seq;      // 序列号 16
    // char Data; //数据
} ICMPHDR, *PICMPHDR;

// 定义 ICMP 回应请求
typedef struct ECHOREQUEST
{
    ICMPHDR icmpHdr;
    DWORD Time; // 时间戳
    // char cData[REQ_DATASIZE];
} ECHOREQUEST, *PECHOREQUEST;

// 定义 ICMP 回应答复
typedef struct ECHOREPLY
{
    IPHDR ipHdr;
    ECHOREQUEST echoRequest;
    // char cFiller[256];
} ECHOREPLY, *PECHOREPLY;

// 计算校验和
unsigned short checksum(unsigned short *buffer, int len)
{
    int length = len;
    unsigned short *w = buffer;
    int sum = 0;
    // 32位累加器
    while (length > 1)
    {
        sum += *w++;
        length -= 2;
    }
    // 补全奇数位
    if (length == 1)
    {
        unsigned short u = 0;
        *(unsigned char *)(&u) = *(unsigned char *)w;
        sum += u;
    }
    // 第一次反码算数运算
    sum = (sum >> 16) + (sum & 0xffff);
    // 第二次反码算数运算
    sum += (sum >> 16);
    // 返回反码
    return (~sum); // 截取低16位
}

// 发送回应请求函数
DWORD SendEchoRequest(SOCKET s, struct sockaddr_in *lpstToAddr)
{
    static ECHOREQUEST echoReq;
    static int nSeq = 1;
    int nRet;
    // 填充回应请求消息
    echoReq.icmpHdr.Type = ICMP_ECHOREQ;
    echoReq.icmpHdr.Code = 0;
    echoReq.icmpHdr.Checksum = 0;
    echoReq.icmpHdr.ID = getpid();
    echoReq.icmpHdr.Seq = nSeq++;
    // 填充要发送的数据
    //  for (nRet = 0; nRet < REQ_DATASIZE; nRet++)
    //  {
    //      echoReq.cData[nRet] = '1' + nRet;
    //  }
    // 存储发送时间戳
    echoReq.Time = GetTickCount();
    // 计算回应请求的校验和
    echoReq.icmpHdr.Checksum = checksum((unsigned short *)&echoReq, sizeof(ECHOREQUEST));
    // 发送回应请求
    nRet = sendto(s, (LPSTR)&echoReq, sizeof(ECHOREQUEST), 0, (struct sockaddr *)lpstToAddr, sizeof(SOCKADDR_IN));
    if (nRet == SOCKET_ERROR)
    {
        printf("send to() error:%d\n", WSAGetLastError());
    }
    // else
    // {
    //     printf("send successfully!\n");
    // }
    return (echoReq.Time);
}

// 等待回应答复
int WaitForEchoReply(SOCKET s)
{
    struct timeval timeout;
    fd_set readfds;
    readfds.fd_count = 1;
    readfds.fd_array[0] = s;
    timeout.tv_sec = 1;
    timeout.tv_usec = 0;
    return (select(1, &readfds, NULL, NULL, &timeout));
}

// 接收应答回复并进行解析
DWORD RecvEchoReply(SOCKET s, LPSOCKADDR_IN lpsaFrom, u_char *pTTL)
{
    ECHOREPLY echoReply;
    int nRet;
    int nAddrLen = sizeof(struct sockaddr_in);
    // 接收应答回复
    nRet = recvfrom(s, (LPSTR)&echoReply, sizeof(ECHOREPLY), 0, (LPSOCKADDR)lpsaFrom, &nAddrLen);
    echoReply.echoRequest.Time = GetTickCount();
    // 检验接收结果
    if (nRet == SOCKET_ERROR)
    {
        printf("recvfrom() error:%d\n", WSAGetLastError());
    }
    // else
    // {
    //     printf("recieve successfully!\n");
    // }
    // 记录返回的 TTL
    *pTTL = echoReply.ipHdr.TTL;
    // 返回应答时间
    return (echoReply.echoRequest.Time);
}

// 解析地址
struct in_addr ResolveHost(char *ptr)
{
    const char *servicename = "http";
    // const char *hostname = "www.baidu.com";
    struct addrinfo hints, *res, *p;
    int status;

    // 初始化 hints 结构体
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;     // 支持 IPv4 和 IPv6
    hints.ai_socktype = SOCK_STREAM; // TCP

    // 解析主机名和服务名
    status = getaddrinfo(ptr, servicename, &hints, &res);
    if (status != 0)
    {
        fprintf(stderr, "getaddrinfo error: %s\n", gai_strerror(status));
        exit(0);
    }
    // else
    // {
    //     printf("resolve successfully!\n");
    // }
    // 遍历 addrinfo 链表，获取 IP 地址
    struct sockaddr_in *addr;
    for (p = res; p != NULL; p = p->ai_next)
    {
        addr = (struct sockaddr_in *)p->ai_addr;
    }
    freeaddrinfo(res);
    return addr->sin_addr;
}

// Ping功能实现
void Ping(char *ptr, bool log)
{
    // 回复次数,请求失败次数
    int recieved = 0, lost = 0;
    struct sockaddr_in srcIP;  // 回复地址
    struct sockaddr_in destIP; // 目标地址
    // 记录TTL
    unsigned char cTTL;
    // 记录回复标识符
    int nRet;
    // 创建原始套接字 ,ICMP 类型
    SOCKET rawSocket = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
    // 第二个注释函数 socket
    if (rawSocket == SOCKET_ERROR)
    {
        printf("socket() error:%d\n", WSAGetLastError());
        return;
    }
    // 设置目标机地址
    destIP.sin_addr = ResolveHost(ptr); // 设置目标 IP
    destIP.sin_family = AF_INET;        // 地址规格
    destIP.sin_port = 0;
    // 提示开始进行 PING
    printf("\nPinging %s [%s] with %d bytes of data:\n", ptr, inet_ntoa(destIP.sin_addr), REQ_DATASIZE);
    // 发起多次 PING 测试
    for (int i = 0; i < 4; i++)
    {
        if (log)
        {
            i = 0;
        }
        // 发送 ICMP 回应请求
        DWORD sendTime = SendEchoRequest(rawSocket, &destIP);
        // 等待回复的数据
        nRet = WaitForEchoReply(rawSocket);
        // 检测回复有没有错误
        if (nRet == SOCKET_ERROR)
        {
            printf("select() error:%d\n", WSAGetLastError());
            break;
        }
        if (!nRet)
        {
            lost++;
            printf("Request time out.\n");
            continue;
        }
        // 接收回复并记录
        DWORD reciveTime = RecvEchoReply(rawSocket, &srcIP, &cTTL);
        // 回复次数加1
        recieved++;
        // 计算花费的时间
        // printf("sendtime: %d,recievetime: %d",sendTime,reciveTime);
        DWORD timer = reciveTime - sendTime;
        if (timer < MAXTIME)
        {
            printf("REPLY FROM %s: bytes = %d time = %ldms TTL = %d\n", inet_ntoa(srcIP.sin_addr), REQ_DATASIZE, timer, cTTL);
        }
        else
        {
            printf("Request time out.\n");
        }
        Sleep(1000);
    }
    // 关闭socket套件
    nRet = closesocket(rawSocket);
    if (nRet == SOCKET_ERROR)
    {
        printf("closesocket() error:%d\n", WSAGetLastError());
    }
}

int main()
{
    printf("ping>\n");
    // 初始化Winsock库
    WSADATA wsaData;
    int result = WSAStartup(MAKEWORD(2, 2), &wsaData);
    if (result != 0)
    {
        fprintf(stderr, "WSAStartup failed: %d\n", result);
        return 1;
    }
    char input[100];
    char words[3][50];
    int count = 0;
    fgets(input, sizeof(input), stdin);
    char *token = strtok(input, " ");
    while (token != NULL)
    {
        strcpy(words[count], token);
        count++;
        token = strtok(NULL, " ");
    }
    char *ptr = words[1];
    bool log = false;
    if (strcmp(words[1], "-t") == 0)
    {
        log = true;
        ptr = words[2];
    }
    ptr[strlen(ptr) - 1] = '\0';
    // 开始ping
    Ping(ptr, log);

    // 清除Winsock库
    WSACleanup();

    return 0;
}
