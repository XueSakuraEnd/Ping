#include <stdio.h>
#include <winsock2.h>
#include <windows.h>
#include <iphlpapi.h>
#include <icmpapi.h>
#include <stdbool.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <time.h>
#include "iphdr.h"
#include <process.h>
#define ICMP_ECHOREPLY 0 // ICMP 回应答复
#define ICMP_ECHOREQ 8   // ICMP 回应请求
#define REQ_DATASIZE 28  // 数据报大小 28字节
#define MAXTIME 10000    // 限定最大回复时间
// 加载静态库
#pragma comment(lib, "ws2_32.lib")

// icmp数据
typedef struct ICMPData
{
    DWORD Time;               // 时间戳 4 字节
    char cData[REQ_DATASIZE]; // 具体数据 28 字节
} ICMPData, *PICMPData;

// 定义 ICMP 回应请求
typedef struct ECHOREQUEST
{
    // IPHDR ipHdr; // ip 头 20 字节
    ICMPHDR icmpHdr; // 8 字节
    ICMPData data;   // 具体数据 28字节
} ECHOREQUEST, *PECHOREQUEST;

// 定义 ICMP 回应答复
typedef struct ECHOREPLY
{
    IPHDR ipHdr;     // ip 头 20 字节
    ICMPHDR icmpHdr; // 8 字节
    ICMPData data;   // 具体数据 28 字节
} ECHOREPLY, *PECHOREPLY;

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

// 返回本地ip
struct in_addr returnHost()
{
    struct hostent *host_entry;
    char *IPbuffer;
    char hostbuffer[256];
    int hostname;
    hostname = gethostname(hostbuffer, sizeof(hostbuffer)); // 检索本地计算机的标准
    // 接收主机信息
    host_entry = gethostbyname(hostbuffer); // 从主机数据库中检索与主机名对应的主机信息
    // 转换网络地址
    IPbuffer = inet_ntoa(*((struct in_addr *)host_entry->h_addr_list[0])); // 转换字符串
    return ResolveHost(IPbuffer);
}

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
    // // 第一次反码算数运算
    // sum = (sum >> 16) + (sum & 0xffff);
    // // 第二次反码算数运算
    // sum += (sum >> 16);
    while (sum >> 16)
    {
        sum = (sum >> 16) + (sum & 0xffff);
    }
    // 返回反码
    return (~sum); // 截取低16位
}

// 发送回应请求函数
DWORD SendEchoRequest(SOCKET s, struct sockaddr_in *lpstToAddr, struct sockaddr_in *hostAddr)
{
    static ECHOREQUEST echoReq;
    static int nSeq = 1; // 标识号 序号
    int nRet;
    // 填充ip头部
    // unsigned char vl = 0;
    // vl = vl | 4;
    // vl = vl | (5 << 4);
    // echoReq.ipHdr.VIHL = vl;
    // echoReq.ipHdr.ToS = 0;
    // echoReq.ipHdr.TotalLen = 60;
    // echoReq.ipHdr.ID = nSeq;
    // echoReq.ipHdr.Frag_Flags = 0;
    // echoReq.ipHdr.TTL = 128;
    // echoReq.ipHdr.Protocol = 1;
    // echoReq.ipHdr.Checksum = 0;
    // echoReq.ipHdr.SrcIP = hostAddr->sin_addr;
    // echoReq.ipHdr.DestIP = lpstToAddr->sin_addr;
    // // 计算ip首部检验和
    // echoReq.ipHdr.Checksum = checksum((unsigned short *)&(echoReq.ipHdr), sizeof(IPHDR));
    // 填充回应请求消息
    // 填充icmp头部
    echoReq.icmpHdr.Type = ICMP_ECHOREQ;
    echoReq.icmpHdr.Code = 0;
    echoReq.icmpHdr.Checksum = 0;
    echoReq.icmpHdr.ID = getpid();
    echoReq.icmpHdr.Seq = nSeq++;
    // 填充要发送的数据
    for (nRet = 0; nRet < REQ_DATASIZE; nRet++)
    {
        echoReq.data.cData[nRet] = '1' + nRet;
    }
    // 存储发送时间戳
    echoReq.data.Time = GetTickCount();
    // 计算回应请求的校验和
    echoReq.icmpHdr.Checksum = checksum((unsigned short *)&(echoReq), sizeof(ECHOREQUEST));
    // 发送回应请求
    nRet = sendto(s, (LPSTR)&echoReq, sizeof(ECHOREQUEST), 0, (struct sockaddr *)lpstToAddr, sizeof(SOCKADDR_IN));
    if (nRet == SOCKET_ERROR)
    {
        printf("send to() error:%d\n", WSAGetLastError());
    }
    return (echoReq.data.Time);
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
    echoReply.data.Time = GetTickCount();
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
    return (echoReply.data.Time);
}

void recsen(SOCKET rawSocket, struct sockaddr_in srcIP, struct sockaddr_in destIP)
{

    // 回复次数,请求失败次数
    int recieved = 0, lost = 0;
    // 记录TTL
    unsigned char cTTL;
    int nRet;
    // 发送 ICMP 回应请求
    DWORD sendTime = SendEchoRequest(rawSocket, &destIP, &srcIP);
    // 等待回复的数据
    nRet = WaitForEchoReply(rawSocket);
    // 检测回复有没有错误
    if (nRet == SOCKET_ERROR)
    {
        printf("select() error:%d\n", WSAGetLastError());
        return;
    }
    if (!nRet)
    {
        lost++;
        printf("Request time out.\n");
        return;
    }
    // 接收回复并记录
    memset(&srcIP, 0, sizeof(srcIP));
    DWORD reciveTime = RecvEchoReply(rawSocket, &srcIP, &cTTL);
    // 回复次数加1
    recieved++;
    // 计算花费的时间
    // printf("sendtime: %d,recievetime: %d", sendTime, reciveTime);
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

// Ping功能实现
void Ping(char *ptr, bool log)
{

    struct sockaddr_in srcIP;  // 回复地址
    struct sockaddr_in destIP; // 目标地址

    // 创建原始套接字 ,ICMP 类型
    SOCKET rawSocket = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
    if (rawSocket == SOCKET_ERROR)
    {
        printf("socket() error:%d\n", WSAGetLastError());
        return;
    }
    // 设置源地址
    srcIP.sin_addr = returnHost();
    srcIP.sin_family = AF_INET;
    srcIP.sin_port = 5024; //
    // 设置目标机地址
    destIP.sin_addr = ResolveHost(ptr); // 设置目标 IP
    destIP.sin_family = AF_INET;        // 地址簇规格
    destIP.sin_port = 0;                //
    // 提示开始进行 PING
    printf("\nPinging %s [%s] with %d bytes of data:\n", ptr, inet_ntoa(destIP.sin_addr), REQ_DATASIZE);
    if (log)
    {
        recsen(rawSocket, srcIP, destIP);
    }
    else
    {
        // 发起多次 PING 测试
        for (int i = 0; i < 4; i++)
        {
            recsen(rawSocket, srcIP, destIP);
        }
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
    system("pause");
    // 清除Winsock库
    WSACleanup();

    return 0;
}
