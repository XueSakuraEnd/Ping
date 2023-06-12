
// IP首部
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
} ICMPHDR, *PICMPHDR;

