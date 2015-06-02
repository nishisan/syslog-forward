/* IP packet header */
struct iphdr {
    int offset;
    int proto;
    int src;
    int dst;
    int data_offset;
    int max_offset;
};
typedef struct iphdr iphdr;

/* tcp packet hdr */
struct tcphdr {
    int offset;
    int src;
    int dst;
    int seqno;
    int ackno;
    int flags;
    int data_offset;
};
typedef struct tcphdr tcphdr;
typedef struct tcphdr udphdr;

/* Pretty printing IP addresses */
#define _XIP(a,n) (int)(((a)>>(n))&0xFF)
#define P_IP_ADDR(a) _XIP(a,24), _XIP(a,16), _XIP(a,8), _XIP(a,0)

/* TCP/IP protocol extraction stuff.  */
#define ex8(p,f)            ((p)[f]) 
#define ex16(p,f)           ((p)[f] << 8 | (p)[f+1])
#define ex32(p,f)           ((ex16(p,f)<<16) | ex16(p,f+2))
#define IP_VERSION(p,f)     ((ex8(p,f+0) >> 4) & 0x0F)
#define IP_SIZEOF_HDR(p,f)  ((ex8(p,f+0) & 0x0F) * 4)
#define IP_TOTALLENGTH(p,f) ex16(p,f+2)
#define IP_PROTOCOL(p,f)    ex8(p,f+9)
#define IP_SRC(p,f)         ex32(p,f+12)                
#define IP_DST(p,f)         ex32(p,f+16)
#define TCP_SRC(p,f)        ex16(p,f+0)
#define TCP_DST(p,f)        ex16(p,f+2)
#define TCP_SEQNO(p,f)      ex32(p,f+4)
#define TCP_ACKNO(p,f)      ex32(p,f+8)
#define TCP_FLAGS(p,f)      (ex8(p,f+13)&0x3F)
#define TCP_SIZEOF_HDR(p,f) (((ex8(p,f+12)>>4) & 0x0f)*4)
#define TCP_FIN             1
#define TCP_SYN             2
#define TCP_RST             4

