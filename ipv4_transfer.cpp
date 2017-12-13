#include "sysInclude.h"
#include <vector>

// system support
extern void fwd_LocalRcv(char *pBuffer, int length);

extern void fwd_SendtoLower(char *pBuffer, int length, unsigned int nexthop);

extern void fwd_DiscardPkt(char *pBuffer, int type);

extern unsigned int getIpv4Address( );

/* implemented by students
typedef struct stud_route_msg
{
	unsigned int dest;
	unsigned int masklen;
	unsigned int nexthop;
};
*/
struct routeTableItem
{
	unsigned int destIP;
	unsigned int mask;
	unsigned int masklen;
	unsigned int nexthop;
};
//线性路由表
vector<routeTableItem> routeTable;

void stud_Route_Init()			
{
	routeTable.clear();
}

void stud_route_add(stud_route_msg *proute)
{
	routeTableItem item;
	item.masklen = ntohl(proute->masklen);
	item.mask = (1<<31)>>(ntohl(proute->masklen)-1);
	item.destIP = ntohl(proute->dest)&item.mask;
	item.nexthop = ntohl(proute->nexthop);
	routeTable.push_back(item);
}
//计算校验和
unsigned short _checksum(char *pBuffer)
{
    int sum = 0;
    for(int i = 0; i < 10; ++i)
    {
        if(i != 5)
        {
            sum += ((unsigned short*)pBuffer)[i];
        }
    }
    while(sum > 0xffff)
    {
        sum = (sum & 0xffff) + (sum >> 16); 
    }
    return (unsigned short)(0xffff - sum);
}

int stud_fwd_deal(char *pBuffer, int length)
{
	//提取头部信息
	int IHL = pBuffer[0] & 0xf; 	
	int TTL = (int)pBuffer[8]; 
	int headerChecksum = ntohl(*(unsigned short*)(pBuffer+10));
	int destIP = ntohl(*(unsigned int*)(pBuffer+16));

	//是否过期
	if(TTL <= 0)
	{
		fwd_DiscardPkt(pBuffer, STUD_FORWARD_TEST_TTLERROR);
		return 1;
	}

	//如果目标地址为本机
	if(destIP == getIpv4Address())
	{
		fwd_LocalRcv(pBuffer, length);
		return 0;
	}
	
	bool isMatch = false;
	unsigned int longestMatchLen = 0;
	int bestMatch = 0;
	
	//匹配最佳的地址
	for(int i = 0; i < routeTable.size(); ++i)
	{
		if(routeTable[i].masklen > longestMatchLen && routeTable[i].destIP == (destIP & routeTable[i].mask))
		{
			bestMatch = i;
			isMatch = true;
			longestMatchLen = routeTable[i].masklen;
		}
	}
	
	//匹配成功，更新TTL和校验和并转发
	if(isMatch)
	{
		char *buffer = new char[length]; 

        memcpy(buffer,pBuffer,length);

        --buffer[8];//TTL

        unsigned short localCheckSum = _checksum(buffer);
       
		memcpy(buffer+10, &localCheckSum, sizeof(unsigned short));
		
		fwd_SendtoLower(buffer, length, routeTable[bestMatch].nexthop);
		return 0;
	}
	//没有找到目标地址，直接丢弃
	else
	{
		fwd_DiscardPkt(pBuffer, STUD_FORWARD_TEST_NOROUTE);
		return 1;
	}

}
