
#include "sysInclude.h"

extern void ip_DiscardPkt(char* pBuffer,int type);

extern void ip_SendtoLower(char*pBuffer,int length);

extern void ip_SendtoUp(char *pBuffer,int length);

extern unsigned int getIpv4Address();


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

int stud_ip_recv(char *pBuffer,unsigned short length)
{
    unsigned short version = pBuffer[0] >> 4;
    if(version != 4)
    {
        ip_DiscardPkt(pBuffer, STUD_IP_TEST_VERSION_ERROR);
        return 1;
    }

    unsigned short headlen = pBuffer[0] & 15;
    if(headlen != 5)
    {
        ip_DiscardPkt(pBuffer, STUD_IP_TEST_HEADLEN_ERROR);
        return 1;
    }

    unsigned short ttl = pBuffer[8];
    if(ttl == 0)
    {
        ip_DiscardPkt(pBuffer, STUD_IP_TEST_TTL_ERROR);
        return 1;
    }

    unsigned int packet_destination = ntohl(((unsigned int*)pBuffer)[4]);
    if(getIpv4Address() != packet_destination)
    {
        ip_DiscardPkt(pBuffer, STUD_IP_TEST_DESTINATION_ERROR);
        return 1;
    }

    int checksum = ((unsigned short *)pBuffer)[5];
    if(checksum != _checksum(pBuffer))
    {
        ip_DiscardPkt(pBuffer, STUD_IP_TEST_CHECKSUM_ERROR);
        return 1;
    }

    ip_SendtoUp(pBuffer, length);

    return 0;
}

int stud_ip_Upsend(char *pBuffer,unsigned short len,unsigned int srcAddr,
                   unsigned int dstAddr,byte protocol,byte ttl)
{
    unsigned short totallen = len + 20; 
    char *pSend = (char*)malloc(sizeof(char)*(totallen));

    //version headlength
    pSend[0] = 'E';

    //total length
    unsigned short nslen = htons(totallen);
    memcpy(pSend + 2, &nslen, sizeof(unsigned short));

    //time to live
    pSend[8] = ttl;

    //protocal
    pSend[9] = protocol;

    //source address
    unsigned int source_add = htonl(srcAddr);
    memcpy(pSend + 12, &source_add, sizeof(unsigned int));

    //destination address
    unsigned int dest_add = htonl(dstAddr);
    memcpy(pSend + 16, &dest_add, sizeof(unsigned int));

    //checksum
    unsigned short checksum = _checksum(pSend);
    memcpy(pSend + 10, &checksum, sizeof(short));

    //data
    memcpy(pSend + 20, pBuffer, len);

    ip_SendtoLower(pSend,totallen);
    return 0;
}

