#include "sysInclude.h"

extern void tcp_DiscardPkt(char *pBuffer, int type);

extern void tcp_sendIpPkt(unsigned char *pData, UINT16 len, unsigned int  srcAddr, unsigned int dstAddr, UINT8	ttl);

extern int waitIpPacket(char *pBuffer, int timeout);

extern unsigned int getIpv4Address();

extern unsigned int getServerIpv4Address();

typedef struct tcphead{           
        UINT16 srcPort;
        UINT16 destPort;
        UINT32 seqNo;
        UINT32 ackNo;
        UINT8  headLen;
        UINT8  flag;  
        UINT16 windowsize;
        UINT16 checksum;
        UINT16 urgentPointer;
        char data[100];  
};

typedef struct TCB              
{
        unsigned int srcAddr;
        unsigned int dstAddr;
        unsigned short srcPort;
        unsigned short dstPort;
        unsigned int seq;
        unsigned int ack;
        int sockfd;
        BYTE state; 
        unsigned char* data;
};


typedef struct tcb_node{                       
        TCB *current;
        struct tcb_node *next;
};

struct tcb_node *tcb_table;                    
struct TCB *current_tcb;                       

enum status{CLOSED,SYN_SENT,ESTABLISHED,FIN_WAIT1,FIN_WAIT2,TIME_WAIT};  

int gSrcPort = 2008;
int gDstPort = 2009;
int gSeqNum = 1234;
int gAckNum = 0;
int socknum = 5;     

unsigned int getchecksum(bool fromLocal, tcphead* thead,unsigned int srcAddr, unsigned int dstAddr,unsigned short len,char* data)
{
        unsigned int checksum = 0;
        checksum += (srcAddr>>16)+srcAddr&0xffff;
        checksum += (dstAddr>>16)+dstAddr&0xffff;
        checksum += IPPROTO_TCP;
        checksum += 0x14;
        if(fromLocal)
        {
          checksum += thead->srcPort+thead->destPort;
          checksum += thead->windowsize;
          checksum += thead->urgentPointer;
        }else{
          checksum += ntohs(thead->srcPort)+ntohs(thead->destPort);
          checksum += ntohs(thead->windowsize);
          checksum += ntohs(thead->urgentPointer);
        }


        checksum += ((thead->seqNo)>>16)+(thead->seqNo)&0xffff;
        checksum += ((thead->ackNo)>>16)+(thead->ackNo)&0xffff;
        checksum += ((thead->headLen)<<8)+thead->flag;

       

        if(thead->flag == PACKET_TYPE_DATA){
                checksum += len;
                int length=len;
                char* p=data;
                while(length>0){
                        checksum += (*p)<<8;
                        p++;
                        checksum += (*p);
                        p++;
                        length=length-2;
                }
        }

        checksum = (checksum>>16)+checksum&0xffff;
        checksum = (checksum>>16)+checksum&0xffff;
        checksum = (~checksum)&0xffff;

        return checksum;

}



int stud_tcp_input(char *pBuffer, unsigned short len, unsigned int srcAddr, unsigned int dstAddr)
{
    
    tcphead* header = (tcphead*)pBuffer;  

    header->seqNo = ntohl(header->seqNo);
    header->ackNo = ntohl(header->ackNo);
    
    if(getchecksum(0,header,ntohl(srcAddr),ntohl(dstAddr),len,NULL) != ntohs(header->checksum)){	
          return -1;
    }

    int seqAdd=1;   //SYN-SENT   FINWAIT1
    if(current_tcb->state == FIN_WAIT2){      
            seqAdd=0;
    }
    else if(len > 20)          
    {
            seqAdd=len-20;
    }
   
    if(header->ackNo != (current_tcb->seq+seqAdd)){
            tcp_DiscardPkt(pBuffer, STUD_TCP_TEST_SEQNO_ERROR);   
            return -1;
    }

    switch(current_tcb->state)                                  
    {
        case SYN_SENT: 
            if(header->flag == PACKET_TYPE_SYN_ACK )
            {
             current_tcb->state = ESTABLISHED;
             current_tcb->ack=  header->seqNo+1;                          
             current_tcb->seq = header->ackNo;
             stud_tcp_output(NULL, 0, PACKET_TYPE_ACK, current_tcb->srcPort, current_tcb->dstPort, ntohl(srcAddr), ntohl(dstAddr));
             break;
            }
            else
              return -1;
        case ESTABLISHED:
            if(header->flag == PACKET_TYPE_ACK)
            {
               if(len > 20) 
               {
                   current_tcb->ack = header->seqNo + len-20;    
                   current_tcb->seq = header->ackNo;            
                   break;
               }
               else if(len==20)  
               {
                   current_tcb->ack=  header->seqNo+1;                          
                   current_tcb->seq = header->ackNo;
                   break;
               }
               else return -1;
            }
            else
               return -1;
        case FIN_WAIT1: 
          if(header->flag == PACKET_TYPE_ACK)
          {
            current_tcb->ack=  header->seqNo+1;                          
            current_tcb->seq = header->ackNo;
            current_tcb->state = FIN_WAIT2; 
            break;
          }
          else 
            return -1;
        case FIN_WAIT2:
            if(header->flag == PACKET_TYPE_FIN_ACK)
            {
                current_tcb->state = TIME_WAIT;
                stud_tcp_output(NULL, 0, PACKET_TYPE_ACK, current_tcb->srcPort, current_tcb->dstPort, ntohl(srcAddr), ntohl(dstAddr));
                break;
            }
            else
                return -1;
        default: 
            return -1;

    }
    return 0;
}
void stud_tcp_output(char *pData, unsigned short len, unsigned char flag, unsigned short srcPort, unsigned short dstPort, unsigned int srcAddr, unsigned int dstAddr)
{
       
       if(current_tcb==NULL){    
            current_tcb = new TCB;
            current_tcb->seq = gSeqNum;
            current_tcb->ack = gAckNum;
            current_tcb->srcPort = srcPort;
            current_tcb->dstPort = dstPort;
            current_tcb->srcAddr = srcAddr;
            current_tcb->dstAddr = dstAddr;
            current_tcb->state = CLOSED;
        }
                             
        tcphead* thead = new tcphead; 
        for(int i=0; i<len; i++){ 
              thead->data[i] = pData[i];
         }
        thead->srcPort = srcPort;
        thead->destPort = dstPort;
        thead->seqNo = current_tcb->seq;
        thead->ackNo = current_tcb->ack;
        thead->headLen = 0x50;   
        thead->flag = flag;
        thead->windowsize = 1;
        thead->urgentPointer = 0;

        switch(current_tcb->state)  
        {
             case CLOSED:
                 if(flag == PACKET_TYPE_SYN)
                 {
                       current_tcb->state = SYN_SENT;
                 }
                 else 
                      return;
                 break;
             case ESTABLISHED:
                 if(flag == PACKET_TYPE_FIN_ACK)
                 {
                       current_tcb->state = FIN_WAIT1;
                       break;
                 }
                 else if(flag == PACKET_TYPE_DATA || flag == PACKET_TYPE_ACK)
                 {
                       break;
                 }
                 else
                       return;
                 break;
             defalut:  
                return;
        }
        
        thead->checksum = ntohs(getchecksum(1,thead,srcAddr,dstAddr,len,pData));
        thead->srcPort = ntohs(thead->srcPort);
        thead->destPort = ntohs(thead->destPort);
        thead->seqNo = ntohl(thead->seqNo);
        thead->ackNo = ntohl(thead->ackNo);
        thead->windowsize = ntohs(thead->windowsize);
        thead->urgentPointer = ntohs(thead->urgentPointer);
        tcp_sendIpPkt((unsigned char*)thead, 20+len, current_tcb->srcAddr, current_tcb->dstAddr, 60);
}

int stud_tcp_socket(int domain, int type, int protocol)
{
       if(domain!=AF_INET || type!= SOCK_STREAM || protocol!=IPPROTO_TCP)
           return -1;
        current_tcb = new TCB;
        if(tcb_table==NULL){      
                tcb_table = new tcb_node;
                tcb_table->current = current_tcb;
                tcb_table->next = NULL;
        }
        else{                     
                tcb_node *head = tcb_table;
                while(head->next != NULL){
                        head = head->next;
                }
                head->next = new tcb_node;
                head->next->current = current_tcb;
                head->next->next = NULL;
        }

        current_tcb->sockfd = socknum++;  
        current_tcb->srcPort = gSrcPort++;
        current_tcb->seq = gSeqNum++;
        current_tcb->ack = gAckNum;
        current_tcb->state = CLOSED;
       
        return current_tcb->sockfd;
}

int  getSockfd(int sockfd)           
{
    tcb_node *current_p = tcb_table;
    while(current_tcb != NULL && current_p->current!=NULL)
    { 
         if(current_p->current->sockfd == sockfd)
         {
                current_tcb = current_p->current;
                return 0;
                break;
         }
         current_p = current_p->next;
    }
    if (current_p==NULL)
       return -1;
}

int stud_tcp_connect(int sockfd, struct sockaddr_in *addr, int addrlen)
{
        
    if(getSockfd(sockfd)==-1) 
         return -1;
    
    UINT32 srcAddr = getIpv4Address();                  
    UINT32 dstAddr = htonl(addr->sin_addr.s_addr);
    current_tcb->srcAddr = srcAddr;
    current_tcb->dstAddr = dstAddr;
    current_tcb->dstPort = ntohs(addr->sin_port);
    current_tcb->state = SYN_SENT;               
    stud_tcp_output(NULL, 0, PACKET_TYPE_SYN, current_tcb->srcPort, current_tcb->dstPort, srcAddr, dstAddr);
    tcphead* receive = new tcphead;
    
    int res = -1;
    while(res == -1)      
            res = waitIpPacket((char*)receive, 5000);


   stud_tcp_input((char *)receive, 20, ntohl(current_tcb->srcAddr), ntohl(current_tcb->dstAddr));
    
   return 0;
}
int stud_tcp_send(int sockfd, const unsigned char *pData, unsigned short datalen, int flags)
{
    if(getSockfd(sockfd)==-1) 
          return -1;
    if(current_tcb->state != ESTABLISHED)
          return -1;

    UINT32 srcAddr = getIpv4Address();
    UINT32 dstAddr = current_tcb->dstAddr;
    current_tcb->data = new unsigned char(datalen);
    strcpy((char*)current_tcb->data,(char*)pData); 
    stud_tcp_output((char *)current_tcb->data, datalen, PACKET_TYPE_DATA, current_tcb->srcPort, current_tcb->dstPort, srcAddr, dstAddr);
    tcphead* receive = new tcphead;
    
    int res = -1;
    while(res == -1)                            
         res = waitIpPacket((char*)receive, 5000);

    stud_tcp_input((char *)receive, datalen+20, ntohl(current_tcb->srcAddr), ntohl(current_tcb->dstAddr));
    
    return 0;
}
int stud_tcp_recv(int sockfd, unsigned char *pData, unsigned short datalen, int flags)
{
    if(getSockfd(sockfd)==-1) 
       return -1;
    if(current_tcb->state != ESTABLISHED)
       return -1;

    UINT32 srcAddr = getIpv4Address();
    UINT32 dstAddr = current_tcb->dstAddr;
    tcphead* receive = new tcphead;
    
    int res = -1;
    while(res == -1)
         res = waitIpPacket((char*)receive, 5000);

    strcpy((char*)pData,(char*)receive->data);
    datalen=sizeof(pData);
    stud_tcp_output(NULL, 0, PACKET_TYPE_ACK, current_tcb->srcPort, current_tcb->dstPort, srcAddr, dstAddr);
    
    return 0;
}

int stud_tcp_close(int sockfd)
{

    tcb_node *current_p = tcb_table;
    tcb_node *preCurrent=current_p;  

    while(current_p != NULL && current_p->current!=NULL)
    {
            if(current_p->current->sockfd == sockfd){
                    current_tcb = current_p->current;
                    break;
            }
            preCurrent=current_p;
            current_p = current_p->next;
    }
    if(current_p==NULL)
        return -1;
    
    UINT32 srcAddr = getIpv4Address();
    UINT32 dstAddr = current_tcb->dstAddr;
    if(current_tcb->state != ESTABLISHED)
    {
        if(current_p!=preCurrent)        
        {
             preCurrent->next=current_p->next;
             delete current_p;
        }
        else
             delete current_tcb;
        current_tcb=NULL;
    return -1;
    }
       
   stud_tcp_output(NULL, 0, PACKET_TYPE_FIN_ACK, current_tcb->srcPort, current_tcb->dstPort, srcAddr, dstAddr);
   current_tcb->state = FIN_WAIT1;	
   tcphead* receive = new tcphead;
   
   int res = -1;
   while(res == -1)
        res = waitIpPacket((char*)receive, 5000);

   stud_tcp_input((char *)receive, 20,ntohl(current_tcb->srcAddr), ntohl(current_tcb->dstAddr)); //ack
   
   res = -1;
   while(res == -1)
        res = waitIpPacket((char*)receive, 5000);

   stud_tcp_input((char *)receive, 20, ntohl(current_tcb->srcAddr), ntohl(current_tcb->dstAddr));//fin/ack
   return 0;

}


