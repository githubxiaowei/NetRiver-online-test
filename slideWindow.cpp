#include "sysinclude.h"
#include<queue>
using namespace std;
extern void SendFRAMEPacket(unsigned char* pData, unsigned int len);

#define WINDOW_SIZE_STOP_WAIT 1
#define WINDOW_SIZE_BACK_N_FRAME 4

//
typedef enum {data,ack,nak} frame_kind;
typedef struct frame_head
{
	frame_kind kind;
	unsigned int seq;
	unsigned int ack;
	unsigned char data[100];
};
typedef struct frame
{
	frame_head head;
	unsigned int size;
};


queue<struct frame> sendList;
deque<struct frame> sendWindow;
/*
* 停等协议测试函数
*/
int stud_slide_window_stop_and_wait(char *pBuffer, int bufferSize, UINT8 messageType)
{
	static bool send = true;
	struct frame f;
	
	switch(messageType)
	{
		case MSG_TYPE_SEND:
			memcpy(&f,pBuffer,sizeof(f));
			f.size = bufferSize;
			sendList.push(f);
			
			if(send)
			{
				f=sendList.front();
				SendFRAMEPacket((unsigned char*)(&f),f.size);
				send = false;
			}
			break;

		case MSG_TYPE_RECEIVE:
			sendList.pop();
			send = true;
			if(!sendList.empty())
			{
				f=sendList.front();
				SendFRAMEPacket((unsigned char*)(&f),f.size);
				send = false;
			}
			break;

		case MSG_TYPE_TIMEOUT:
			f = sendList.front();
			SendFRAMEPacket((unsigned char*)(&f),f.size);
			send = false;
			break;

		default:
			break;
	}

	return 0;
}

/*
* 回退n帧测试函数
*/
int stud_slide_window_back_n_frame(char *pBuffer, int bufferSize, UINT8 messageType)
{
	struct frame f;

	switch(messageType)
	{
		case MSG_TYPE_SEND:
			memcpy(&f,pBuffer,sizeof(f));
			f.size = bufferSize;
			sendList.push(f);

			if(sendWindow.size() < WINDOW_SIZE_BACK_N_FRAME)
			{
				f = sendList.front();
				sendWindow.push_back(f);
				SendFRAMEPacket((unsigned char*)(&f),f.size);
				sendList.pop();
			}
			break;

		case MSG_TYPE_RECEIVE:
			memcpy(&f,pBuffer,sizeof(f));

			while(ntohl(sendWindow.begin()->head.seq) != ntohl(f.head.ack) && !sendWindow.empty())
			{
				sendWindow.pop_front();
			}
			sendWindow.pop_front();
			
			while(sendWindow.size()<WINDOW_SIZE_BACK_N_FRAME && !sendList.empty())
			{
					f=sendList.front();
					sendWindow.push_back(f);
					sendList.pop();
					SendFRAMEPacket((unsigned char*)(&f),f.size);
			}
			break;

		case MSG_TYPE_TIMEOUT:
			for(deque<struct frame>::iterator iter = sendWindow.begin(); iter != sendWindow.end(); ++ iter)
			{	
				SendFRAMEPacket((unsigned char*)&(*iter),iter->size);
			}
			break;

		default:
			break;
	}

}

/*
* 选择性重传测试函数
*/
int stud_slide_window_choice_frame_resend(char *pBuffer, int bufferSize, UINT8 messageType)
{
	struct frame f;

	switch(messageType)
	{
		case MSG_TYPE_SEND:
			memcpy(&f,pBuffer,sizeof(f));
			f.size=bufferSize;
			sendList.push(f);

			if(sendWindow.size() < WINDOW_SIZE_BACK_N_FRAME)
			{
				f=sendList.front();
				sendWindow.push_back(f);
				sendList.pop();
				SendFRAMEPacket((unsigned char*)(&f),f.size);
			}
			break;

		case MSG_TYPE_RECEIVE:
			memcpy(&f,pBuffer,sizeof(f));
			
			if(ntohl(f.head.kind) == ack)
			{
				while(ntohl(sendWindow.begin()->head.seq) != ntohl(f.head.ack) && !sendWindow.empty())
				{
					sendWindow.pop_front();
				}
				sendWindow.pop_front();
			}
			else if(ntohl(f.head.kind) == nak)
			{
				for(deque<struct frame>::iterator iter = sendWindow.begin(); iter != sendWindow.end(); ++ iter)
				{
					if(ntohl(f.head.ack)==ntohl(iter->head.seq))
					{
						SendFRAMEPacket((unsigned char*)&(*iter),iter->size);
						break;
					}
				}
			}	
			while(sendWindow.size()<WINDOW_SIZE_BACK_N_FRAME && !sendList.empty())
			{
					f=sendList.front();
					sendWindow.push_back(f);
					sendList.pop();
					SendFRAMEPacket((unsigned char*)(&f),f.size);
			}
			break;

		case MSG_TYPE_TIMEOUT:
			unsigned int seq;
			memcpy(&seq,pBuffer,sizeof(seq));

			for(deque<struct frame>::iterator iter = sendWindow.begin(); iter != sendWindow.end(); ++ iter)
			{
				if(ntohl(seq) == ntohl(iter->head.seq))
				{
					SendFRAMEPacket((unsigned char*)(&(*iter)),iter->size);
					break;
				}
			}
			break;

		default:
			break;
	}

	return 0;
}
