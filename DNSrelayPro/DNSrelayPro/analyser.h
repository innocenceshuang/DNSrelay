#pragma once
#include <WinSock2.h>
#include <Windows.h>
#include <iostream>
#include <map>
#include <vector>
#include <deque>
#include<WS2tcpip.h>
#include <shared_mutex>

#include "globalStruct.h"

#define PORT 53
#define MAX_CAP 200	// ������������
#define ANA_NUM 5	// ����������
#define DECLINE_TIME 2000	// ����ʱ��ʱ������
// #define IP_LEN_LIM 30	// IP��������
#define REQUEST_DNS "223.5.5.5"	// ������û��ʱ���ip������

using namespace std;


typedef enum ResolveType{Authority,UnAuthority,Reject}ResolveType;

class Analyser {
public:
	Analyser() {
		readConfigure();
		buildClientSideSock();
		thread recvmes(&Analyser::acceptMessage, this);
		thread anames[ANA_NUM];
		for (int i = 0; i < ANA_NUM; i++) {
			anames[i] = thread(&Analyser::resolution, this);
		}
		recvmes.detach();
		for (int i = 0; i < ANA_NUM; i++) {
			anames[i].detach();
		}
		thread cleanPool(&Analyser::washTempMap, this);
		cleanPool.join();
	}

	~Analyser() {

	}

	

private:
	SOCKET withClient;	// ����ͻ���socket����

	map<string, string> domainToIP;	// ���ش洢��ת����
	vector<string> ban;	// ������


	deque<MessageItem> messageQueue;	// ��Ϣ����
	QueProtect queprotect;	// �����Ϣ���е�����������������

	map<string, ConvertItem> tempDomainToIP;	// ��ʱת����
	shared_mutex smt;	// ������ʱת����Ļ�����


	// �������ļ�����ʼ�����õ�ַת����
	void readConfigure();
	// ׼������ͻ���ͨ�ŵ�socket�˿�
	void buildClientSideSock();
	// ���տͻ����󣬷�����Ϣ�����������
	void acceptMessage();

	void resolution();

	/* �����Ƿ�Ӧ����Ӧ,ֻ��Ӧ��׼����flag��0x0100����ֻ��һ������ģ�ͨ���������Ϊ�Ҳ������������ı��ĸ�ʽ����֪��զ��������
	   ����type��A(HOST��(��ΪPTR�ǲ�dns��������Ȩ�ģ���������Ұdns��AAAA��Ȼ˵�ǲ�ipv6������Ӧ��ͨ���Ǳ�����CNANE��������Ҳ������)
	   ����class��in��internet��*/
	bool continueAnalyse(char[],int);

	void localResolve(MessageItem, ResolveType, string domain);

	void outerResolve(MessageItem, SOCKET, struct sockaddr_in, string domain);

	void washTempMap();
};
