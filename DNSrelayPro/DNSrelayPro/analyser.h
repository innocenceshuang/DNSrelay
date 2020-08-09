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
#define MAX_CAP 200	// 请求池最大容量
#define ANA_NUM 5	// 分析器数量
#define DECLINE_TIME 2000	// 请求超时的时间限制
// #define IP_LEN_LIM 30	// IP长度限制
#define REQUEST_DNS "223.5.5.5"	// 配置里没有时向该ip发请求

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
	SOCKET withClient;	// 面向客户的socket对象

	map<string, string> domainToIP;	// 本地存储的转换表
	vector<string> ban;	// 黑名单


	deque<MessageItem> messageQueue;	// 消息队列
	QueProtect queprotect;	// 解决消息队列的生产者消费者问题

	map<string, ConvertItem> tempDomainToIP;	// 临时转换表
	shared_mutex smt;	// 访问临时转换表的互斥量


	// 读配置文件，初始化永久地址转化表
	void readConfigure();
	// 准备好与客户端通信的socket端口
	void buildClientSideSock();
	// 接收客户请求，放入消息队列里，生产者
	void acceptMessage();

	void resolution();

	/* 报文是否应该响应,只响应标准请求（flag域0x0100），只带一个问题的（通常情况，因为找不到带多个请求的报文格式，不知道咋分析），
	   请求type是A(HOST）(因为PTR是查dns服务器授权的，而我们是野dns；AAAA虽然说是查ipv6，但响应里通常是别名（CNANE），所以也不考虑)
	   请求class是in（internet）*/
	bool continueAnalyse(char[],int);

	void localResolve(MessageItem, ResolveType, string domain);

	void outerResolve(MessageItem, SOCKET, struct sockaddr_in, string domain);

	void washTempMap();
};
