#pragma once
#include <thread>
#include <mutex>
#include <time.h>
#include <Windows.h>

#define LENGTH 2048



typedef struct QueProtect {
	std::mutex mt;	// ������ ���ڻ���ط��ʻ���
	std::condition_variable isfull;	// ������������
	std::condition_variable isempty;	// ������������
}QueProtect;

typedef struct MessageItem {
	char message[LENGTH];
	int mess_len;
	struct sockaddr_in peer;	// ����˵�ַ
	int addr_len = sizeof(peer);
	DWORD timestamp;
}MessageItem;

typedef struct ConvertItem {
	std::string ip_add;
	unsigned int TTL;
	time_t timestamp;
}ConvertItem;