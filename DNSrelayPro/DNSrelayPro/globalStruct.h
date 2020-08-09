#pragma once
#include <thread>
#include <mutex>
#include <time.h>
#include <Windows.h>

#define LENGTH 2048



typedef struct QueProtect {
	std::mutex mt;	// 互斥量 用于互斥地访问缓存
	std::condition_variable isfull;	// 用来挂生产者
	std::condition_variable isempty;	// 用来挂消费者
}QueProtect;

typedef struct MessageItem {
	char message[LENGTH];
	int mess_len;
	struct sockaddr_in peer;	// 请求端地址
	int addr_len = sizeof(peer);
	DWORD timestamp;
}MessageItem;

typedef struct ConvertItem {
	std::string ip_add;
	unsigned int TTL;
	time_t timestamp;
}ConvertItem;