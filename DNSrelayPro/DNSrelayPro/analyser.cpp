#include <fstream>
#include <string>
#include <chrono>

#include "analyser.h"

using namespace std;


void Analyser::readConfigure() {
	// 扫描文件，初始化域名转化配置
	ifstream fin("allow.txt");
	if (!fin)
	{
		cout << "配置文件打开失败" << endl;
		exit(3);
	}
	string line;
	while (getline(fin, line))
	{
		string key;
		string val;
		int i = 0;
		for (i = 0; i < line.size() && line[i] != ' '; i++) {
			key += line[i];
		}
		i++;
		for (; i < line.size(); i++) {
			val += line[i];
		}
		domainToIP[key] = val;
	}
	fin.close();

	fin.open("deny.txt");
	if (!fin)
	{
		cout << "配置文件打开失败" << endl;
		exit(3);
	}
	while (getline(fin, line))
	{
		ban.push_back(line);
	}
	fin.close();
	for (auto i = domainToIP.begin(); i != domainToIP.end(); i++)
	{
		cout << i->first << " ," << i->second << endl;
	}
	for (auto i = ban.begin(); i != ban.end(); i++)
	{
		cout << *i << endl;
	}
}

void Analyser::buildClientSideSock()
{
	WSADATA wsadata;
	if (WSAStartup(MAKEWORD(2, 2), &wsadata) != 0)
	{
		std::cout << "Failed to link winsock.dll!" << std::endl;
		exit(1);
	}

	withClient = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	if (withClient == SOCKET_ERROR) {
		std::cout << "Failed to create socket!" << std::endl;
		exit(2);
	}

	struct sockaddr_in name;
	name.sin_family = AF_INET;
	name.sin_port = htons(PORT);
	name.sin_addr.s_addr = htonl(INADDR_ANY);

	bind(withClient, (struct sockaddr*)&name, sizeof(name));
}

void Analyser::acceptMessage() 
{
	while (true) {
		MessageItem messageItem;
		messageItem.mess_len = recvfrom(withClient, messageItem.message, LENGTH, 0, (struct sockaddr*)&(messageItem.peer), &(messageItem.addr_len));
		messageItem.timestamp = GetTickCount();

		std:unique_lock <std::mutex> lk(queprotect.mt);
		cout << "writer get key!" << endl;
		queprotect.isfull.wait(lk, [&]() {return messageQueue.size() < MAX_CAP; });

// 		MessageItem messageItem;
// 		messageItem.mess_len = recvfrom(withClient, messageItem.message, LENGTH, 0, (struct sockaddr*)&(messageItem.peer), &(messageItem.addr_len));
// 		messageItem.timestamp = GetTickCount();
		messageQueue.push_back(messageItem);

		// 拥塞控制，当存储区满时丢弃后一半
		if (messageQueue.size() == MAX_CAP) {
			for (int i = 0; i < MAX_CAP / 2; i++) {
				messageQueue.pop_back();
			}
		}

		cout << "recv:";
		for (int i = 0; i < messageItem.mess_len; i++) {
			printf("%02x", messageItem.message[i]);
		}
		cout << endl;
		cout << "size of queue" << messageQueue.size() << endl;

		queprotect.isempty.notify_all();
		
		lk.unlock();
		// std::this_thread::sleep_for(std::chrono::milliseconds(200));
	}
}

void Analyser::resolution()
{
	SOCKET withServer = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	struct sockaddr_in reqAddr;
	reqAddr.sin_family = AF_INET;
	reqAddr.sin_port = htons(PORT);
	inet_pton(AF_INET, REQUEST_DNS, &reqAddr.sin_addr);

	while (true) {
		// 从消息队列中取出消息
		std::unique_lock <std::mutex> lk(queprotect.mt);
		cout << "reader get key!" << endl;
		queprotect.isempty.wait(lk, [&]() {return messageQueue.size() > 0; });

		MessageItem messageItem;
		memcpy(&messageItem, &(messageQueue.front()), sizeof(messageQueue.front()));

		cout << "get:";
		for (int i = 0; i < messageItem.mess_len; i++) {
			printf("%02x", messageItem.message[i]);
		}
		cout << endl;

		messageQueue.pop_front();

		queprotect.isfull.notify_all();
		lk.unlock();

		// 处理消息
		DWORD dealTime = GetTickCount();
		// 超时消息处理,处理到超时消息时，默认前一半消息已经超时，丢弃
		if (dealTime - messageItem.timestamp > DECLINE_TIME) 
		{
			cout << "TIMEOUT!" << endl;
			std::unique_lock <std::mutex> lk(queprotect.mt);

			queprotect.isempty.wait(lk, [&]() {return !messageQueue.empty(); });

			int cap = messageQueue.size();
			for (int i = 0; i < cap / 2; i++) {
				messageQueue.pop_front();
			}

			queprotect.isfull.notify_all();
			lk.unlock();
		}
		else {
			if(!continueAnalyse(messageItem.message,messageItem.mess_len))
				continue;

			string domain;
			int i = 12;
			while (messageItem.message[i] != 0x00) {
				unsigned short bound = messageItem.message[i];
				i++;
				if (i != 13)
				{
					domain += '.';
				}
				for (int j = 0; j < bound; j++) {
					domain += messageItem.message[i];
					i++;
				}
			}
			// cout << domain;

			shared_lock<std::shared_mutex> tempConvert(smt);
			if (tempDomainToIP.count(domain)) {
				localResolve(messageItem, UnAuthority, domain);
				tempConvert.unlock();
			}
			else
			{
				tempConvert.unlock();
				if (domainToIP.count(domain))
				{
					localResolve(messageItem, Authority, domain);
				}
				else if (count(ban.begin(), ban.end(), domain))
				{
					localResolve(messageItem, Reject, domain);
				}
				else {
					outerResolve(messageItem, withServer, reqAddr, domain);
				}
			
			}

// 			if (domainToIP.count(domain))
// 			{
// 				localResolve(messageItem, Authority, domain);
// 			}
// 			else if(count(ban.begin(), ban.end(), domain))
// 			{
// 				localResolve(messageItem, Reject, domain);
// 			}
// 			else if (tempDomainToIP.count(domain))
// 			{
// 				localResolve(messageItem, UnAuthority, domain);
// 			}
// 			else {
// 				outerResolve(messageItem, withServer, reqAddr, domain);
// 			}
		}
		// std::this_thread::sleep_for(std::chrono::milliseconds(200));
	}
}

bool Analyser::continueAnalyse(char buf[],int len) {
	unsigned short* u = (unsigned short*)(buf + 2);
	unsigned short flag = ntohs(*u);	// 标志位
	u++;
	unsigned short QDCOUNT = ntohs(*u);	// 问题记录数
	u++;
	unsigned short ANCOUNT = ntohs(*u);	// 回答记录数
	u++;
	unsigned short NSCOUNT = ntohs(*u);	// 授权记录数
	u++;
	unsigned short ARCOUNT = ntohs(*u);	// 附加记录数
	u++;
	if (flag == 256 && QDCOUNT == 1 && ANCOUNT == 0)
	{
		u = (unsigned short*)(buf + len - 4);
		unsigned short queryType = ntohs(*u);
		u = (unsigned short*)(buf + len - 2);
		unsigned short queryClass = ntohs(*u);
		if (queryType != 1)		// 只回应IPV4请求
			return false;
		if (queryClass != 1)
			return false;
		return true;
	}
	else
		return false;
}

void Analyser::localResolve(MessageItem messageItem, ResolveType reType, string domain) {
	char sendbuf[LENGTH] = { 0 };	// 响应报文
	for (int i = 0; i < messageItem.mess_len; i++) {
		sendbuf[i] = messageItem.message[i];
	}

	int sendlen = messageItem.mess_len;
	// flag
	sendbuf[2] = 0x85;	sendbuf[3] = 0x80;

	sendbuf[7] = 0x01;	// 回答数

	sendbuf[sendlen] = 0xc0;		sendbuf[sendlen + 1] = 0x0c;	// 域名的偏移量
	sendlen += 2;

	sendbuf[sendlen] = 0x00;		sendbuf[sendlen + 1] = 0x01;	// type
	sendlen += 2;

	sendbuf[sendlen] = 0x00;		sendbuf[sendlen + 1] = 0x01;	// class
	sendlen += 2;

	sendbuf[sendlen] = 0x00;		sendbuf[sendlen + 1] = 0x00;	sendbuf[sendlen + 2] = 0x00; sendbuf[sendlen + 3] = 0xf0;// TTL，单位是秒
	sendlen += 4;

	sendbuf[sendlen] = 0x00;		sendbuf[sendlen + 1] = 0x04;	// 解析IP的长度，单位是byte
	sendlen += 2;

	if (reType == Authority) {
		string part;
		for (int j = 0; j < domainToIP[domain].size(); j++) {
			if (domainToIP[domain][j] == '.') {
				int p = atoi(part.c_str());
				sendbuf[sendlen++] = p & 0xff;
				part.clear();
				continue;
			}
			part += domainToIP[domain][j];
		}
		int p = atoi(part.c_str());
		sendbuf[sendlen++] = p & 0xff;
	}
	else if (reType == UnAuthority) {
		string part;
		for (int j = 0; j < tempDomainToIP[domain].ip_add.size(); j++) {
			if (tempDomainToIP[domain].ip_add[j] == '.') {
				int p = atoi(part.c_str());
				sendbuf[sendlen++] = p & 0xff;
				part.clear();
				continue;
			}
			part += tempDomainToIP[domain].ip_add[j];
		}
		int p = atoi(part.c_str());
		sendbuf[sendlen++] = p & 0xff;
		sendbuf[2] = 0x85;
	}
	else {
		for(int i = 0;i<4;i++)
			sendbuf[sendlen++] = 0x00;
	}
	sendto(withClient, sendbuf, sendlen, 0, (struct sockaddr*)&messageItem.peer, messageItem.addr_len);
}

void Analyser::outerResolve(MessageItem messageItem, SOCKET withServer, struct sockaddr_in reqAddr, string domain) {
	
	sendto(withServer, messageItem.message, messageItem.mess_len, 0, (struct sockaddr*)&reqAddr, sizeof(reqAddr));
	char recvbuf[LENGTH];
	int addr_len = sizeof(reqAddr);
	int getlen = recvfrom(withServer, recvbuf, sizeof(recvbuf), 0, (struct sockaddr*)&reqAddr, &addr_len);
	unsigned short* u = (unsigned short*)(recvbuf + 2);
	if ((recvbuf[2] & 0x80) != 0x80 || (recvbuf[3] & 0xf) != 0)
		return;
	u = (unsigned short*)(recvbuf + 6);
	unsigned short answer_amont = ntohs(*u);
	if (answer_amont < 1)
		return;

	char sendbuf[LENGTH];
	sendbuf[0] = messageItem.message[0];	
	sendbuf[1] = messageItem.message[1];	// 修改为请求序号
	for (int i = 2; i < getlen; i++)
		sendbuf[i] = recvbuf[i];
	sendto(withClient, sendbuf, getlen, 0, (struct sockaddr*)&messageItem.peer, messageItem.addr_len);

	char* answerItem = recvbuf + messageItem.mess_len;
	string ip_add;
	unsigned int TTL = 0;

	int gap = messageItem.mess_len;
	for (int i = 0; i < answer_amont; i++) {
		u = (unsigned short*)(recvbuf + gap + 2);	// answer type
		unsigned short antype = ntohs(*u);
		if (antype == 1) // 解析类型为HOST
		{
			unsigned int* ttlptr = (unsigned int*)(recvbuf + gap + 6);
			
			TTL = ntohl(*ttlptr);
			u = (unsigned short*)(recvbuf + gap + 10);
			unsigned short ip_len = ntohs(*u);	// IP长度
			
			for (int j = 0; j < 4; j++) {
				int temp = unsigned char(recvbuf[gap + 12 + j]);
				char area[6] = { 0 };
				cout << temp << endl;
				_itoa_s(temp, area, 4, 10);
				ip_add += area;
				if(j<3)
					ip_add += '.';
			}
			break;
		}
		u = (unsigned short*)(recvbuf + gap + 10);
		unsigned short anslen = ntohs(*u);	// 答案长度
		gap += (anslen+12);
	}
	if (TTL > 0)
	{
		ConvertItem converitem;
		converitem.TTL = TTL - 5;
		converitem.ip_add = ip_add;
		time(&converitem.timestamp);

		unique_lock<std::shared_mutex> tempConvert(smt);
		tempDomainToIP[domain] = converitem;
		tempConvert.unlock();
	}
	
}

void Analyser::washTempMap() {
	while (true)
	{
		unique_lock<std::shared_mutex> tempConvert(smt);

		for (auto it = tempDomainToIP.begin(); it != tempDomainToIP.end();)
		{
			time_t now;
			time(&now);
			if (difftime(now, it->second.timestamp) > it->second.TTL)
			{
				cout << "Swap out " << it->first << endl;
				tempDomainToIP.erase(it);
				it = tempDomainToIP.begin();
			}
			else
			{
				it++;
			}
		}
		tempConvert.unlock();
		std::this_thread::sleep_for(std::chrono::milliseconds(3000));
	}
}