// DNSrelayPro.cpp : 此文件包含 "main" 函数。程序执行将在此处开始并结束。
//

#include <iostream>
#include "analyser.h"
#pragma comment(lib,"ws2_32.lib")

using namespace std;

int main()
{
    std::cout << "Hello World!\n";
    Analyser* anaptr = new Analyser();
    return 0;
}

// 运行程序: Ctrl + F5 或调试 >“开始执行(不调试)”菜单
// 调试程序: F5 或调试 >“开始调试”菜单
