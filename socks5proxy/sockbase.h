#pragma once
#include <string>

#define WTSOCKET_ADDR sockaddr_in
#define IP_TYPE		  unsigned long
#define IP_TYPE_SOCKET(x)	((IP_TYPE)((x)->sin_addr.s_addr))

IP_TYPE GetHostID(const char *szHost);

/**
* 将x.x.x.x转为x.x.x.1返回。
*/
std::string TranferRouteDisk(unsigned int nIp);

/**
* 将x.x.x.x转为x.x.x.(x-1)返回。但如果最后一位为0，则返回和输入内容一样的IP。
*/
std::string TranferRouteDisk2(unsigned int nIp);

/**
* 将x.x.x.x转为x.x.x.255返回。
*/
std::string TranferRouteDisk3(unsigned int nIp);
/**
* 连接socket
*/
BOOL ConnetTimeOut(SOCKET sock, WTSOCKET_ADDR *sockAddr, int msTimeOut);
/**
* 将sockaddr_in转化为字符串，格式为"IP:Port"
*/
std::string SockAddrToString(IN WTSOCKET_ADDR *pSocketAddr);

/**
* 将整形的IPv4转为字符串形式。
*/
std::string IPTypeToString(IP_TYPE ip);

/**
* WSAStartup/WSACleanup();
*/
BOOL WinSockInit();
void WinSockCleanup();

#define LOCALHOST_INT		0x0100007f
