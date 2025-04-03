#pragma once
#include <string>

#define WTSOCKET_ADDR sockaddr_in
#define IP_TYPE		  unsigned long
#define IP_TYPE_SOCKET(x)	((IP_TYPE)((x)->sin_addr.s_addr))

IP_TYPE GetHostID(const char *szHost);

/**
* ��x.x.x.xתΪx.x.x.1���ء�
*/
std::string TranferRouteDisk(unsigned int nIp);

/**
* ��x.x.x.xתΪx.x.x.(x-1)���ء���������һλΪ0���򷵻غ���������һ����IP��
*/
std::string TranferRouteDisk2(unsigned int nIp);

/**
* ��x.x.x.xתΪx.x.x.255���ء�
*/
std::string TranferRouteDisk3(unsigned int nIp);
/**
* ����socket
*/
BOOL ConnetTimeOut(SOCKET sock, WTSOCKET_ADDR *sockAddr, int msTimeOut);
/**
* ��sockaddr_inת��Ϊ�ַ�������ʽΪ"IP:Port"
*/
std::string SockAddrToString(IN WTSOCKET_ADDR *pSocketAddr);

/**
* �����ε�IPv4תΪ�ַ�����ʽ��
*/
std::string IPTypeToString(IP_TYPE ip);

/**
* WSAStartup/WSACleanup();
*/
BOOL WinSockInit();
void WinSockCleanup();

#define LOCALHOST_INT		0x0100007f
