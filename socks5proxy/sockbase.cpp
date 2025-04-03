#include "stdafx.h"
#include "sockbase.h"
#include <sstream>

IP_TYPE GetHostID(const char *szHost)
{
	if (szHost == NULL || strlen(szHost) == 0)
	{
		return 0;
	}

	IP_TYPE nIp = inet_addr(szHost);
	if (nIp != INADDR_NONE) {
		return nIp;
	}

	hostent* lpstHostent;

	/* Resolve hostname for local address*/
	lpstHostent = gethostbyname(szHost);
	if (lpstHostent)
	{
		return *((unsigned long *)lpstHostent->h_addr_list[0]);
	}
	return 0;
}

std::string TranferRouteDisk(unsigned int nIp)
{
	BYTE *p = (BYTE *)&nIp;
	char sz[128] = { 0 };
	sprintf(sz, "%d.%d.%d.%d", p[0], p[1], p[2], 0);
	return std::string(sz);
}

std::string TranferRouteDisk2(unsigned int nIp)
{
	BYTE *p = (BYTE *)&nIp;
	char sz[128];
	if (p[3] == 0)
		sprintf(sz, "%d.%d.%d.%d", p[0], p[1], p[2], p[3]);
	else
		sprintf(sz, "%d.%d.%d.%d", p[0], p[1], p[2], p[3] - 1);
	return std::string(sz);
}

std::string TranferRouteDisk3(unsigned int nIp)
{
	BYTE *p = (BYTE *)&nIp;
	char sz[128] = { 0 };
	sprintf(sz, "%d.%d.%d.%d", p[0], p[1], p[2], 255);
	return std::string(sz);
}

BOOL SetFIONBIO(SOCKET sock, unsigned long ul /*= 1*/)
{
	int n = ioctlsocket(sock, FIONBIO, (unsigned long*)&ul);
	return n == 0;
}

BOOL ConnetTimeOut(SOCKET sock, WTSOCKET_ADDR *sockAddr, int msTimeOut)
{
	if (msTimeOut < 0)
	{
		int tmp = connect(sock, (sockaddr *)sockAddr, sizeof(WTSOCKET_ADDR));
		return 0 == tmp;
	}

	if (SetFIONBIO(sock, 1) == FALSE)
		return FALSE;

	int nCon = connect(sock, (sockaddr *)sockAddr, sizeof(WTSOCKET_ADDR));
	if (nCon == 0)
	{
		SetFIONBIO(sock, 0);
		return TRUE;
	}

	int nLastError = WSAGetLastError();
	if (nCon == SOCKET_ERROR &&  nLastError != WSAEWOULDBLOCK)
	{
		SetFIONBIO(sock, 0);
		return FALSE;
	}

	/*
	下面用select阻塞等待一段时间，等待连接完成。
	select函数中的timeout,参数至关重要，它可以使select处于三种状态，
	第一，若将NULL以形参传入，即不传入时间结构，就是将select置于阻塞状态，一定等到监视文件描述符集合中某个文件描述符发生变化为止；
	第二，若将时间值设为0秒0毫秒，就变成一个纯粹的非阻塞函数，不管文件描述符是否有变化，都立刻返回继续执行，文件无变化返回0，有变化返回一个正值；
	第三，timeout的值大于0，这就是等待的超时时间，即select在timeout时间内阻塞，超时时间之内有事件到来就返回了，否则在超时后不管怎样一定返回，返回值同上述。
	返回值：
	负值：select错误
	正值：某些文件可读写或出错
	0：等待超时，没有可读写或错误的文件
	*/
	struct timeval timeout;
	fd_set r, rexp;

	FD_ZERO(&r);
	FD_ZERO(&rexp);
	FD_SET(sock, &r);
	FD_SET(sock, &rexp);
	timeout.tv_sec = msTimeOut / 1000;
	timeout.tv_usec = msTimeOut % 1000;

	int ret = select((int)sock + 1, 0, &r, &rexp, &timeout);
	if (ret <= 0)
	{
		shutdown(sock, SD_BOTH);
		::closesocket(sock);
		return FALSE;
	}

	if (FD_ISSET(sock, &rexp))
	{
		shutdown(sock, SD_BOTH);
		::closesocket(sock);
		return FALSE;
	}

	if (SetFIONBIO(sock, 0) == false)
	{
		shutdown(sock, SD_BOTH);
		::closesocket(sock);
		return FALSE;
	}

	return TRUE;
}

std::string SockAddrToString(IN WTSOCKET_ADDR *pSocketAddr)
{
	std::stringstream ss;
	ss << inet_ntoa(pSocketAddr->sin_addr) << ":" << htons(pSocketAddr->sin_port);
	return ss.str();
}

std::string IPTypeToString(IP_TYPE ip)
{
	struct in_addr inAddr;
	inAddr.s_addr = ip;
	char* pstr = inet_ntoa(inAddr);
	std::string ret;
	if (pstr)
	{
		ret = pstr;
	}
	return ret;
}

BOOL WinSockInit()
{
	WSADATA wsaData = { 0 };
	int iResult = 0;
	iResult = WSAStartup(MAKEWORD(2, 2), &wsaData);
	if (iResult != 0) {
		//wprintf(L"WSAStartup failed: %d\n", iResult);
		return FALSE;
	}
	return TRUE;
}

void WinSockCleanup()
{
	WSACleanup();
}