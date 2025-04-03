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
	������select�����ȴ�һ��ʱ�䣬�ȴ�������ɡ�
	select�����е�timeout,����������Ҫ��������ʹselect��������״̬��
	��һ������NULL���βδ��룬��������ʱ��ṹ�����ǽ�select��������״̬��һ���ȵ������ļ�������������ĳ���ļ������������仯Ϊֹ��
	�ڶ�������ʱ��ֵ��Ϊ0��0���룬�ͱ��һ������ķ����������������ļ��������Ƿ��б仯�������̷��ؼ���ִ�У��ļ��ޱ仯����0���б仯����һ����ֵ��
	������timeout��ֵ����0������ǵȴ��ĳ�ʱʱ�䣬��select��timeoutʱ������������ʱʱ��֮�����¼������ͷ����ˣ������ڳ�ʱ�󲻹�����һ�����أ�����ֵͬ������
	����ֵ��
	��ֵ��select����
	��ֵ��ĳЩ�ļ��ɶ�д�����
	0���ȴ���ʱ��û�пɶ�д�������ļ�
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