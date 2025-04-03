// socks5proxy.cpp : �������̨Ӧ�ó������ڵ㡣
//

#include "stdafx.h"
#include "Sock5Client.h"
#include "GlobalTun.h"
#include "util/StringEx.h"
#include "util/StringList.h"
#include "XyzTun.h"
#include "TunFactory.h"
#include "DKTraces.h"
#include "sockbase.h"
// For GetAdaptersAddresses etc.
#pragma comment(lib, "IPHLPAPI.LIB")
// For PathFileExist etc.
#pragma comment(lib, "SHLWAPI.LIB")
// For soket()/closesocket() etc.
#pragma comment(lib, "WS2_32.lib")
// For GetModuleFileNameEx(), EnumProcessModules() etc.
#pragma comment(lib, "PsAPI.lib")

BOOL OnVPN(asio::io_context &io);

static HANDLE g_hEventQuit = NULL;
static volatile bool g_exit = false;
static BOOL WINAPI console_ctrl_handler(DWORD dwCtrlType)
{
	g_exit = true;
	if (g_hEventQuit)
	{
		SetEvent(g_hEventQuit);
	}
	return TRUE;
}
int main()
{
	WinSockInit();
	boost::asio::io_context io;
	auto work = boost::asio::make_work_guard(io); // ��� work_guard
	OnVPN(io);
	WinSockCleanup();
    return 0;
}

BOOL OnVPN(asio::io_context &io)
{
	
	printf("��������Ҫ����Ŀ��ڵ��ַ����IP�˿ڻ��������˿ڵ���ʽ:\n");
	string ip;
	std::cin >> ip;
	String ipXX(ip);
	ipXX.remove("\r");
	ipXX.remove("\n");
	ipXX.remove("\t");
	ipXX.remove("\b");
	StringList sl = ipXX.split(":");
	if (sl.size() != 2)
	{
		printf("���Ϸ������룬����ð�Ÿ���IP���������Ͷ˿ڡ�\n");
		return FALSE;
	}
	CSock5Client Sock5Client(io);
	Sock5Client.SetLoginParam("tianyiyun", "tianyiyun88", "218.78.74.116", 2668);
	Sock5Client.ForDataTransfer();
	IXyzTun* pTun = CTunFactory::CreateTun();
	BOOL bRet = pTun->Create(&Sock5Client,
		GetHostID("10.198.75.60"),
		GetHostID("10.198.75.61"),
		GetHostID("223.5.5.5"),
		GetHostID("119.29.29.29"),
		true, "218.78.74.116");
	if (!bRet)
	{
		pTun->Close();
		CTunFactory::DestoryTun(pTun);
		Sock5Client.Quit();
		return FALSE;
	}
	//pTun->AddFilePathToWhiteList("C:\\Program Files (x86)\\Google\\Chrome\\Application\\chrome.exe");
	Sock5Client.SetTun(pTun);
	// ����Ķγ���ѡ��1200
	pTun->SetTcpMss(1200);
	//4�������û�г�ʼ��������������ʧ��
	for (int i = 0; i < 50 * 4 && (!pTun->IsReady()); i++)
	{
		Sleep(20);
	}

	if (!pTun->IsReady())
	{
		DKTRACEA("ʧ�ܡ�Tun�豸δ������\n");
		CTunFactory::DestoryTun(pTun);
		Sock5Client.Quit();
		return FALSE;
	}
	io.run();
	g_hEventQuit = CreateEvent(NULL, FALSE, FALSE, NULL);
	TRAFFIC_STATICS oldt = { 0,0,0,0,0 };
	while (!g_exit)
	{
		DWORD dwWait = WaitForSingleObject(g_hEventQuit, 1000);
		if (dwWait == WAIT_TIMEOUT)
		{
			TRAFFIC_STATICS t;
			Sock5Client.GetTraffic(t);
			double downsp = (t.m_llDown - oldt.m_llDown) / 1000.0;
			double upsp = (t.m_llUp - oldt.m_llUp) / 1000.0;
			printf("down: %.02f KB/s , up: %0.2f KB/s               \r", downsp, upsp);
			oldt = t;
		}
		else if (dwWait == WAIT_OBJECT_0)
		{
			break;
		}
	}

	if (pTun)
	{
		pTun->Close();
		CTunFactory::DestoryTun(pTun);
	}
	Sock5Client.Quit();

	printf("Over!\n");
	return TRUE;
}
