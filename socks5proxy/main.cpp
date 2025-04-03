// socks5proxy.cpp : 定义控制台应用程序的入口点。
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
	auto work = boost::asio::make_work_guard(io); // 添加 work_guard
	OnVPN(io);
	WinSockCleanup();
    return 0;
}

BOOL OnVPN(asio::io_context &io)
{
	
	printf("请输入需要连接目标节点地址，以IP端口或者域名端口的形式:\n");
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
		printf("不合法的输入，请用冒号隔开IP（域名）和端口。\n");
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
	// 最大报文段长度选项1200
	pTun->SetTcpMss(1200);
	//4秒内如果没有初始化好网卡就连接失败
	for (int i = 0; i < 50 * 4 && (!pTun->IsReady()); i++)
	{
		Sleep(20);
	}

	if (!pTun->IsReady())
	{
		DKTRACEA("失败。Tun设备未就绪。\n");
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
