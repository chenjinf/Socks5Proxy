#include "stdafx.h"
#include "GlobalTun.h"
#include "DKTraces.h"
#include "XyzRoute.h"
#include "AdapterInformation.h"
#include "util/StringEx.h"
#include "util/AutoMemory.h"
#include "util/DateTime.h"
#include "util/OSVersion.h"
#include "util/subprocess.h"
#include "util/WinRegs.h"
#include "HexStr.h"
#include <WinIoCtl.h>
#include <fstream>
#include <sstream>
#include "tap-windows.h"
#include "ITunDataRead.h"
#include "proto.h"
#include <xfunctional>


#define WORKING_BUFFER_SIZE 15000
#define MAX_TRIES 3
#define MALLOC(x) HeapAlloc(GetProcessHeap(), 0, (x))
#define FREE(x) HeapFree(GetProcessHeap(), 0, (x))



std::unordered_map<IpFragmentKey, FragmentData> fragment_cache;


CGlobalTun::CGlobalTun()
{
	m_TcpMss = 1200;
	m_hFileTun = INVALID_HANDLE_VALUE;
	m_TunEthIP = 0;
	m_TunEthNextHop = 0;
	m_TunEthDNS1 = 0;
	m_TunEthDNS2 = 0;
	m_bDefGetWayClient = FALSE;
	m_pReadInterface = nullptr;
	m_hIOCP = nullptr;
	m_hEventClientCreate = CreateEvent(NULL, FALSE, FALSE, NULL);
	Init();
}


CGlobalTun::~CGlobalTun()
{
	if (m_hEventClientCreate)
	{
		CloseHandle(m_hEventClientCreate);
		m_hEventClientCreate = NULL;
	}
	if (m_createthread.joinable()) {
		m_createthread.join();
	}
}

BOOL CGlobalTun::Create(ITunDataRead *pReadIneterface, IP_TYPE ipLocal, IP_TYPE ipMask, IP_TYPE ipDns1, IP_TYPE ipDns2, bool bDefGetWay, const std::string& sNodeServerIp)
{
	if (m_hFileTun != INVALID_HANDLE_VALUE)
	{
		DKTRACEA("����tunʵ�������ȹر�����\n");
		return FALSE;
	}
	DKTRACEA("��������ͻ���: IP��%s - ���룺%s - DNS1��%s - DNS2��%s\n", IPTypeToString(ipLocal).c_str(), IPTypeToString(ipMask).c_str(), IPTypeToString(ipDns1).c_str(), IPTypeToString(ipDns2).c_str());
	//����·����Ϣ��
	//Ŀǰ���·�ɱ���Ϣû�еط�ʹ�ã���ʱ����
	//CAutoMem mem;
	//BOOL bRet = CxyzRoute::GetWindowsRoutingTable(&mem);
	//if (bRet)
	//{
	//	MIB_IPFORWARDTABLE *pIpTables = (MIB_IPFORWARDTABLE *)mem.GetBuffer();
	//	if (pIpTables)
	//	{
	//		for (UINT i = 0; i<pIpTables->dwNumEntries; i++)
	//		{
	//			if (pIpTables->table[i].dwForwardDest != 0)
	//			{
	//				m_RouteTable[(pIpTables->table[i].dwForwardDest) & pIpTables->table[i].dwForwardMask] = pIpTables->table[i].dwForwardMask;
	//				m_mask.push_back(pIpTables->table[i].dwForwardMask);
	//			}
	//		}

	//		/*
	//		//
	//		// �����APNIC���ߵ�ַ���в�������"CN"�ĵ�ַ�������Ѿ�������delegated-apnic-latest.txt�ļ��Ѿ���ʹ�ã���
	//		// APNIC�ǹ�����̫����IP��ַ����Ļ����������ŷḻ׼ȷ��IP��ַ����⣬ͬʱ��Щ��ϢҲ�Ƕ��⹫���ģ�
	//		// ����APNIC�����http://ftp.apnic.net/apnic/stats/apnic/README.TXT
	//		//
	//		std::string strFileName("delegated-apnic-latest.txt");
	//		std::string strFullPath = Path::getApplicationDirPath() + "route\\" + strFileName;
	//		std::ifstream input(strFullPath.c_str(), std::ios::in | std::ios::binary);
	//		std::string line;
	//		while(std::getline(input, line))
	//		{
	//		int len1 = line.find("|", 0);
	//		int len2 = line.find("|", len1 + 1);
	//		int len3 = line.find("|", len2 + 1);
	//		int len4 = line.find("|", len3 + 1);
	//		int len5 = line.find("|", len4 + 1);
	//		std::string test = line.substr(len1 + 1, len2 - len1 - 1);
	//		if (line.substr(len1 + 1, len2 - len1 - 1) == "CN")
	//		{
	//		DWORD tmp = 0xffffffff - atoi(line.substr(len4 + 1, len5 - len4 - 1).c_str()) + 1;
	//		DWORD value = htonl(tmp);
	//		DWORD  key = inet_addr(line.substr(len3 + 1, len4 - len3 - 1).c_str());
	//		m_RouteTable[key] = value;
	//		m_mask.push_back(value);
	//		}
	//		line.empty();
	//		}
	//		*/
	//		m_mask.sort(std::greater<IP_TYPE>());
	//		m_mask.unique();
	//	}
	//}

	/*
	//
	// ���´���ԭ���ڵ���DNS��������(�������������İ�ͷIP)�����ѷ�����
	// �ڻ��������У���������������������ˡ�
	// ������жϸ�����������Ŀ���ַ�Ƿ��ڹ����б���,��������ضϷ��ʡ�
	// �����ټ����ж�Ŀ���ַ�Ƿ���m_DnsSendServer�У�����������滻����ԭ·������
	// ����������·���DNS��ַ10.100.1.1�����Ǳ��ص�DNS192.168.1.1�����ʱ�����10.100.1.1����������������ת����192.168.1.1��������������
	//
	CFilter test1(std::string(""));
	for (unsigned int i=0; i< RuleLength; i++)
	{
	m_pCombinedMatcher->add(*(test1.fromText(rules[i])));
	}
	*/

	m_TunEthIP = ipLocal;
	m_TunEthNextHop = ipMask;
	m_TunEthDNS1 = ipDns1;
	m_TunEthDNS2 = ipDns2;

	// ע���ڻ�����������ʼ��Ϊ�գ����������������ǿ��Ի�ȡ�ġ�
	// Ҫע������ط���������ı仯��
	//m_DnsSendServer,Ŀǰû�п����еط�ʹ�ã���ʱ����
	/*if (m_Dns.empty())
	{
		DKTRACEA("FATAL:NET DNS Config Info Is NULL\n");
	}
	else if (m_Dns.size() == 1)
	{
		m_DnsSendServer[ipDns1] = inet_addr(m_Dns[0].c_str());
		m_DnsSendServer[ipDns2] = inet_addr(m_Dns[0].c_str());
	}
	else
	{
		m_DnsSendServer[ipDns1] = inet_addr(m_Dns[0].c_str());
		m_DnsSendServer[ipDns2] = inet_addr(m_Dns[1].c_str());
	}*/

	m_bDefGetWayClient = bDefGetWay;
	m_strServerIP = sNodeServerIp;
	m_pReadInterface = pReadIneterface; 
	m_createthread = std::thread(&CGlobalTun::DoCreateClient, this);
	// �ȴ���������Ϣ
	WaitForSingleObject(m_hEventClientCreate, INFINITE);
	if (m_hFileTun == INVALID_HANDLE_VALUE)
	{
		return FALSE;
	}
	return TRUE;
}

BOOL CGlobalTun::Write(void *buf, int Packet_len)
{
	// ����һ��ȫ�µ�AutoMem���󣬲������ݿ���������
	// ���������buf���ͷŵ�Ҳû�й�ϵ�ˡ�
	CAutoMem *pMem = new CAutoMem(Packet_len);
	pMem->Write(buf, Packet_len);
	// ���뵽д��tun�豸�����ݰ����С�
	m_memListWriteTun.push(pMem);
	return TRUE;
}

void CGlobalTun::Close()
{
	if (m_hFileTun == INVALID_HANDLE_VALUE)
	{
		return;
	}
	if (m_nTapIndex != TUN_ADAPTER_INDEX_INVALID)
	{
		DKTRACEA("��·�ɱ���ɾ�������ӿ�%u�������\n", m_nTapIndex);
		CxyzRoute::DeleteAllRouteIndex(m_nTapIndex);
	}

	m_bQuit = TRUE;
	m_memListWriteTun.abort();
	if (m_createthread.joinable()) {
		m_createthread.join();
	}
	for (std::thread &worker : read_workers) {
		if (worker.joinable()) {
			worker.join();
		}
	}
	for (std::thread &worker : write_workers) {
		if (worker.joinable()) {
			worker.join();
		}
	}
	for (auto & Iocontext : m_asyncIocontext)
	{
		delete Iocontext;
	}

	if (m_hFileTun != INVALID_HANDLE_VALUE)
	{
		SetTapConnected(FALSE);
		CloseHandle(m_hFileTun);
		m_hFileTun = INVALID_HANDLE_VALUE;
	}
}

static void CallRouteAddCmd(const std::string& dst, const std::string& mask, const std::string& nextHop, int metric, DWORD IFIndex)
{
	std::stringstream ss;
	ss << "route add " << dst << " mask " << mask << " " << nextHop << " METRIC " << metric << " IF " << IFIndex;
	std::string strCommandLine = ss.str();
	DKTRACEA("Run command: %s\n", strCommandLine.c_str());
	std::string ret;
	DWORD dwRet = qcutil::subprocess::CreateProcessEx(strCommandLine, ret);
	if (!ret.empty())
	{
		DKTRACEA("%s\n", ret.c_str());
	}
	// switch(dwRet) ...
}

//void CGlobalTun::DoCreateClient()
//{
//	DKTRACEA("Tun�豸������,IP: %s, Ŀ�꣨����?��: %s, DNS1��%s, DNS2��%s\n", IPTypeToString(m_TunEthIP).c_str(), IPTypeToString(m_TunEthNextHop).c_str(), IPTypeToString(m_TunEthDNS1).c_str(), IPTypeToString(m_TunEthDNS2).c_str());
//	if (!OpenTun(m_TunEthIP, m_TunEthNextHop, m_TunEthDNS1, m_TunEthDNS2))
//	{
//		// Note: ���ۺ�ʱ���ض�Ҫȷ����������¼������ã���������һ���̻߳�һֱ�ȴ���
//		SetEvent(m_hEventClientCreate);
//		return;
//	}
//
//	// ��ȡTAP��IP�������������IP�Ĳ�����
//	int nCnt = 0;
//	BOOL TapIPHaveSet = FALSE;
//	do
//	{
//		Sleep(100);
//		nCnt++;
//		if (AdapterInfo::IsSetTapIp(m_TunEthIP, m_nTapIndex))
//		{
//			TapIPHaveSet = TRUE;
//			break;
//		}
//	} while (nCnt < 40);
//	DKTRACEA("IP���úķ�ʱ��: %d ms\n", nCnt * 100);
//	if (!TapIPHaveSet)
//	{
//		DKTRACEA("����IP���÷�����ʱ�����ˡ�\n");
//		if (m_hFileTun != INVALID_HANDLE_VALUE)
//		{
//			SetTapConnected(FALSE);
//			CloseHandle(m_hFileTun);
//			m_hFileTun = INVALID_HANDLE_VALUE;
//		}
//		SetEvent(m_hEventClientCreate);
//		return;
//	}
//	CxyzRoute::DeleteAllRouteIndex(m_nTapIndex);
//	if (qcutil::IsOsWindowsVistaorLater())
//	{
//		CxyzRoute::set_interface_metric(m_nTapIndex, AF_INET, BLOCK_DNS_IFACE_METRIC);
//	}
//
//	//if (m_TunEthIP != LOCALHOST_INT)
//	//{
//	//	// �����и����ʣ�Ϊ����IP"10.100.0.6"ָ����һ���ĵ�ַΪ"10.100.0.5"��������
//	//	CxyzRoute::AddRoute(m_TunEthIP, GetHostID("255.255.255.255"), m_TunEthIP, m_nTapIndex);
//	//	CxyzRoute::AddRoute(GetHostID(TranferRouteDisk3(m_TunEthNextHop).c_str()), GetHostID("255.255.255.255"), m_TunEthIP, m_nTapIndex);
//	//}
//
//	if (m_bDefGetWayClient)
//	{
//		if (qcutil::IsOsWindowsVistaorLater())
//		{
//			if (!CxyzRoute::AddRoute(0, 0, m_TunEthNextHop, m_nTapIndex))
//			{
//				DKTRACEA("���棡ʹ��AddRoute�������·�ɱ�ʧ���ˣ�\n");
//				// ʹ��CxyzRoute::AddRoute���·�ɱ�ʧ���ˣ���Ϊʹ��route.exe��ӡ�
//				CallRouteAddCmd("0.0.0.0", "0.0.0.0", IPTypeToString(m_TunEthNextHop), 3, m_nTapIndex);
//				CallRouteAddCmd("0.0.0.0", "128.0.0.0", IPTypeToString(m_TunEthNextHop), 3, m_nTapIndex);
//			}
//			else
//			{
//				CxyzRoute::AddRoute(0, GetHostID("128.0.0.0"), m_TunEthNextHop, m_nTapIndex);
//			}
//
//			//CallRouteAddCmd("8.8.4.4", "255.255.255.255", IPTypeToString(m_TunEthIP), 2, m_nTapIndex);
//			//CallRouteAddCmd("8.8.8.8", "255.255.255.255", IPTypeToString(m_TunEthIP), 2, m_nTapIndex);
//			
//			//CxyzRoute::AddRoute(GetHostID("8.8.4.4"), GetHostID("255.255.255.255"), m_TunEthNextHop, m_nTapIndex);
//			//CxyzRoute::AddRoute(GetHostID("8.8.8.8"), GetHostID("255.255.255.255"), m_TunEthNextHop, m_nTapIndex);
//			//CxyzRoute::AddRoute(GetHostID(TranferRouteDisk(m_TunEthNextHop).c_str()), GetHostID("255.255.255.0"), m_TunEthIP, m_nTapIndex);
//			
//			CallRouteAddCmd(TranferRouteDisk(m_TunEthIP).c_str(), "255.255.255.0", IPTypeToString(m_TunEthIP), 254, m_nTapIndex);
//			CallRouteAddCmd(IPTypeToString(m_TunEthIP), "255.255.255.255", IPTypeToString(m_TunEthIP), 254, m_nTapIndex);
//			CallRouteAddCmd(TranferRouteDisk3(m_TunEthIP).c_str(), "255.255.255.255", IPTypeToString(m_TunEthIP), 252, m_nTapIndex);
//
//			//CallRouteAddCmd("119.28.28.28", "255.255.255.255", IPTypeToString(m_defaultIP.defaultGateway), 101, m_defaultIP.index_);
//			//CallRouteAddCmd("119.29.29.29", "255.255.255.255", IPTypeToString(m_defaultIP.defaultGateway), 101, m_defaultIP.index_);
//			
//			CallRouteAddCmd(m_strServerIP, "255.255.255.255", IPTypeToString(m_defaultIP.defaultGateway), 101, m_defaultIP.index_);
//			
//			//CxyzRoute::AddRoute(GetHostID("119.28.28.28"), GetHostID("255.255.255.255"), m_defaultIP.defaultGateway, m_defaultIP.index_);
//			//::AddRoute(GetHostID("119.29.29.29"), GetHostID("255.255.255.255"), m_defaultIP.defaultGateway, m_defaultIP.index_);
//
//			//CxyzRoute::AddRoute(GetHostID(m_strServerIP.c_str()), GetHostID("255.255.255.255"), m_defaultIP.defaultGateway, m_defaultIP.index_);
//			CxyzRoute::AddRoute(GetHostID("128.0.0.0"), GetHostID("128.0.0.0"), m_TunEthNextHop, m_nTapIndex);
//
//			CallRouteAddCmd("224.0.0.0", "224.0.0.0", IPTypeToString(m_TunEthIP), 252, m_nTapIndex);
//			CallRouteAddCmd("255.255.255.255", "255.255.255.255", IPTypeToString(m_TunEthIP), 252, m_nTapIndex);
//
//			//CxyzRoute::AddRoute(GetHostID("224.0.0.0"), GetHostID("224.0.0.0"), m_TunEthNextHop, m_nTapIndex);
//			//CxyzRoute::AddRoute(GetHostID("255.255.255.255"), GetHostID("255.255.255.255"), m_TunEthNextHop, m_nTapIndex);
//			//CxyzRoute::AddRoute(GetHostID(m_strServerIP.c_str()), GetHostID("255.255.255.255"), m_TunEthNextHop, m_nTapIndex);
//		}
//		else
//		{
//			//XPϵͳ
//			//Sleep(5000);
//			CallRouteAddCmd("128.0.0.0", "128.0.0.0", IPTypeToString(m_TunEthNextHop), 1, m_nTapIndex);
//			CallRouteAddCmd("0.0.0.0", "0.0.0.0", IPTypeToString(m_TunEthNextHop), 3, m_nTapIndex);
//			CallRouteAddCmd("0.0.0.0", "128.0.0.0", IPTypeToString(m_TunEthNextHop), 1, m_nTapIndex);
//			CallRouteAddCmd(TranferRouteDisk(m_TunEthNextHop), "255.255.255.255", IPTypeToString(m_TunEthNextHop), 1, m_nTapIndex);
//			//CallRouteAddCmd(TranferRouteDisk2(m_TunEthNextHop), "255.255.255.252", IPTypeToString(m_TunEthIP), 1, m_nTapIndex);
//			CallRouteAddCmd(IPTypeToString(m_TunEthIP), "255.255.255.255", IPTypeToString(m_TunEthIP), 1, m_nTapIndex);
//			//CallRouteAddCmd(m_strServerIP, "255.255.255.255", IPTypeToString(m_TunEthNextHop), 1, m_nTapIndex);
//		}
//	}
//
//	m_bIsReady = TRUE;
//	SetEvent(m_hEventClientCreate);
//	OnReadTun();
//}

void CGlobalTun::DoCreateClient()
{
	DKTRACEA("Tun�豸������,IP: %s, Ŀ�꣨����?��: %s, DNS1��%s, DNS2��%s\n", IPTypeToString(m_TunEthIP).c_str(), IPTypeToString(m_TunEthNextHop).c_str(), IPTypeToString(m_TunEthDNS1).c_str(), IPTypeToString(m_TunEthDNS2).c_str());
	if (!OpenTun(m_TunEthIP, m_TunEthNextHop, m_TunEthDNS1, m_TunEthDNS2))
	{
		// Note: ���ۺ�ʱ���ض�Ҫȷ����������¼������ã���������һ���̻߳�һֱ�ȴ���
		SetEvent(m_hEventClientCreate);
		return;
	}

	// ��ȡTAP��IP�������������IP�Ĳ�����
	int nCnt = 0;
	BOOL TapIPHaveSet = FALSE;
	do
	{
		Sleep(100);
		nCnt++;
		if (AdapterInfo::IsSetTapIp(m_TunEthIP, m_nTapIndex))
		{
			TapIPHaveSet = TRUE;
			break;
		}
	} while (nCnt < 40);
	DKTRACEA("IP���úķ�ʱ��: %d ms\n", nCnt * 100);
	if (!TapIPHaveSet)
	{
		DKTRACEA("����IP���÷�����ʱ�����ˡ�\n");
		if (m_hFileTun != INVALID_HANDLE_VALUE)
		{
			SetTapConnected(FALSE);
			CloseHandle(m_hFileTun);
			m_hFileTun = INVALID_HANDLE_VALUE;
		}
		SetEvent(m_hEventClientCreate);
		return;
	}
	CxyzRoute::DeleteAllRouteIndex(m_nTapIndex);
	if (qcutil::IsOsWindowsVistaorLater())
	{
		CxyzRoute::set_interface_metric(m_nTapIndex, AF_INET, BLOCK_DNS_IFACE_METRIC);
	}

	if (m_TunEthIP != LOCALHOST_INT)
	{
		// �����и����ʣ�Ϊ����IP"10.100.0.6"ָ����һ���ĵ�ַΪ"10.100.0.5"��������
		CxyzRoute::AddRoute(m_TunEthIP, GetHostID("255.255.255.255"), m_TunEthIP, m_nTapIndex);
	}

	if (m_bDefGetWayClient)
	{
		if (qcutil::IsOsWindowsVistaorLater())
		{
			if (!CxyzRoute::AddRoute(0, 0, m_TunEthNextHop, m_nTapIndex))
			{
				DKTRACEA("���棡ʹ��AddRoute�������·�ɱ�ʧ���ˣ�\n");
				// ʹ��CxyzRoute::AddRoute���·�ɱ�ʧ���ˣ���Ϊʹ��route.exe��ӡ�
				CallRouteAddCmd("0.0.0.0", "0.0.0.0", IPTypeToString(m_TunEthNextHop), 3, m_nTapIndex);
				CallRouteAddCmd("0.0.0.0", "128.0.0.0", IPTypeToString(m_TunEthNextHop), 3, m_nTapIndex);
			}
			else
			{
				CxyzRoute::AddRoute(0, GetHostID("128.0.0.0"), m_TunEthNextHop, m_nTapIndex);
			}

			CxyzRoute::AddRoute(GetHostID(TranferRouteDisk(m_TunEthNextHop).c_str()), GetHostID("255.255.255.255"), m_TunEthNextHop, m_nTapIndex);
			//CxyzRoute::AddRoute(GetHostID(TranferRouteDisk2(m_TunEthNextHop).c_str()), GetHostID("255.255.255.252"), m_TunEthIP, m_nTapIndex);
			CxyzRoute::AddRoute(m_TunEthNextHop, GetHostID("255.255.255.255"), m_TunEthIP, m_nTapIndex);
			CxyzRoute::AddRoute(GetHostID("128.0.0.0"), GetHostID("128.0.0.0"), m_TunEthNextHop, m_nTapIndex);
		}
		else
		{
			//XPϵͳ
			//Sleep(5000);
			CallRouteAddCmd("128.0.0.0", "128.0.0.0", IPTypeToString(m_TunEthNextHop), 1, m_nTapIndex);
			CallRouteAddCmd("0.0.0.0", "0.0.0.0", IPTypeToString(m_TunEthNextHop), 3, m_nTapIndex);
			CallRouteAddCmd("0.0.0.0", "128.0.0.0", IPTypeToString(m_TunEthNextHop), 1, m_nTapIndex);
			CallRouteAddCmd(TranferRouteDisk(m_TunEthNextHop), "255.255.255.255", IPTypeToString(m_TunEthNextHop), 1, m_nTapIndex);
			//CallRouteAddCmd(TranferRouteDisk2(m_TunEthNextHop), "255.255.255.252", IPTypeToString(m_TunEthIP), 1, m_nTapIndex);
			CallRouteAddCmd(IPTypeToString(m_TunEthIP), "255.255.255.255", IPTypeToString(m_TunEthIP), 1, m_nTapIndex);
		}
	}

	// ���ú����MTU�������Ƭ��
	if (qcutil::IsOsWindowsVistaorLater()) {
		std::string mtu_cmd = "netsh interface ipv4 set subinterface " +
			std::to_string(m_nTapIndex) +
			" mtu=1500 store=persistent";
		std::string ret;
		DWORD dwRet = qcutil::subprocess::CreateProcessEx(mtu_cmd, ret);
		if (!ret.empty())
		{
			DKTRACEA("%s\n", ret.c_str());
		}
	}

	m_bIsReady = TRUE;
	SetEvent(m_hEventClientCreate);
	OnReadTun();
}

void CGlobalTun::WorkerThread()
{
	DWORD bytesTransferred;
	ULONG_PTR key;
	LPOVERLAPPED pov;

	while (!m_bQuit) {
		BOOL status = GetQueuedCompletionStatus(
			m_hIOCP,
			&bytesTransferred,
			&key,
			&pov,
			INFINITE
		);
		if (!status) {
			DWORD err = GetLastError();
			if (err != WAIT_TIMEOUT) {
				DKTRACEA("IOCP����: ");
			}
			continue;
		}
		TapAsyncContext* ctx = CONTAINING_RECORD(pov, TapAsyncContext, ov);
		if (ctx->isReadOperation) {
			// ������յ������ݰ�
			if (bytesTransferred > 0) {

				DKTRACEA("���� %d �ֽ�����", bytesTransferred);
				// �������������ݰ������߼�
				ProcessDataFromTun(ctx->buffer.data(), bytesTransferred);
			}
			ResetEvent(ctx->ov.hEvent);
			StartAsyncRead(ctx); // ���·����ȡ
		}
		else {
			// д�������
			if (bytesTransferred > 0) {
				DKTRACEA("���� %d �ֽ�����", bytesTransferred);
			}
			delete ctx;  // д����������ʹ�ú��ͷ�
		}
	}
}

void CGlobalTun::DoWriteTun()
{
	for (int i = 0; i < 2; ++i)
	{
		write_workers.emplace_back(std::thread(&CGlobalTun::OnWriteTun, this));
	}
}

void CGlobalTun::OnWriteTun()
{
	while (!m_bQuit)
	{
		m_memListWriteTun.wait_data(INFINITE);
		while (!m_bQuit)
		{
			CAutoMem *pMem = m_memListWriteTun.pop();
			if (pMem == NULL)
			{
				break;
			}
			AsyncWrite(pMem);
		}

	}
}

void CGlobalTun::StartAsyncRead(TapAsyncContext* ctx)
{
	DWORD bytesRead;
	if (!ReadFile(
		ctx->hTap,
		ctx->buffer.data(),
		static_cast<DWORD>(ctx->buffer.size()),
		&bytesRead,
		&ctx->ov
	)) {
		DWORD err = GetLastError();
		if (err == ERROR_IO_PENDING) {
			//ctx->isPending = true;
			//delete ctx;
		}
		
	}
	else {
		// ����������ɣ����ټ���
		ProcessDataFromTun(ctx->buffer.data(), bytesRead);
		//CloseHandle(ctx->ov.hEvent);
	}
}

bool CGlobalTun::ProcessDataFromTun(void *buf, UINT dwRead)
{
	/*if (m_TcpMss > 0)
	{
		static CAutoMem mem;
		mem.Attach(buf, dwRead);
		mss_fixup_ipv4((BYTE*)buf, dwRead, m_TcpMss);
	} */  
	struct openvpn_iphdr* ip = reinterpret_cast<openvpn_iphdr*>(buf);

	// ����Ƿ��Ƿ�Ƭ��
	if ((ntohs(ip->frag_off) & 0x1FFF) != 0 || (ntohs(ip->frag_off) & 0x2000)) {
		return HandleIpFragment(ip, dwRead);
	}
	else {
		// ����������
		m_pReadInterface->OnReadTun(reinterpret_cast<BYTE*>(buf), dwRead);
		return true;
	}
}

void CGlobalTun::StartFragmentCleanupThread()
{
	std::thread([this]() {
		while (!m_bQuit) {
			std::this_thread::sleep_for(std::chrono::seconds(30));
			auto now = std::chrono::steady_clock::now();

			for (auto it = fragment_cache.begin(); it != fragment_cache.end();) {
				// ����ʱ30�����Ŀ
				if (now - it->second.last_update > std::chrono::seconds(30)) {
					current_cache_size -= it->second.received_bytes;
					it = fragment_cache.erase(it);
				}
				else {
					++it;
				}
			}
		}
	}).detach();
}

bool CheckAllFragmentsReceived(FragmentData& entry) {
	// ��ʵ�֣�����0�����һ������Ƿ�ȫΪtrue
	for (size_t i = 0; i < entry.received.size(); ++i) {
		if (!entry.received[i]) return false;
	}
	return true;
}

bool CGlobalTun::HandleIpFragment(struct openvpn_iphdr* ip, UINT dwRead)
{
	if (dwRead < sizeof(openvpn_iphdr)) {
		DKTRACEA("��Ч���ݰ�����: %u\n", dwRead);
		return false;
	}
	if (fragment_cache.size() > 10000) { // ��ֹDDoS����
		DKTRACEA("��Ƭ���泬����ȫ��ֵ����ջ���\n");
		fragment_cache.clear();
		current_cache_size = 0;
	}
	const uint16_t frag_off = ntohs(ip->frag_off);
	const uint16_t offset = (frag_off & 0x1FFF) * 8;  // �����ֽ�ƫ��
	const bool is_last = (frag_off & 0x2000) == 0;    // �Ƿ�������Ƭ

													  // �������ݿ���Ϣ
	const uint16_t block_idx = offset / FRAG_BLOCK_SIZE;
	const uint16_t data_size = dwRead - sizeof(openvpn_iphdr);
	const uint8_t* payload = reinterpret_cast<uint8_t*>(ip) + sizeof(openvpn_iphdr);

													  // ���ɻ����
	IpFragmentKey key{
		ip->saddr,
		ip->daddr,
		ntohs(ip->id),
		ip->protocol
	};

	auto& entry = fragment_cache[key];

	// ��ʼ���ܳ��Ⱥ���������
	if (entry.total_length == 0) {
		entry.total_length = ntohs(ip->tot_len);
		if (entry.total_length == 0 || entry.total_length > 65535) {
			fragment_cache.erase(key);
			return false;
		}
		entry.max_block_idx = (entry.total_length - 1) / FRAG_BLOCK_SIZE;
		entry.received.resize(entry.max_block_idx + 1, false);
	}

	// ��֤ block_idx ��Ч��
	if (block_idx > entry.max_block_idx) {
		DKTRACEA("������Ч��Ƭ��block_idx=%u (max=%u)\n", block_idx, entry.max_block_idx);
		return false;
	}

	// ǿ�Ƹ������ݣ���ʹ�ѽ��գ�
	entry.blocks[block_idx] = std::vector<uint8_t>(
		reinterpret_cast<uint8_t*>(ip) + sizeof(openvpn_iphdr),
		reinterpret_cast<uint8_t*>(ip) + sizeof(openvpn_iphdr) + data_size
		);

	// ����״̬
	if (!entry.received[block_idx]) {
		entry.received_bytes += data_size;
		entry.received[block_idx] = true;
		current_cache_size += data_size;
	}

	

	// �����������
	if (is_last && entry.is_complete()) {
		// �����������ݰ�
		std::vector<uint8_t> full_packet;
		full_packet.reserve(entry.total_length);

		// ��˳��ϲ����ݿ�
		uint16_t current_pos = 0;
		for (uint16_t i = 0; i <= (entry.total_length - 1) / FRAG_BLOCK_SIZE; ++i) {
			auto it = entry.blocks.find(i);
			if (it != entry.blocks.end()) {
				const auto& block = it->second;
				const uint16_t copy_size = std::min<uint16_t>(
					block.size(),
					entry.total_length - current_pos
					);

				full_packet.insert(full_packet.end(),
					block.begin(),
					block.begin() + copy_size);
				current_pos += copy_size;
			}
			else {
				// ����ȱʧ�飬����ʧ��
				fragment_cache.erase(key);
				return false;
			}
		}

		// ��������������
		if (current_pos == entry.total_length) {
			m_pReadInterface->OnReadTun(full_packet.data(), full_packet.size());
			current_cache_size -= entry.received_bytes;
			fragment_cache.erase(key);
			return true;
		}
	}
	return false;
}

void CGlobalTun::Init()
{
	//Init parameter
	DWORD dwSize = 0;
	ULONG dwRetVal = 0;
	// default to unspecified address family (both)
	ULONG family = AF_INET;
	// Set the flags to pass to GetAdaptersAddresses
	ULONG flag = GAA_FLAG_INCLUDE_PREFIX | GAA_FLAG_INCLUDE_GATEWAYS;
	ULONG outBufLen = WORKING_BUFFER_SIZE;
	ULONG Iterations = 0;
	PIP_ADAPTER_ADDRESSES pAddresses = NULL;
	m_defaultIP = CxyzRoute::GetDefaultIp();
	if (m_defaultIP.defaultIP_ == 0)
	{
		DKTRACEA("��ȡ����IP��ַʧ���ˡ�\n");
		return;
	}
	//m_strdefaultIP = IPTypeToString(defaultIP);
	// ��ȡ���������Ϣ�����������ơ�MAC ��ַ��IP��DNS�����ص���Ϣ
	// ��ɹ��򱣴浽pCurrAddresses
	PIP_ADAPTER_ADDRESSES pCurrAddresses = NULL;
	do
	{
		pAddresses = (IP_ADAPTER_ADDRESSES *)MALLOC(outBufLen);
		if (pAddresses == NULL)
		{
			DKTRACEA("Memory allocation failed for IP_ADAPTER_ADDRESSES struct.\n");
			break;
		}

		dwRetVal = GetAdaptersAddresses(family, flag, NULL, pAddresses, &outBufLen);
		if (dwRetVal == ERROR_BUFFER_OVERFLOW)
		{
			FREE(pAddresses);
			pAddresses = NULL;
		}
		else
		{
			break;
		}
		Iterations++;
	} while ((dwRetVal == ERROR_BUFFER_OVERFLOW) && (Iterations < MAX_TRIES));
	pCurrAddresses = pAddresses;

	// ȡĬ�������µ�DNS���á�
	if (dwRetVal == NO_ERROR)
	{
		while (pCurrAddresses)
		{
			PIP_ADAPTER_UNICAST_ADDRESS pUnicast = pCurrAddresses->FirstUnicastAddress;
			if (pUnicast == NULL)
			{
				pCurrAddresses = pCurrAddresses->Next;
				continue;
			}
			if (AF_INET == pUnicast->Address.lpSockaddr->sa_family)
			{
				char* ip = inet_ntoa(((sockaddr_in*)pUnicast->Address.lpSockaddr)->sin_addr);
				std::string strPerment(ip);
				if (GetHostID(strPerment.c_str()) == m_defaultIP.defaultIP_)
				{
					IP_ADAPTER_DNS_SERVER_ADDRESS *pDnServer = NULL;
					pDnServer = pCurrAddresses->FirstDnsServerAddress;
					while (pDnServer != NULL)
					{
						((sockaddr_in*)pDnServer->Address.lpSockaddr)->sin_addr;
						sockaddr_in *sa_in = (sockaddr_in *)pDnServer->Address.lpSockaddr;
						std::string dns = inet_ntoa(sa_in->sin_addr);
						m_Dns.push_back(dns.c_str()); ///<<<<<<< DNS���� (����Ĭ�ϵ�DNS����: "192.168.1.1"). <<<<<<<
						DKTRACEA("DNS for local Net interface which match ip %s : %s\n", strPerment.c_str(), dns.c_str());
						pDnServer = pDnServer->Next;
					}
					if (!m_Dns.empty())
					{
						m_IsInitSucess = TRUE;
						break;
					}
				}
			}
			pCurrAddresses = pCurrAddresses->Next;
		}
	}
	else
	{
		DKTRACEA("FATAL:Init DivertImp parameter fail");
	}

	if (pAddresses != NULL)
	{
		FREE(pAddresses);
	}
}

BOOL CGlobalTun::OpenTun(IP_TYPE ipLocal, IP_TYPE ipMask, IP_TYPE ipDns1, IP_TYPE ipDns2)
{
	//��ȡ������Ϣ
	GetTapFromReg();
	GetPanelFromReg();

	if (m_vTapGuids.empty())
	{
		DKTRACEA("��Ϊû���ҵ�tun/tap�豸,�����ʧ��!\n");
		return FALSE;
	}

	std::wstring GuidOpened;
	for (int i = 0; i < (int)m_vTapGuids.size(); i++)
	{
		std::wstring strFile = USERMODEDEVICEDIR + m_vTapGuids[i] + TAP_WIN_SUFFIX;
		DKTRACEA("���Դ�Tun�豸��%S\n", strFile.c_str());
		m_hFileTun = CreateFile(
			strFile.c_str(),
			GENERIC_READ | GENERIC_WRITE,
			0,
			0,
			OPEN_EXISTING,
			FILE_ATTRIBUTE_SYSTEM | FILE_FLAG_OVERLAPPED,
			0
		);
		if (m_hFileTun != INVALID_HANDLE_VALUE)
		{
			m_strTunDevName = strFile;
			GuidOpened = m_vTapGuids[i];
			DKTRACEA("�ɹ���Tun�豸\n");
			break;
		}
		else
		{
			DKTRACEA("�޷����豸��������:%u��\n", GetLastError());
		}
	}
	if (m_hFileTun == INVALID_HANDLE_VALUE)
	{
		DKTRACEA("��Tun�豸ʧ����\n");
		return FALSE;
	}

	m_nTapIndex = AdapterInfo::get_adapter_index(GuidOpened.c_str());

	std::wstring strVersion = GetTapVersion();
	int nMTU = GetTapMTU();

	int nDhcpStatus = AdapterInfo::GetDhcpStatus(m_nTapIndex);
	if (nDhcpStatus != DHCP_STATUS_ENABLED)
	{
		std::wstring IFName = m_mapGuidName[GuidOpened];
		AdapterInfo::NetShSetDhcpEnable(String::fromStdWString(IFName));
	}
	DKTRACEA("Set IP Config for tun/tap device: %s | %s\n", IPTypeToString(ipLocal).c_str(), IPTypeToString(ipMask).c_str());
	SetIpConfig(ipLocal, ipMask);


	DKTRACEA("Set DHCP for tun/tap device: %s | %s\n", IPTypeToString(ipLocal).c_str(), IPTypeToString(ipMask).c_str());
	SetDhcpMasq(ipLocal, ipMask);
	if (ipDns1) {
		DKTRACEA("Set DHCP for tun/tap device: %s | %s\n", IPTypeToString(ipDns1).c_str(), IPTypeToString(ipDns2).c_str());
		SetDhcpDNS(ipDns1, ipDns2);
	}
	//std::string IFName = String::fromStdWString(m_mapGuidName[GuidOpened]);
	//SetIpConfig(ipLocal, ipMask);
	//if (ipDns1) {
	//	SetDhcpDNS(ipDns1, ipDns2);
	//}

	SetTapConnected(TRUE);
	if (m_nTapIndex != TUN_ADAPTER_INDEX_INVALID)
	{
		//FlushIpNetTable�����ӱ��ؼ�����ϵ�ARP����ɾ��ָ���ӿڵ�����ARP��Ŀ��
		DWORD status = ::FlushIpNetTable(m_nTapIndex);
		if (status == NO_ERROR)
		{
			DKTRACEA("�ɹ�ɾ���˽ӿ�(%u)������ARP��Ŀ\n", m_nTapIndex);
		}
		else
		{
			DKTRACEA("ɾ���˽ӿ�(%u)������ARP��Ŀʱ��������%u��\n", m_nTapIndex, status);
		}
	}

	return TRUE;
}

int CGlobalTun::GetTapFromReg()
{
	m_vTapGuids.clear();
	qcutil::CWinRegKey regAdapter(HKEY_LOCAL_MACHINE, ADAPTER_KEYW, FALSE);
	std::vector<std::wstring> subKeys = regAdapter.EnumSubKeys();
	if (subKeys.empty())
	{
		DKTRACEA("û����ע������ҵ�tap�豸����1��\n");
		return 0;
	}

	const wstring strTapComponentID = String(TAP_WIN_COMPONENT_ID).toStdWString();

	for (int i = 0; i != subKeys.size(); i++)
	{
		std::wstring strSubKeyPath = ADAPTER_KEYW;
		strSubKeyPath += L"\\";
		strSubKeyPath += subKeys[i];
		qcutil::CWinRegKey regSubKey(HKEY_LOCAL_MACHINE, strSubKeyPath.c_str(), FALSE);

		wchar_t szComPonentId[256] = { 0 };
		regSubKey.ReadString(L"ComponentId", szComPonentId, sizeof(szComPonentId));
		if (std::wstring(szComPonentId) != strTapComponentID)
		{
			continue;
		}

		wchar_t szNetCfgInstanceId[256] = { 0 };
		regSubKey.ReadString(L"NetCfgInstanceId", szNetCfgInstanceId, sizeof(szNetCfgInstanceId));
		if (szNetCfgInstanceId[0])
		{
			DKTRACEA("TAP GUID: %S\n", szNetCfgInstanceId);
			m_vTapGuids.push_back(szNetCfgInstanceId);
		}
	}

	return (int)m_vTapGuids.size();
}

int CGlobalTun::GetPanelFromReg()
{
	m_mapGuidName.clear();

	qcutil::CWinRegKey reg(HKEY_LOCAL_MACHINE, NETWORK_CONNECTIONS_KEYW, FALSE);
	std::vector<std::wstring> subKeys = reg.EnumSubKeys();
	for (int i = 0; i != subKeys.size(); i++)
	{
		std::wstring keyName = subKeys[i];
		if (keyName.empty())
		{
			continue;
		}

		std::wstring fullKeyPath = NETWORK_CONNECTIONS_KEYW;
		fullKeyPath += L"\\";
		fullKeyPath += keyName;
		fullKeyPath += L"\\Connection";

		qcutil::CWinRegKey subRegKey(HKEY_LOCAL_MACHINE, fullKeyPath.c_str(), FALSE);

		wchar_t szNameValue[256] = { 0 };
		subRegKey.ReadString(L"Name", szNameValue, sizeof(szNameValue));
		if (szNameValue[0])
		{
			//DKTRACEA("GUID-MAP: %S - %S\n", keyName.c_str(), szNameValue);
			m_mapGuidName[keyName] = szNameValue;
		}
	}
	return m_mapGuidName.size();
}

/**
* DeviceIoControl�ļ򵥷�װ����߿������IOCode������������Ϣ��
*/
BOOL DeviceIoControl_Rep(__in HANDLE hDevice,
	__in DWORD dwIoControlCode,
	__in_bcount_opt(nInBufferSize) LPVOID lpInBuffer,
	__in DWORD nInBufferSize,
	__out_bcount_part_opt(nOutBufferSize, *lpBytesReturned) LPVOID lpOutBuffer,
	__in DWORD nOutBufferSize,
	__out_opt LPDWORD lpBytesReturned,
	__inout_opt LPOVERLAPPED lpOverlapped)
{

	std::stringstream ss;
	ss << DateTime().toString() << " DeviceHandle:" << hDevice << ",IOCode:";
	switch (dwIoControlCode)
	{
	case TAP_WIN_IOCTL_GET_MAC:
		ss << "TAP_WIN_IOCTL_GET_MAC";
		break;
	case TAP_WIN_IOCTL_GET_VERSION:
		ss << "TAP_WIN_IOCTL_GET_VERSION";
		break;
	case TAP_WIN_IOCTL_GET_MTU:
		ss << "TAP_WIN_IOCTL_GET_MTU";
		break;
	case TAP_WIN_IOCTL_GET_INFO:
		ss << "TAP_WIN_IOCTL_GET_INFO";
		break;
	case TAP_WIN_IOCTL_CONFIG_POINT_TO_POINT:
		ss << "TAP_WIN_IOCTL_CONFIG_POINT_TO_POINT";
		break;
	case TAP_WIN_IOCTL_SET_MEDIA_STATUS:
		ss << "TAP_WIN_IOCTL_SET_MEDIA_STATUS";
		break;
	case TAP_WIN_IOCTL_CONFIG_DHCP_MASQ:
		ss << "TAP_WIN_IOCTL_CONFIG_DHCP_MASQ";
		break;
	case TAP_WIN_IOCTL_GET_LOG_LINE:
		ss << "TAP_WIN_IOCTL_GET_LOG_LINE";
		break;
	case TAP_WIN_IOCTL_CONFIG_DHCP_SET_OPT:
		ss << "TAP_WIN_IOCTL_CONFIG_DHCP_SET_OPT";
		break;
	default:
		ss << "Unknown IO code!";
		break;
	}
	ss << "\r\nContent:" << BcdToStr(lpInBuffer, nInBufferSize) << "\r\n";

	//DKTRACEA("%s\n", ss.str().c_str());

	return DeviceIoControl(hDevice, dwIoControlCode, lpInBuffer, nInBufferSize, lpOutBuffer, nOutBufferSize, lpBytesReturned, lpOverlapped);
}

std::wstring CGlobalTun::GetTapVersion()
{
	std::wstring strVersion;
	ULONG info[3];
	ZeroMemory(info, sizeof(info));
	DWORD len = sizeof(info);
	if (DeviceIoControl_Rep(m_hFileTun, TAP_WIN_IOCTL_GET_VERSION,
		&info, sizeof(info),
		&info, sizeof(info), &len, NULL))
	{
		std::wstringstream wss;
		wss << (int)info[0] << L"." << (int)info[1] << " " << info[2] ? L"(DEBUG)" : L"";
		strVersion = wss.str();
		DKTRACEA("Tap version: %S\n", strVersion.c_str());
	}
	return strVersion;
}

int CGlobalTun::GetTapMTU()
{
	ULONG mtu = 0;
	DWORD dwLen = 4;
	if (DeviceIoControl_Rep(m_hFileTun, TAP_WIN_IOCTL_GET_MTU,
		&mtu, sizeof(mtu),
		&mtu, sizeof(mtu), &dwLen, NULL))
	{
		DKTRACEA("���TAP-Windows MTU:%u\n", mtu);
	}
	else
		DKTRACEA("��ȡTAP-Windows MTUʧ�ܣ�������%u��\n", GetLastError());
	return mtu;
}

BOOL CGlobalTun::SetIpConfig(/*string pszName,*/IP_TYPE ip, IP_TYPE netMask)
{

	//BOOL bRet = FALSE;
	//std::stringstream ss;
	//ss << "netsh interface ipv4 set address \"" << pszName << "\" static " << IPTypeToString(ip).c_str()\
	//	<< " 255.255.255.0";

	//std::string NetshCmd;
	//NetshCmd = ss.str();

	//DKTRACEA("ִ��Netsh����:%s\n", NetshCmd.c_str());
	//std::string ret;
	//DWORD dw = qcutil::subprocess::CreateProcessEx(NetshCmd.c_str(), ret);
	//if (!ret.empty())
	//{
	//	DKTRACEA("%s\n", ret.c_str());
	//}

	//switch (dw)
	//{
	//case 0:
	//	DKTRACEA("�ѳɹ�ִ�����\n");
	//	bRet = TRUE;
	//	break;
	//case (DWORD)-1:
	//	DKTRACEA("ִ������ʧ�ܣ�ԭ��������̫����\n");
	//	break;
	//case (DWORD)-2:
	//	DKTRACEA("ִ������ʧ�ܣ�ԭ�򣺴����ӽ���ʧ�ܣ�������:%u��\n", GetLastError());
	//	break;
	//default:
	//	DKTRACEA("��ִ��netsh���������ķ���ֵΪ%u��\n", dw);
	//	break;
	//}
	//return bRet;

	IP_TYPE ep[2];
	DWORD len = sizeof(ep);
	ep[0] = ip;
	ep[1] = netMask;
	if (!DeviceIoControl_Rep(m_hFileTun,
		TAP_WIN_IOCTL_CONFIG_POINT_TO_POINT,
		ep,
		sizeof(ep),
		ep,
		sizeof(ep),
		&len, NULL))
	{
		DKTRACEA("FATAL: The TAP-Windows driver rejected a DeviceIoControl call to set Point-to-Point mode, which is required for --dev tun\n");
		return FALSE;
	}
	return TRUE;
}

BOOL CGlobalTun::SetDhcpMasq(IP_TYPE ip, IP_TYPE netMask)
{
	IP_TYPE ep[4];
	DWORD len = sizeof(ep);

	/* We will answer DHCP requests with a reply to set IP/subnet to these values */
	ep[0] = ip;
	ep[1] = GetHostID("255.255.255.0");
	ep[2] = netMask;
	ep[3] = 31536000; /* one year */
	if (!DeviceIoControl_Rep(m_hFileTun, TAP_WIN_IOCTL_CONFIG_DHCP_MASQ,
		ep, sizeof(ep),
		ep, sizeof(ep), &len, NULL))
	{
		DKTRACEA("FATAL:The TAP-Windows driver rejected a DeviceIoControl call to set TAP_WIN_IOCTL_CONFIG_DHCP_MASQ mode");
		return FALSE;
	}
	return TRUE;
}

BOOL CGlobalTun::SetDhcpDNS(/*string pszName,*/ IP_TYPE ip1, IP_TYPE ip2)
{
	/*BOOL bRet = FALSE;
	std::stringstream ss;
	ss << "netsh interface ipv4 set dns \"" << pszName << "\" static " << IPTypeToString(ip1).c_str()\
		<< " primary";

	std::string NetshCmd;
	NetshCmd = ss.str();

	DKTRACEA("ִ��Netsh����:%s\n", NetshCmd.c_str());
	std::string ret;
	DWORD dw = qcutil::subprocess::CreateProcessEx(NetshCmd.c_str(), ret);
	if (ip2 != 0)
	{
		ss.str("");
		ss << "netsh interface ipv4 add dns \"" << pszName << "\" " << IPTypeToString(ip2).c_str()\
		<< " index=2";

		NetshCmd = ss.str();
		dw = qcutil::subprocess::CreateProcessEx(NetshCmd.c_str(), ret);
	}
	
	if (!ret.empty())
	{
		DKTRACEA("%s\n", ret.c_str());
	}

	switch (dw)
	{
	case 0:
		DKTRACEA("�ѳɹ�ִ�����\n");
		bRet = TRUE;
		break;
	case (DWORD)-1:
		DKTRACEA("ִ������ʧ�ܣ�ԭ��������̫����\n");
		break;
	case (DWORD)-2:
		DKTRACEA("ִ������ʧ�ܣ�ԭ�򣺴����ӽ���ʧ�ܣ�������:%u��\n", GetLastError());
		break;
	default:
		DKTRACEA("��ִ��netsh���������ķ���ֵΪ%u��\n", dw);
		break;
	}
	return bRet;*/
	BYTE ep[10];
	DWORD len = sizeof(ep);
	ep[0] = 6;			//dns
	ep[1] = 8;			//len
	*((int *)(ep + 2)) = ip1;
	*((int *)(ep + 6)) = ip2;
	if (!DeviceIoControl_Rep(m_hFileTun, TAP_WIN_IOCTL_CONFIG_DHCP_SET_OPT,
		ep, sizeof(ep),
		ep, sizeof(ep), &len, NULL))
	{
		DKTRACEA("FATAL:The TAP-Windows driver rejected a DeviceIoControl call to set TAP_WIN_IOCTL_CONFIG_DHCP_SET_OPT mode");
		return FALSE;
	}
	return TRUE;
}


BOOL CGlobalTun::SetTapConnected(BOOL bConnect /*= TRUE*/)
{
	ULONG status = bConnect;
	DWORD len = sizeof(status);
	if (!DeviceIoControl_Rep(m_hFileTun, TAP_WIN_IOCTL_SET_MEDIA_STATUS,
		&status, sizeof(status),
		&status, sizeof(status), &len, NULL))
	{
		DKTRACEA("����SET_MEDIA_STATUSʧ�ܣ�������%u\n", GetLastError());
		return FALSE;
	}
	else
	{
		DKTRACEA("�ɹ�����SET_MEDIA_STATUS=%d��\n", bConnect);
		return TRUE;
	}
}



void CGlobalTun::OnReadTun()
{
	m_hIOCP = CreateIoCompletionPort(INVALID_HANDLE_VALUE, NULL, 0, 0);
	CreateIoCompletionPort(m_hFileTun, m_hIOCP, (ULONG_PTR)m_hFileTun, 0);
	size_t threads = std::thread::hardware_concurrency();
	if (threads == 0) threads = 1;
	for (int i = 0; i < threads*2; ++i)
	{
		read_workers.emplace_back(std::thread(&CGlobalTun::WorkerThread, this));
	}

	// ��ʼ���첽��ȡ
	for (int i = 0; i < threads; ++i)
	{
		TapAsyncContext* ctx = new TapAsyncContext(m_hFileTun,2048,true);
		StartAsyncRead(ctx);
		m_asyncIocontext.emplace_back(ctx);
	}
	DoWriteTun();
}

void CGlobalTun::AsyncWrite(CAutoMem * pmem)
{
	auto ctx = new TapAsyncContext(m_hFileTun,2048,false);
	std::copy(pmem->GetBuffer(), pmem->GetCurBuffer(), ctx->buffer.begin());
	DWORD bytesWritten;
	if (!WriteFile(m_hFileTun, ctx->buffer.data(), static_cast<DWORD>(ctx->buffer.size()), &bytesWritten, &ctx->ov)) {
		if (GetLastError() != ERROR_IO_PENDING) {
			DKTRACEA("�첽д��ʧ��: %d", GetLastError());
			delete ctx;
		}
	}
}

void CGlobalTun::mss_fixup_ipv4(BYTE *buf, int nBuflen, int maxmss)
{
	if (nBuflen < (int)sizeof(struct openvpn_iphdr))
	{
		return;
	}
	//verify_align_4(buf);
	const struct openvpn_iphdr *pip = (struct openvpn_iphdr *)buf;
	int hlen = OPENVPN_IPH_GET_LEN(pip->version_len);

	// ��ȡTAP�豸��MTU
	int mtu = GetTapMTU();
	if (mtu <= 0) mtu = 1500; // Ĭ��ֵ

							  // ��������MSS��MTU - IPͷ - TCPͷ��
	int valid_mss = mtu - sizeof(openvpn_iphdr) - sizeof(openvpn_tcphdr);
	if (maxmss > valid_mss) {
		maxmss = valid_mss;
	}

	// ��TCPЭ�飬��Ƭƫ��=0���ײ�����С��nBuflen���ҳ���IP��ͷ֮��ʣ��ռ��������һ��TCPͷ
	if (pip->protocol == OPENVPN_IPPROTO_TCP
		&& (ntohs(pip->frag_off) & OPENVPN_IP_OFFMASK) == 0
		&& hlen <= nBuflen
		&& nBuflen - hlen >= (int)sizeof(struct openvpn_tcphdr))
	{
		//����IP��ͷ�ĳ��ȣ�tcָ����tcpͷ��
		struct openvpn_tcphdr *tc = (struct openvpn_tcphdr *)(buf + hlen);
		if (tc->flags & OPENVPN_TCPH_SYN_MASK)
		{
			// ȡ���ȡ�
			hlen = OPENVPN_TCPH_GET_DOFF(tc->doff_res);
			// ȡ������ͷ��֮���ѡ�
			uint8_t *opt = (uint8_t *)(tc + 1);
			// ѡ��ĳ��ȵ����ܳ��ȼ�ȥͷ�����ȡ�
			int olen = hlen - sizeof(struct openvpn_tcphdr);
			int optlen = 0;
			// ��ѡ��������������TCP���е�ѡ�
			// ���͵�TCPͷ��ѡ��ṹ: kind(1�ֽ�)|length(1�ֽ�)|info(�ɱ䳤��)��ѡ��ĵ�һ���ֶ�kind˵��ѡ������͡��е�TCPѡ��û�к��������ֶΣ�������1�ֽڵ�kind�ֶΡ�
			// �ڶ����ֶ�length������еĵĻ���ָ����ѡ����ܳ��ȣ��ó��Ȱ���kind�ֶκ�length�ֶ�ռ�ݵ�2�ֽڡ��������ֶ�info������еĻ�����ѡ��ľ�����Ϣ��
			// ������TCPѡ����7�֣�
			// kind=0��ѡ������ѡ�
			// kind=1�ǿղ�����nop��ѡ�û�����⺬�壬һ�����ڽ�TCPѡ����ܳ������Ϊ4�ֽڵ���������
			// kind=2������Ķγ���ѡ�TCP���ӳ�ʼ��ʱ��ͨ��˫��ʹ�ø�ѡ����Э������Ķγ��ȣ�Max Segement Size��MSS����
			//       TCPģ��ͨ����MSS����Ϊ��MTU-40���ֽڣ���������40�ֽڰ���20�ֽڵ�TCPͷ����20�ֽڵ�IPͷ������
			//       ����Я��TCP���Ķε�IP���ݱ��ĳ��ȾͲ��ᳬ��MTU������TCPͷ����IPͷ����������ѡ���ֶΣ�������Ҳ��һ���������
			//       �Ӷ����Ȿ������IP��Ƭ������̫�����ԣ�MSSֵ��1460��1500-40���ֽڡ�
			// kind=3�Ǵ�����������ѡ�TCP���ӳ�ʼ��ʱ��ͨ��˫��ʹ�ø�ѡ����Э�̽���ͨ�洰�ڵ��������ӡ�
			// kind=5��SACKʵ�ʹ�����ѡ���ѡ��Ĳ������߷��ͷ������Ѿ��յ�������Ĳ����������ݿ飬�Ӷ��÷��Ͷ˿��Ծݴ˼�鲢�ط���ʧ�����ݿ顣
			// kind=8��ʱ���ѡ���ѡ���ṩ�˽�Ϊ׼ȷ�ļ���ͨ��˫��֮��Ļ�·ʱ�䣨Round Trip Time��RTT���ķ������Ӷ�ΪTCP���������ṩ��Ҫ��Ϣ��
			while (olen > 1)
			{
				if (*opt == OPENVPN_TCPOPT_EOL)
				{
					break;
				}
				else if (*opt == OPENVPN_TCPOPT_NOP)
				{
					optlen = 1;
				}
				else
				{
					optlen = *(opt + 1);
					if (optlen <= 0 || optlen > olen)
					{
						break;
					}
					if (*opt == OPENVPN_TCPOPT_MAXSEG)
					{
						if (optlen != OPENVPN_TCPOLEN_MAXSEG)
						{
							// OPENVPN_TCPOPT_MAXSEG��2��ѡ����ڵĳ���Ӧ����4
							continue;
						}
						unsigned short mssval = (opt[2] << 8) + opt[3];
						if (mssval > maxmss)
						{
							//std::string trace = std::string("mss one dest:") + IPTypeToString(pip->daddr);
							//DKTRACEA("%s\n", trace.c_str());
							int accumulate = htons(mssval);
							opt[2] = (maxmss >> 8) & 0xff;
							opt[3] = maxmss & 0xff;
							accumulate -= htons(maxmss);
							ADJUST_CHECKSUM(accumulate, tc->check);
						}
					}
				}
				olen -= optlen;
				opt += optlen;
			}// end while (olen > 1)
		}
	}
}



