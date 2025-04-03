#include "stdafx.h"
#include "util/AutoMemory.h"
#include "util/subprocess.h"
#include "sockbase.h"
#include "XyzRoute.h"
#include "AdapterInformation.h"
#include "util/OSVersion.h"
#include <Netioapi.h>
#include "tap-windows.h"
#include "DKTraces.h"
#include <sstream>

BOOL CxyzRoute::GetWindowsRoutingTable(OUT CAutoMem* pMem)
{
	ULONG size = 0;
	DWORD status;

	status = GetIpForwardTable(NULL, &size, TRUE);
	if (status == ERROR_INSUFFICIENT_BUFFER)
	{
		pMem->ChgLen(size);
		PMIB_IPFORWARDTABLE pBuf = (PMIB_IPFORWARDTABLE)pMem->GetBuffer();
		status = GetIpForwardTable(pBuf, &size, TRUE);
		if (status != NO_ERROR)
		{
			DKTRACEA("NOTE: GetIpForwardTable returned error %u\n", GetLastError());
			return FALSE;
		}
		else
			return TRUE;
	}
	return FALSE;
}

MIB_IPFORWARDROW * CxyzRoute::GetDefaultGatewayRow(MIB_IPFORWARDTABLE *routes)
{
	DWORD lowest_metric = MAXDWORD;
	MIB_IPFORWARDROW *ret = NULL;
	int i;
	int best = -1;

	if (routes)
	{
		for (i = 0; i < (int)routes->dwNumEntries; ++i)
		{
			MIB_IPFORWARDROW *row = &routes->table[i];
			IP_TYPE net = row->dwForwardDest;
			IP_TYPE mask = row->dwForwardMask;
			DWORD index = row->dwForwardIfIndex;
			DWORD metric = row->dwForwardMetric1;

			// 获取默认网关：即路由表中“网络目标”= "0.0.0.0"和“网络掩码”="0.0.0.0"且跃点最小的那个项目。
			if (0 == net && 0 == mask && metric < lowest_metric)
			{
				ret = row;
				lowest_metric = metric;
				best = i;
			}
		}
	}
	return ret;
}

void CxyzRoute::DeleteAllRouteIndex(int nIndex)
{
	CAutoMem mem;
	if (!GetWindowsRoutingTable(&mem))
		return;
	MIB_IPFORWARDTABLE *pIpTables = (MIB_IPFORWARDTABLE *)mem.GetBuffer();
	DWORD lowest_metric = MAXDWORD;
	const MIB_IPFORWARDROW *ret = NULL;
	int i;
	int best = -1;

	if (pIpTables)
	{
		for (i = 0; i < (int)pIpTables->dwNumEntries; ++i) {
			MIB_IPFORWARDROW *row = (MIB_IPFORWARDROW *)&pIpTables->table[i];
			const IP_TYPE net = row->dwForwardDest;
			const IP_TYPE mask = row->dwForwardMask;
			const DWORD index = row->dwForwardIfIndex;
			const DWORD metric = row->dwForwardMetric1;
			if (index == nIndex) {
				DeleteIpForwardEntry(row);
			}
		}
	}
}

DefaultIpinfo CxyzRoute::GetDefaultIp()
{
	DefaultIpinfo info;
	memset(&info, 0, sizeof(DefaultIpinfo));
	CAutoMem mem;
	BOOL bx = GetWindowsRoutingTable(&mem);
	if (bx)
	{
		MIB_IPFORWARDTABLE* pIpTables = (MIB_IPFORWARDTABLE*)mem.GetBuffer();
		MIB_IPFORWARDROW *pDef = (MIB_IPFORWARDROW *)GetDefaultGatewayRow(pIpTables);
		if (pDef == NULL)
		{
			return info;
		}
		info.index_ = pDef->dwForwardIfIndex;
		const IP_ADAPTER_INFO *ip = AdapterInfo::get_adapter_info(info.index_, &mem);
		if (ip)
		{
			DKTRACEA("Default IP: %s\n", ip->IpAddressList.IpAddress.String);
			info.defaultIP_ = GetHostID(ip->IpAddressList.IpAddress.String);
			info.defaultGateway = GetHostID(ip->GatewayList.IpAddress.String);
		}
	}
	return info;
}

typedef VOID(__stdcall *PFUNInitializeIpInterfaceEntry)(PMIB_IPINTERFACE_ROW);
typedef DWORD(__stdcall *PFUNC_IPINERNTRY)(PMIB_IPINTERFACE_ROW);

PFUNInitializeIpInterfaceEntry m_pInitInfEntry = NULL;
PFUNC_IPINERNTRY m_pFunGetInfEntry = NULL;
PFUNC_IPINERNTRY m_pFunSetInfEntry = NULL;

DWORD CxyzRoute::set_interface_metric(const NET_IFINDEX index, const ADDRESS_FAMILY family, const ULONG metric)
{
	DWORD err = 0;
	if (qcutil::IsOsWindowsVistaorLater())
	{
		if (!m_pInitInfEntry)
		{
			HMODULE m_hInst = ::LoadLibrary(TEXT("Iphlpapi.dll"));
			if (NULL != m_hInst)
			{
				m_pInitInfEntry = (PFUNInitializeIpInterfaceEntry)GetProcAddress(m_hInst, "InitializeIpInterfaceEntry");
				m_pFunGetInfEntry = (PFUNC_IPINERNTRY)GetProcAddress(m_hInst, "GetIpInterfaceEntry");
				m_pFunSetInfEntry = (PFUNC_IPINERNTRY)GetProcAddress(m_hInst, "SetIpInterfaceEntry");
			}
		}

		if (m_pInitInfEntry && m_pFunGetInfEntry && m_pFunSetInfEntry)
		{
			MIB_IPINTERFACE_ROW ipiface;
			m_pInitInfEntry(&ipiface);
			ipiface.Family = family;
			ipiface.InterfaceIndex = index;
			err = m_pFunGetInfEntry(&ipiface);
			if (err == NO_ERROR)
			{
				if (family == AF_INET)
				{
					/* required for IPv4 as per MSDN */
					ipiface.SitePrefixLength = 0;
				}
				ipiface.Metric = metric;
				if (metric == 0)
				{
					ipiface.UseAutomaticMetric = TRUE;
				}
				else
				{
					ipiface.UseAutomaticMetric = FALSE;
				}
				err = m_pFunSetInfEntry(&ipiface);
				if (err == NO_ERROR)
				{
					return 0;
				}
			}
		}
	}

	return err;
}

bool CxyzRoute::AddRoute(IP_TYPE ipDest, IP_TYPE ipMask, IP_TYPE ipNextHop, int adapter_index)
{
	DWORD status;
	if (adapter_index == TUN_ADAPTER_INDEX_INVALID)
	{
		DKTRACEA("ROUTE: adapter_index == TUN_ADAPTER_INDEX_INVALID");
		return false;
	}

	MIB_IPFORWARDROW fr;
	ZeroMemory(&fr, sizeof(fr));
	fr.dwForwardDest = ipDest;
	fr.dwForwardMask = ipMask;
	fr.dwForwardPolicy = 0;
	fr.dwForwardNextHop = ipNextHop;
	fr.dwForwardIfIndex = adapter_index;
	fr.dwForwardType = 4; /* the next hop is not the final dest */
	fr.dwForwardProto = 3; /* PROTO_IP_NETMGMT */
	fr.dwForwardAge = 0;
	fr.dwForwardNextHopAS = 0;
	fr.dwForwardMetric1 = qcutil::IsOsWindowsVistaorLater() ? BLOCK_DNS_IFACE_METRIC : 1;
	fr.dwForwardMetric2 = METRIC_NOT_USED;
	fr.dwForwardMetric3 = METRIC_NOT_USED;
	fr.dwForwardMetric4 = METRIC_NOT_USED;
	fr.dwForwardMetric5 = METRIC_NOT_USED;

	if ((ipDest & ipMask) != ipDest)
	{
		DKTRACEA("ROUTE Warning: address %s is not a network address in relation to netmask %s\n", IPTypeToString(ipDest).c_str(), IPTypeToString(ipMask).c_str());
	}

	status = CreateIpForwardEntry(&fr);

	if (status == NO_ERROR)
	{
		//DKTRACEA("ROUTE: CreateIpForwardEntry succeeded!\n");
		return true;
	}
	/* failed, try increasing the metric to work around Vista issue */
	const unsigned int forward_metric_limit = 2048; /* iteratively retry higher metrics up to this limit */

	for (; fr.dwForwardMetric1 <= forward_metric_limit; ++fr.dwForwardMetric1)
	{
		/* try a different forward type=3 ("the next hop is the final dest") in addition to 4.
		* --redirect-gateway over RRAS seems to need this. */
		for (fr.dwForwardType = 4; fr.dwForwardType >= 3; --fr.dwForwardType)
		{
			status = CreateIpForwardEntry(&fr);
			if (status == NO_ERROR)
			{
				DKTRACEA("ROUTE: CreateIpForwardEntry succeeded with dwForwardMetric1=%u and dwForwardType=%u\n", fr.dwForwardMetric1, fr.dwForwardType);
				return true;
			}
			else if (status != ERROR_BAD_ARGUMENTS)
			{
				DKTRACEA("ROUTE: CreateIpForwardEntry error: %u", GetLastError());
				return false;
			}
		}
	}
	return false;
}

bool CxyzRoute::DelRoute(IP_TYPE ipRoute, IP_TYPE ipMask, IP_TYPE ipGetWay, int adapter_index)
{
	DWORD status;

	if (adapter_index != TUN_ADAPTER_INDEX_INVALID)
	{
		MIB_IPFORWARDROW fr;
		ZeroMemory(&fr, sizeof(fr));

		fr.dwForwardDest = ipRoute;
		fr.dwForwardMask = ipMask;
		fr.dwForwardPolicy = 0;
		fr.dwForwardNextHop = ipGetWay;
		fr.dwForwardIfIndex = adapter_index;

		status = DeleteIpForwardEntry(&fr);

		if (status == NO_ERROR)
		{
			return true;
		}
		else
		{
			DKTRACEA("ROUTE: route deletion failed using DeleteIpForwardEntry: %s\n", IPTypeToString(ipRoute).c_str());
		}
	}
	DKTRACEA("ROUTE: del route:%s, mask: %s, gateway: %s, index: %d\n",
		IPTypeToString(ipRoute).c_str(),
		IPTypeToString(ipMask).c_str(),
		IPTypeToString(ipGetWay).c_str(),
		adapter_index);
	return false;
}


bool CxyzRoute::DelIpFromDefGateway(IP_TYPE ip)
{
	CAutoMem mem;
	if (GetWindowsRoutingTable(&mem))
	{
		MIB_IPFORWARDTABLE *pIpTables = (MIB_IPFORWARDTABLE *)mem.GetBuffer();
		MIB_IPFORWARDROW *pDef = GetDefaultGatewayRow(pIpTables);
		if (pDef == NULL)
		{
			std::string ret;
			std::string cmd = "route.exe delete ";
			cmd += IPTypeToString(ip);
			qcutil::subprocess::CreateProcessEx(cmd, ret, FALSE);
			return false;
		}
		else
		{
			pDef->dwForwardDest = ip;
			pDef->dwForwardMask = 0xffffffff;
			if (!DelRoute(ip, 0xffffffff, pDef->dwForwardNextHop, pDef->dwForwardIfIndex))
			{
				std::string ret;
				std::string cmd = "route.exe delete ";
				cmd += IPTypeToString(ip);
				qcutil::subprocess::CreateProcessEx(cmd, ret, FALSE);
				return false;
			}
			else
				return true;
		}
	}
	return false;
}

bool CxyzRoute::AddIpToDefGateway(IP_TYPE ip)
{
	if (ip == 0)
	{
		return false;
	}
	CAutoMem mem;
	if (GetWindowsRoutingTable(&mem))
	{
		MIB_IPFORWARDTABLE *pIpTables = (MIB_IPFORWARDTABLE *)mem.GetBuffer();
		MIB_IPFORWARDROW *pDef = GetDefaultGatewayRow(pIpTables);
		if (pDef == NULL)
			return false;
		pDef->dwForwardDest = ip;
		pDef->dwForwardMask = 0xffffffff;
		if (FALSE == AddRoute(ip, 0xffffffff, pDef->dwForwardNextHop, pDef->dwForwardIfIndex))
		{
			std::stringstream ss;
			ss << "route.exe add " << IPTypeToString(ip) << " mask 255.255.255.255 " << IPTypeToString(pDef->dwForwardNextHop) << " METRIC " << 1;
			std::string strCommandLine = ss.str();
			DKTRACEA("Run command: %s\n", strCommandLine.c_str());
			std::string ret;
			DWORD dwRet = qcutil::subprocess::CreateProcessEx(strCommandLine, ret);
			if (!ret.empty())
			{
				DKTRACEA("%s\n", ret.c_str());
			}
			return dwRet == 0;
		}
		else
			return true;
	}
	else
		return false;

}
