#include "stdafx.h"
#include <sstream>
#include "DKTraces.h"
#include "util/AutoMemory.h"
#include "util/StringEx.h"
#include "util/subprocess.h"
#include "sockbase.h"
#include "AdapterInformation.h"
#include "tap-windows.h"

namespace AdapterInfo
{
	IP_ADAPTER_INFO* get_adapter_info(DWORD index, CAutoMem *pMem)
	{
		return get_adapter(get_adapter_info_list(pMem), index);
	}

	IP_ADAPTER_INFO* get_adapter_info_list(CAutoMem *pMem)
	{
		ULONG size = 0;
		IP_ADAPTER_INFO *pi = NULL;
		DWORD status;

		if ((status = GetAdaptersInfo(NULL, &size)) == ERROR_BUFFER_OVERFLOW)
		{
			pMem->ChgLenAndSeek(size, 0);
			pi = (PIP_ADAPTER_INFO)pMem->GetBuffer();
			if ((status = GetAdaptersInfo(pi, &size)) != NO_ERROR)
			{
				pi = NULL;
				DKTRACEA("FATAL:GetAdaptersInfo #2 failed ErrCode = [%u]", GetLastError());
			}
		}
		return pi;
	}

	IP_ADAPTER_INFO* get_adapter(IP_ADAPTER_INFO *ai, DWORD index)
	{
		if (ai && index != TUN_ADAPTER_INDEX_INVALID)
		{
			IP_ADAPTER_INFO *a;
			/* find index in the linked list */
			for (a = ai; a != NULL; a = a->Next)
			{
				if (a->Index == index)
					return a;
			}
		}
		return NULL;
	}

	DWORD get_adapter_index_method_1(LPCTSTR lpszGuid)
	{
		DWORD index;
		ULONG aindex;
		std::wstring str(_T("\\DEVICE\\TCPIP_"));
		str += lpszGuid;
		if (GetAdapterIndex((LPWSTR)str.c_str(), &aindex) != NO_ERROR)
			index = TUN_ADAPTER_INDEX_INVALID;
		else
		{
			DKTRACEA("成功通过GetAdapterIndex获取到tap索引: %u\n", aindex);
			index = (DWORD)aindex;
		}
		return index;
	}

	DWORD get_adapter_index_method_2(LPCTSTR lpszGuid)
	{
		DWORD index = TUN_ADAPTER_INDEX_INVALID;
		std::string strGuid = String::fromStdWString(lpszGuid);
		CAutoMem mem;
		const IP_ADAPTER_INFO *pi = get_adapter_info_list(&mem);;
		while (pi)
		{
			if (_stricmp(strGuid.c_str(), pi->AdapterName) == 0)
			{
				index = pi->Index;
				DKTRACEA("成功通过method_2获取到tap索引: %u\n", index);
				break;
			}
			pi = pi->Next;
		}
		return index;
	}

	DWORD get_adapter_index(LPCTSTR lpszGuid)
	{
		DWORD index;
		index = get_adapter_index_method_1(lpszGuid);
		if (index == TUN_ADAPTER_INDEX_INVALID)
			index = get_adapter_index_method_2(lpszGuid);

		if (index == TUN_ADAPTER_INDEX_INVALID)
		{
			DKTRACEA("获取Tap接口%S的索引失败了\n", lpszGuid);
		}
		return index;
	}

	DHCP_Status GetDhcpStatus(DWORD index)
	{
		CAutoMem mem;
		DHCP_Status ret = DHCP_STATUS_UNDEF;
		if (index != TUN_ADAPTER_INDEX_INVALID)
		{
			const IP_ADAPTER_INFO *ai = get_adapter_info(index, &mem);
			if (ai)
			{
				if (ai->DhcpEnabled)
				{
					DKTRACEA("Current tap DHCP status : DHCP_STATUS_ENABLED\n");
					ret = DHCP_STATUS_ENABLED;
				}
				else
				{
					DKTRACEA("Current tap DHCP status : DHCP_STATUS_DISABLED\n");
					ret = DHCP_STATUS_DISABLED;
				}
			}
			else
			{
				DKTRACEA("Current tap DHCP status : Unknown 1\n");
			}
		}
		else
		{
			DKTRACEA("Current tap DHCP status : Unknown 2\n");
		}
		return ret;
	}

	BOOL NetShSetDhcpEnable(const std::string& lpszName, int nSleep/*=200*/)
	{
		BOOL bRet = FALSE;
		std::stringstream ss;
		ss << "interface ip set address \"" << lpszName << "\" dhcp";

		char DirNetsh[MAX_PATH] = { 0 };
		GetWindowsDirectoryA(DirNetsh, _countof(DirNetsh));
		std::string NetshCmd(DirNetsh);
		NetshCmd += "\\System32\\netsh.exe";
		NetshCmd += " ";
		NetshCmd += ss.str();

		DKTRACEA("执行Netsh命令:%s\n", NetshCmd.c_str());
		std::string ret;
		DWORD dw = qcutil::subprocess::CreateProcessEx(NetshCmd.c_str(), ret);
		if (!ret.empty())
		{
			DKTRACEA("%s\n", ret.c_str());
		}

		switch (dw)
		{
		case 0:
			DKTRACEA("已成功执行命令。\n");
			bRet = TRUE;
			break;
		case (DWORD)-1:
			DKTRACEA("执行命令失败，原因：命令行太长。\n");
			break;
		case (DWORD)-2:
			DKTRACEA("执行命令失败，原因：创建子进程失败，错误码:%u。\n", GetLastError());
			break;
		default:
			DKTRACEA("已执行netsh命令，但命令的返回值为%u。\n", dw);
			break;
		}

		if (nSleep > 0)
			Sleep(nSleep);

		return bRet;
	}

	BOOL NetShSetDhcpDisenable(const std::string& lpszName, int nSleep /*= 200*/)
	{
		BOOL bRet = FALSE;
		std::stringstream ss;
		ss << "interface ip set address \"" << lpszName << "static 0.0.0.0 0.0.0.0";

		char DirNetsh[MAX_PATH] = { 0 };
		GetWindowsDirectoryA(DirNetsh, _countof(DirNetsh));
		std::string NetshCmd(DirNetsh);
		NetshCmd += "\\System32\\netsh.exe";
		NetshCmd += " ";
		NetshCmd += ss.str();

		DKTRACEA("执行Netsh命令:%s\n", NetshCmd.c_str());
		std::string ret;
		DWORD dw = qcutil::subprocess::CreateProcessEx(NetshCmd.c_str(), ret);
		if (!ret.empty())
		{
			DKTRACEA("%s\n", ret.c_str());
		}

		switch (dw)
		{
		case 0:
			DKTRACEA("已成功执行命令。\n");
			bRet = TRUE;
			break;
		case (DWORD)-1:
			DKTRACEA("执行命令失败，原因：命令行太长。\n");
			break;
		case (DWORD)-2:
			DKTRACEA("执行命令失败，原因：创建子进程失败，错误码:%u。\n", GetLastError());
			break;
		default:
			DKTRACEA("已执行netsh命令，但命令的返回值为%u。\n", dw);
			break;
		}

		if (nSleep > 0)
			Sleep(nSleep);

		return bRet;
	}

	bool IsSetTapIp(IP_TYPE ip, DWORD index)
	{
		CAutoMem mem;
		bool ret = false;
		if (index != TUN_ADAPTER_INDEX_INVALID)
		{
			std::string strCurIP = IPTypeToString(ip);
			DKTRACEA("Current IP:%s\n", strCurIP.c_str());
			IP_ADAPTER_INFO *ai = get_adapter_info(index, &mem);
			if (ai)
			{
				//DKTRACEA("ai not null\n");
				IP_ADAPTER_INFO * pnext = ai;
				while (pnext)
				{
					IP_ADDR_STRING *pIpAddrString = &(pnext->IpAddressList);
					std::string strIp = pIpAddrString->IpAddress.String;
					DKTRACEA("Tapip %s\n", strIp.c_str());
					if (strCurIP == strIp)
					{
						ret = true;
						break;
					}
					pnext = pnext->Next;
				}
			}
		}
		return ret;
	}

};