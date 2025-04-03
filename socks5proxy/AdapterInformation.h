#pragma once

class CAutoMem;

enum DHCP_Status
{
	DHCP_STATUS_UNDEF = 0,
	DHCP_STATUS_ENABLED = 1,
	DHCP_STATUS_DISABLED = 2
};

namespace AdapterInfo
{
	IP_ADAPTER_INFO* get_adapter_info(DWORD index, CAutoMem *pMem);

	IP_ADAPTER_INFO* get_adapter_info_list(CAutoMem *pMem);

	IP_ADAPTER_INFO* get_adapter(IP_ADAPTER_INFO *ai, DWORD index);

	DWORD get_adapter_index(LPCTSTR lpszGuid);

	DHCP_Status GetDhcpStatus(DWORD index);

	BOOL NetShSetDhcpEnable(const std::string& lpszName, int nSleep = 200);

	BOOL NetShSetDhcpDisenable(const std::string& lpszName, int nSleep = 200);
	/**
	* 查询参数index指定的
	*/
	bool IsSetTapIp(IP_TYPE ip, DWORD index);
};
