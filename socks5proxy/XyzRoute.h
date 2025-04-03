#pragma once

class CAutoMem;

// 跃点数=3
#define BLOCK_DNS_IFACE_METRIC 3
#define METRIC_NOT_USED ((DWORD)-1)
struct DefaultIpinfo
{
	int index_;
	IP_TYPE defaultIP_;
	IP_TYPE defaultGateway;
};
class CxyzRoute
{
public:
	/**
	* 获取IP路由表信息并保存到一个CAutoMem对象中，如成功执行则可将它转为PMIB_IPFORWARDTABLE结构。
	* \return 如失败则返回FALSE。
	* \remark
	* - 路由表详细信息详见Windows API GetIpForwardTable
	*/
	static BOOL GetWindowsRoutingTable(OUT CAutoMem* mem);

	/**
	* 取本机内网IP（如存在多个，则取路由表中跃点最小那个）
	*/
	static DefaultIpinfo GetDefaultIp();

	/**
	* 获取默认网关，即路由表中“网络目标”= "0.0.0.0"和“网络掩码”="0.0.0.0"且跃点最小的那一行。
	* \return 返回值为输入路由表中的一行。如找不到，则返回NULL。
	*/
	static MIB_IPFORWARDROW* GetDefaultGatewayRow(MIB_IPFORWARDTABLE *routes);

	/**
	* 在路由表中删除网卡索引号为nIndex的所有项。
	*/
	static void DeleteAllRouteIndex(int nIndex);

	/**
	* 设置跃点数，已禁用。
	*/
	static DWORD set_interface_metric(const NET_IFINDEX index, const ADDRESS_FAMILY family, const ULONG metric);

	/**
	* 为adapter_index指定的NetworkInterface的路由表添加项，指定一个IP它下一跳的地址。
	* \param ipDest 目标网络
	* \param ipMask 目标网络掩码
	* \param ipNextHop 下一跳的地址（通常是网关）
	* \param adapter_index 网卡索引号。
	* \return 成功返回true，否则返回false。
	*/
	static bool AddRoute(IP_TYPE ipDest, IP_TYPE ipMask, IP_TYPE ipNextHop, int adapter_index);

	/**
	* 删除路由表中的指定IP。
	*/
	static bool DelRoute(IP_TYPE ipRoute, IP_TYPE ipMask, IP_TYPE ipGetWay, int adapter_index);
	/**
	* 从默认路由（默认路由在局域网通常是192.168.x.1这个地址作为网关）中删除指定的IP。
	*/
	static bool DelIpFromDefGateway(IP_TYPE ip);
	/**
	* 让指定的IP走默认路由（默认路由在局域网通常是192.168.x.1这个地址）。
	*/
	static bool AddIpToDefGateway(IP_TYPE ip);
protected:
private:
};

