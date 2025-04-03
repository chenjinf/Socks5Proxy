#pragma once

class CAutoMem;

// Ծ����=3
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
	* ��ȡIP·�ɱ���Ϣ�����浽һ��CAutoMem�����У���ɹ�ִ����ɽ���תΪPMIB_IPFORWARDTABLE�ṹ��
	* \return ��ʧ���򷵻�FALSE��
	* \remark
	* - ·�ɱ���ϸ��Ϣ���Windows API GetIpForwardTable
	*/
	static BOOL GetWindowsRoutingTable(OUT CAutoMem* mem);

	/**
	* ȡ��������IP������ڶ������ȡ·�ɱ���Ծ����С�Ǹ���
	*/
	static DefaultIpinfo GetDefaultIp();

	/**
	* ��ȡĬ�����أ���·�ɱ��С�����Ŀ�ꡱ= "0.0.0.0"�͡��������롱="0.0.0.0"��Ծ����С����һ�С�
	* \return ����ֵΪ����·�ɱ��е�һ�С����Ҳ������򷵻�NULL��
	*/
	static MIB_IPFORWARDROW* GetDefaultGatewayRow(MIB_IPFORWARDTABLE *routes);

	/**
	* ��·�ɱ���ɾ������������ΪnIndex�������
	*/
	static void DeleteAllRouteIndex(int nIndex);

	/**
	* ����Ծ�������ѽ��á�
	*/
	static DWORD set_interface_metric(const NET_IFINDEX index, const ADDRESS_FAMILY family, const ULONG metric);

	/**
	* Ϊadapter_indexָ����NetworkInterface��·�ɱ�����ָ��һ��IP����һ���ĵ�ַ��
	* \param ipDest Ŀ������
	* \param ipMask Ŀ����������
	* \param ipNextHop ��һ���ĵ�ַ��ͨ�������أ�
	* \param adapter_index ���������š�
	* \return �ɹ�����true�����򷵻�false��
	*/
	static bool AddRoute(IP_TYPE ipDest, IP_TYPE ipMask, IP_TYPE ipNextHop, int adapter_index);

	/**
	* ɾ��·�ɱ��е�ָ��IP��
	*/
	static bool DelRoute(IP_TYPE ipRoute, IP_TYPE ipMask, IP_TYPE ipGetWay, int adapter_index);
	/**
	* ��Ĭ��·�ɣ�Ĭ��·���ھ�����ͨ����192.168.x.1�����ַ��Ϊ���أ���ɾ��ָ����IP��
	*/
	static bool DelIpFromDefGateway(IP_TYPE ip);
	/**
	* ��ָ����IP��Ĭ��·�ɣ�Ĭ��·���ھ�����ͨ����192.168.x.1�����ַ����
	*/
	static bool AddIpToDefGateway(IP_TYPE ip);
protected:
private:
};

