#pragma once
#include <string>
#include <vector>
#include <list>
#include <map>
#include "XyzTun.h"
#include "MemList.h"
#include <atomic>
#include <thread>
#include "XyzRoute.h"
#include <bitset>

// TAP�豸�첽����������
struct TapAsyncContext {
	OVERLAPPED ov = { 0 };
	std::vector<uint8_t> buffer;
	bool isReadOperation;
	HANDLE hTap;

	TapAsyncContext(HANDLE h, size_t size, bool isRead)
		: hTap(h), buffer(size), isReadOperation(isRead)
	{
		ov.hEvent = CreateEvent(NULL, TRUE, FALSE, NULL);
	}

	~TapAsyncContext() {
		if (ov.hEvent) CloseHandle(ov.hEvent);
	}
};


class CGlobalTun:public IXyzTun
{
public:
	CGlobalTun();
	~CGlobalTun();
public:
	virtual BOOL Create(ITunDataRead *pReadIneterface, IP_TYPE ipLocal, IP_TYPE ipMask, IP_TYPE ipDns1, IP_TYPE ipDns2, bool bDefGetWay, const std::string& sNodeServerIp);
	/**
	* ��������Ķγ���ѡ��
	*/
	virtual void SetTcpMss(int nMss) { m_TcpMss = nMss; }
	virtual BOOL IsReady() { return m_bIsReady; }
	virtual BOOL Write(void *buf, int Packet_len);

	/**
	* �ر�tun�豸���������·�ɱ��н������йص���ȫ��ɾ����
	*/
	virtual void Close();
protected:

	void DoCreateClient();
	void WorkerThread();
	void DoWriteTun();
	void OnWriteTun();

private:
	// ��ʼ���첽��ȡ����
	void StartAsyncRead(TapAsyncContext* ctx);
	/**
	* �����tun�ж�ȡ�����ݣ������ʹ��ITunDataRead�ӿڷ�����������
	*/
	bool ProcessDataFromTun(void *buf, UINT dwRead);

	/**
	* ��ʼ����
	*/
	void Init();
	/**
	* ��tun�豸��Ϊ������ip�����롢DNS��DHCP��
	*/
	BOOL OpenTun(IP_TYPE ipLocal, IP_TYPE ipMask, IP_TYPE ipDns1, IP_TYPE ipDns2);

	/**
	* ��ע�����Ѱ��"ComponentId" = "tap0901"���豸������������"NetCfgInstanceId"(GUIDֵ)��m_vTapGuids��
	* \return ����m_vTapGuids�Ĵ�С��
	*/
	int GetTapFromReg();

	/**
	* ����NetworkInterfaceʵ��ID�����ֵ�ӳ�䣬���浽m_mapGuidName��
	* \return ����m_mapGuidName�Ĵ�С��
	*/
	int GetPanelFromReg();

	/**
	* ��m_hFileTun����IOCTRL���룬�����ȡ�汾��Ϣ��
	*/
	std::wstring GetTapVersion();

	/**
	* ��m_hFileTun����IOCTRL���룬�����ȡMTU��Ϣ��
	*/
	int GetTapMTU();

	/**
	* ��m_hFileTun����IOCTRL���룬����IP�����롣
	*/
	BOOL SetIpConfig(/*string pszName,*/IP_TYPE ip, IP_TYPE netMask);

	/**
	* ��m_hFileTun����TAP_WIN_IOCTL_CONFIG_DHCP_MASQ
	*/
	BOOL SetDhcpMasq(IP_TYPE ip, IP_TYPE netMask);

	/**
	* ��m_hFileTun����TAP_WIN_IOCTL_CONFIG_DHCP_SET_OPT������DNS
	*/
	BOOL SetDhcpDNS(/*string pszName,*/ IP_TYPE ip1, IP_TYPE ip2);

	/**
	* ��m_hFileTun����TAP_WIN_IOCTL_SET_MEDIA_STATUS���������ӡ�
	*/
	BOOL SetTapConnected(BOOL bConnect = TRUE);

	/**
	* ����������̺߳����б����á�������������дtun�豸���߳�ThreadWriteTun��Ȼ������ѭ��ֱ��m_bQuit�����á�
	*/
	void OnReadTun();

	void AsyncWrite(CAutoMem * pmem);

	/**
	* �޸�TCPͷ�е�����Ķγ���ѡ���������Ϊm_TcpMss��
	*/
	void mss_fixup_ipv4(BYTE *buf, int nBuflen, int maxmss);

private:
	DefaultIpinfo m_defaultIP;
	std::atomic<BOOL> m_bQuit{FALSE};
	BOOL m_bIsReady;
	BOOL m_IsInitSucess;
	int  m_TcpMss;
	CMemList m_memListWriteTun;      //< �Ŷ�д��TUN�����ݷ����

	std::vector<std::string> m_Dns;
	std::vector<std::wstring> m_vTapGuids;
	std::list<IP_TYPE> m_mask;
	std::map<IP_TYPE, IP_TYPE> m_RouteTable;

	IP_TYPE m_TunEthIP;             //< �ڵ��·���OpenVPN����IP������Ҫ��������ʼ��TUN�豸��
	IP_TYPE m_TunEthNextHop;           //< �ڵ��·����������루���ɣ������·�ɱ��ʱ���ܸо����ֵ�������أ���
	IP_TYPE m_TunEthDNS1;           //< �ڵ��·���DNS��ַ1��
	IP_TYPE m_TunEthDNS2;           //< �ڵ��·���DNS��ַ2��

	BOOL m_bDefGetWayClient;        //< �Ƿ����·��,�����������������
	string  m_strServerIP;

	//std::map<IP_TYPE, IP_TYPE> m_DnsSendServer;
	std::map<std::wstring, std::wstring> m_mapGuidName;

	ITunDataRead *m_pReadInterface; //< ���ص���ͨ��������ȡ������ת����ȥ��
	std::wstring m_strTunDevName;   //< ʹ��OpenFile��Tun�豸ʱָ�����豸������"\\\\.\\Global\\{4DD758AE-852B-4F24-B728-D6A734B6C173}.tap"�����ֻ�ڴ򿪵�ʱ���õ�һ�¡�
	HANDLE m_hFileTun;              //< Tun�豸�����
	DWORD m_nTapIndex;				//< Tun�豸��Ӧ�������ӿڣ����硰��������2����������
	HANDLE m_hEventClientCreate;    //< �����ͻ�����ɵ��¼�
	HANDLE m_hIOCP;
	std::thread				 m_createthread;
	std::vector<std::thread> read_workers;     // ��ȡ���ݹ����߳�
	std::vector<TapAsyncContext*> m_asyncIocontext;

	std::vector<std::thread> write_workers;     // д��tap�������ݹ����߳�

};

