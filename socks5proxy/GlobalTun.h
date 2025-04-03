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

// TAP设备异步操作上下文
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

// 分片块大小（通常为MTU - IP头 - 传输头）
constexpr uint16_t FRAG_BLOCK_SIZE = 1480;  // 1500(MTU) - 20(IP) - 20(TCP)

struct IpFragmentKey {
	uint32_t src_ip;
	uint32_t dst_ip;
	uint16_t identification;
	uint8_t protocol;

	bool operator==(const IpFragmentKey& other) const {
		return src_ip == other.src_ip &&
			dst_ip == other.dst_ip &&
			identification == other.identification &&
			protocol == other.protocol;
	}
};

namespace std {
	template<> struct hash<IpFragmentKey> {
		size_t operator()(const IpFragmentKey& k) const {
			return hash<uint32_t>()(k.src_ip) ^
				hash<uint32_t>()(k.dst_ip) ^
				(hash<uint16_t>()(k.identification) << 1) ^
				(hash<uint8_t>()(k.protocol) << 2);
		}
	};
}

struct FragmentData {
	std::map<uint16_t, std::vector<uint8_t>> blocks;
	std::vector<bool> received;  // 动态位图
	uint16_t total_length = 0;
	uint16_t received_bytes = 0;
	uint16_t max_block_idx = 0;  // 最大有效块索引
	std::chrono::steady_clock::time_point last_update;

	bool is_complete() const {
		if (total_length == 0) return false;
		for (uint16_t i = 0; i <= max_block_idx; ++i) {
			if (!received[i]) return false;
		}
		return received_bytes >= total_length;
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
	* 设置最大报文段长度选项
	*/
	virtual void SetTcpMss(int nMss) { m_TcpMss = nMss; }
	virtual BOOL IsReady() { return m_bIsReady; }
	virtual BOOL Write(void *buf, int Packet_len);

	/**
	* 关闭tun设备句柄，并从路由表中将和他有关的项全部删除。
	*/
	virtual void Close();
protected:

	void DoCreateClient();
	void WorkerThread();
	void DoWriteTun();
	void OnWriteTun();

private:
	// 初始化异步读取操作
	void StartAsyncRead(TapAsyncContext* ctx);
	/**
	* 处理从tun中读取的数据，处理后使用ITunDataRead接口发往服务器。
	*/
	bool ProcessDataFromTun(void *buf, UINT dwRead);


	void StartFragmentCleanupThread();

	bool HandleIpFragment(struct openvpn_iphdr* ip, UINT dwRead);

	/**
	* 初始化。
	*/
	void Init();
	/**
	* 打开tun设备，为他配置ip、掩码、DNS、DHCP。
	*/
	BOOL OpenTun(IP_TYPE ipLocal, IP_TYPE ipMask, IP_TYPE ipDns1, IP_TYPE ipDns2);

	/**
	* 在注册表中寻找"ComponentId" = "tap0901"的设备，并保存它的"NetCfgInstanceId"(GUID值)到m_vTapGuids。
	* \return 返回m_vTapGuids的大小。
	*/
	int GetTapFromReg();

	/**
	* 创建NetworkInterface实例ID和名字的映射，保存到m_mapGuidName。
	* \return 返回m_mapGuidName的大小。
	*/
	int GetPanelFromReg();

	/**
	* 向m_hFileTun发送IOCTRL代码，请求获取版本信息。
	*/
	std::wstring GetTapVersion();

	/**
	* 向m_hFileTun发送IOCTRL代码，请求获取MTU信息。
	*/
	int GetTapMTU();

	/**
	* 向m_hFileTun发送IOCTRL代码，设置IP和掩码。
	*/
	BOOL SetIpConfig(/*string pszName,*/IP_TYPE ip, IP_TYPE netMask);

	/**
	* 向m_hFileTun发送TAP_WIN_IOCTL_CONFIG_DHCP_MASQ
	*/
	BOOL SetDhcpMasq(IP_TYPE ip, IP_TYPE netMask);

	/**
	* 向m_hFileTun发送TAP_WIN_IOCTL_CONFIG_DHCP_SET_OPT，设置DNS
	*/
	BOOL SetDhcpDNS(/*string pszName,*/ IP_TYPE ip1, IP_TYPE ip2);

	/**
	* 向m_hFileTun发送TAP_WIN_IOCTL_SET_MEDIA_STATUS，启动连接。
	*/
	BOOL SetTapConnected(BOOL bConnect = TRUE);

	/**
	* 这个函数在线程函数中被调用。它将创建两个写tun设备的线程ThreadWriteTun，然后进入读循环直到m_bQuit被设置。
	*/
	void OnReadTun();

	void AsyncWrite(CAutoMem * pmem);

	/**
	* 修改TCP头中的最大报文段长度选项，将它设置为m_TcpMss。
	*/
	void mss_fixup_ipv4(BYTE *buf, int nBuflen, int maxmss);

private:

	std::unordered_map<IpFragmentKey, FragmentData> fragment_cache;
	const size_t MAX_CACHE_SIZE = 100 * 1024 * 1024;  // 最大缓存100MB
	size_t current_cache_size = 0;
	DefaultIpinfo m_defaultIP;
	std::atomic<BOOL> m_bQuit{FALSE};
	BOOL m_bIsReady;
	BOOL m_IsInitSucess;
	int  m_TcpMss;
	CMemList m_memListWriteTun;      //< 排队写入TUN的数据放这里。

	std::vector<std::string> m_Dns;
	std::vector<std::wstring> m_vTapGuids;
	std::list<IP_TYPE> m_mask;
	std::map<IP_TYPE, IP_TYPE> m_RouteTable;

	IP_TYPE m_TunEthIP;             //< 节点下发的OpenVPN内网IP，我们要用它来初始化TUN设备。
	IP_TYPE m_TunEthNextHop;           //< 节点下发的内网掩码（存疑！在添加路由表的时候总感觉这个值更像网关）。
	IP_TYPE m_TunEthDNS1;           //< 节点下发的DNS地址1。
	IP_TYPE m_TunEthDNS2;           //< 节点下发的DNS地址2。

	BOOL m_bDefGetWayClient;        //< 是否添加路由,让网络流量走向这里。
	string  m_strServerIP;

	//std::map<IP_TYPE, IP_TYPE> m_DnsSendServer;
	std::map<std::wstring, std::wstring> m_mapGuidName;

	ITunDataRead *m_pReadInterface; //< 读回调，通过它将读取的数据转发出去。
	std::wstring m_strTunDevName;   //< 使用OpenFile打开Tun设备时指定的设备名，如"\\\\.\\Global\\{4DD758AE-852B-4F24-B728-D6A734B6C173}.tap"。这个只在打开的时候用到一下。
	HANDLE m_hFileTun;              //< Tun设备句柄。
	DWORD m_nTapIndex;				//< Tun设备对应的网卡接口（例如“本地连接2”）索引。
	HANDLE m_hEventClientCreate;    //< 创建客户端完成的事件
	HANDLE m_hIOCP;
	std::thread				 m_createthread;
	std::vector<std::thread> read_workers;     // 读取数据工作线程
	std::vector<TapAsyncContext*> m_asyncIocontext;

	std::vector<std::thread> write_workers;     // 写入tap网卡数据工作线程

};

