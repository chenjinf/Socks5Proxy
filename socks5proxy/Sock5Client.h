#pragma once
#include <string>
#include "ITunDataRead.h"
#include "XyzTun.h"
#include <time.h>
#include "util/AutoLock.h"
#include "MemList.h"
#include <thread>
#include "SessioId.h"
#include <unordered_map>
#include "Socks5Session.h"

typedef struct tagTRAFFIC_STATICS
{
	time_t m_timeStart;
	LONGLONG m_llDown;
	LONGLONG m_llUp;
	LONGLONG m_llLastSend;
	LONGLONG m_llLastRecv;
}TRAFFIC_STATICS;


/**
* \brief “每连接”统计，每次重连都会重置。
*/
class StaticsticsPerConnection
{
public:
	StaticsticsPerConnection()
		:isConnected(FALSE)
		, ConnectStart(0)
		, ConnectEnd(0)
		, llUp(0)
		, llDown(0)
	{
	}

	~StaticsticsPerConnection() {}

	void reset()
	{
		isConnected = FALSE;
		ConnectStart = 0;
		ConnectEnd = 0;
		llUp = 0;
		llDown = 0;
	}
public:
	BOOL isConnected;
	time_t ConnectStart;
	time_t ConnectEnd;
	LONGLONG llUp;
	LONGLONG llDown;
};

/**
* SOCKS%客户端，所有通过隧道的数据都将使用它发送到节点。
* 使用方法大概按照如下步骤，具体详情见函数：

*
* 拥有的线程：

*/

class CSock5Client : public ITunDataRead
{
public:
	CSock5Client(boost::asio::io_context& io);
	~CSock5Client();
public:
	/**
	* ITunDataRead的实现。
	*/
	virtual void OnReadTun(BYTE *buf, int len);
public:
	/**
	* 设置登录用户名，密码，服务器地址（IP地址），服务器端口。
	*/
	void SetLoginParam(const string& pszName, const string& pszPass, const string& pszServer, USHORT port);

	/**
	* 关联一个tun对象
	*/
	void SetTun(IXyzTun* pTun);

	/**
	* 读取流量信息
	*/
	void GetTraffic(TRAFFIC_STATICS& traffic) { traffic = m_statics; }

	/**
	* 退出。在这里会等待工作线程的结束。
	*/
	void Quit();

	void ForDataTransfer();

	void OnDataTransfer();

	void handle_tcp_packet(const uint8_t* data, size_t size);
public:
	static std::mutex session_map_mutex_;
	static std::unordered_map<SessionID, std::shared_ptr<Socks5Session>> session_map_;
private:
	boost::asio::io_context& io_;
	string m_strLoginName;         //< 登录节点时需要带上用户名。
	string m_strLoginPass;         //< 登录节点时需要带上密码。
	string m_strLoginServer;	    //< 服务器地址，可以是域名也可以是一个IP。
	IP_TYPE m_ipLoginIP;		    //< 解析后的服务器IP地址
	USHORT m_usLoginPort;		    //< 服务器端口。

	CMemList m_memListSend;         //< 将要发往节点服务器的数据放这里。
	TRAFFIC_STATICS m_statics;                        //< 用于统计:生命周期内的上下传流量。

	BOOL m_bQuit;            //< 是否退出。注意！仅能由Quit()设置它！否则会影响退出的判断！
	IXyzTun* m_pTunDev;      //< 隧道对象。
	CLock_CS m_tunSet;       //< 防止多线程环境下正在使用隧道指针时指针被设置为NULL。
	std::thread				 m_Datasendthread; //< 这个是数据发送线程
};

