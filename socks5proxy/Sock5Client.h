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
* \brief ��ÿ���ӡ�ͳ�ƣ�ÿ�������������á�
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
* SOCKS%�ͻ��ˣ�����ͨ����������ݶ���ʹ�������͵��ڵ㡣
* ʹ�÷�����Ű������²��裬���������������

*
* ӵ�е��̣߳�

*/

class CSock5Client : public ITunDataRead
{
public:
	CSock5Client(boost::asio::io_context& io);
	~CSock5Client();
public:
	/**
	* ITunDataRead��ʵ�֡�
	*/
	virtual void OnReadTun(BYTE *buf, int len);
public:
	/**
	* ���õ�¼�û��������룬��������ַ��IP��ַ�����������˿ڡ�
	*/
	void SetLoginParam(const string& pszName, const string& pszPass, const string& pszServer, USHORT port);

	/**
	* ����һ��tun����
	*/
	void SetTun(IXyzTun* pTun);

	/**
	* ��ȡ������Ϣ
	*/
	void GetTraffic(TRAFFIC_STATICS& traffic) { traffic = m_statics; }

	/**
	* �˳����������ȴ������̵߳Ľ�����
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
	string m_strLoginName;         //< ��¼�ڵ�ʱ��Ҫ�����û�����
	string m_strLoginPass;         //< ��¼�ڵ�ʱ��Ҫ�������롣
	string m_strLoginServer;	    //< ��������ַ������������Ҳ������һ��IP��
	IP_TYPE m_ipLoginIP;		    //< ������ķ�����IP��ַ
	USHORT m_usLoginPort;		    //< �������˿ڡ�

	CMemList m_memListSend;         //< ��Ҫ�����ڵ�����������ݷ����
	TRAFFIC_STATICS m_statics;                        //< ����ͳ��:���������ڵ����´�������

	BOOL m_bQuit;            //< �Ƿ��˳���ע�⣡������Quit()�������������Ӱ���˳����жϣ�
	IXyzTun* m_pTunDev;      //< �������
	CLock_CS m_tunSet;       //< ��ֹ���̻߳���������ʹ�����ָ��ʱָ�뱻����ΪNULL��
	std::thread				 m_Datasendthread; //< ��������ݷ����߳�
};

