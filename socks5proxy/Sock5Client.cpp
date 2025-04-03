#include "stdafx.h"
#include "Sock5Client.h"
#include "proto.h"
#include "DatapacketDefine.h"

std::unordered_map<SessionID, std::shared_ptr<Socks5Session>> CSock5Client::session_map_;
std::mutex CSock5Client::session_map_mutex_;

CSock5Client::CSock5Client(boost::asio::io_context& io)
	:io_(io)
{
}


CSock5Client::~CSock5Client()
{
}

void CSock5Client::OnReadTun(BYTE *buf, int len)
{
	m_statics.m_llUp += len;
	if (len < sizeof(openvpn_iphdr))
	{
		printf("[discard](1)OnReadTun: len < sizeof(openvpn_iphdr)\n");
		return;
	}
	// 下面是丢弃非IPv4包和丢弃ARP包的操作。
	openvpn_iphdr *pIpPack = (openvpn_iphdr*)buf;
	int iIPVer = OPENVPN_IPH_GET_VER(pIpPack->version_len);

	if (iIPVer != 4)
	{
		return;
	}
	if (m_memListSend.size() < 1000)
	{
		CAutoMem *pMem = new CAutoMem(len);
		pMem->Write(buf, len);
		m_memListSend.push(pMem);
	}
}

void CSock5Client::SetLoginParam(const string& pszName, const string& pszPass, const string& pszServer, USHORT port)
{
	m_strLoginName = pszName;
	m_strLoginPass = pszPass;
	m_strLoginServer = pszServer;
	m_usLoginPort = port;
}

void CSock5Client::SetTun(IXyzTun* pTun)
{
	CAutoLock l(m_tunSet);
	m_pTunDev = pTun;
}

void CSock5Client::Quit()
{
	m_bQuit = TRUE;
	m_memListSend.abort();
	if (m_Datasendthread.joinable())
	{
		m_Datasendthread.join();
	}
}

void CSock5Client::ForDataTransfer()
{
	m_Datasendthread = std::thread(&CSock5Client::OnDataTransfer, this);
}

void CSock5Client::OnDataTransfer()
{
	while (!m_bQuit)
	{
		// 在下面这里无限等待合适吗？如需退出等待要设置m_memListSend.m_hEvent。
		// 当数据断开的时候，会不会在这里无限等待了？
		m_memListSend.wait_data(INFINITE);
		while (!m_bQuit)
		{
			CAutoMem *pMem = m_memListSend.pop();
			if (pMem == NULL)
			{
				break;
			}
			BYTE* buf = pMem->GetBuffer();
			int buflen = pMem->GetLen();
			const struct openvpn_iphdr *pip = (struct openvpn_iphdr *)buf;
			if (pip->protocol == OPENVPN_IPPROTO_TCP)
			{
				handle_tcp_packet(buf, buflen);
			}
			else if(pip->protocol == OPENVPN_IPPROTO_UDP)
			{
				//这里是以后处理UDP预留的处理
			}
		}
	}
}

void CSock5Client::handle_tcp_packet(const uint8_t* data, size_t size)
{
	const struct openvpn_iphdr *pip = (struct openvpn_iphdr *)data;
	int hlen = OPENVPN_IPH_GET_LEN(pip->version_len);
	struct openvpn_tcphdr *tc = (struct openvpn_tcphdr *)(data + hlen);
	// 构造 SessionID
	SessionID id;
	id.src_ip.v4 = boost::asio::ip::address_v4(ntohl(pip->saddr)).to_bytes();
	id.dst_ip.v4 = boost::asio::ip::address_v4(ntohl(pip->daddr)).to_bytes();
	id.src_port = ntohs(tc->source); // 转换为主机字节序
	id.dst_port = ntohs(tc->dest);
	id.protocol = IPPROTO_TCP;

	/*if (boost::asio::ip::make_address_v4(id.dst_ip.v4).to_string() == m_strLoginServer)
	{
		return;
	}*/
	std::cout << "handle_tcp_packet, src_ip:" << boost::asio::ip::make_address_v4(id.src_ip.v4).to_string() <<
		",port:" << id.src_port << ",dst_ip:" << boost::asio::ip::make_address_v4(id.dst_ip.v4).to_string() <<
		",port:" << id.dst_port << "packet len:" << size <<"\n";
	// 初始化序列号（如果是 SYN 包）
	if (tc->flags & OPENVPN_TCPH_SYN_MASK) {
		id.client_seq = ntohl(tc->seq) + 1; // SYN 占用 1 个序号
		id.server_seq = generate_initial_seq(); // 随机生成初始序列号
	}
	// 访问时加锁
	std::lock_guard<std::mutex> lock(session_map_mutex_);
	auto it = session_map_.find(id);
	if (it == session_map_.end()) {
		// 创建代理配置
		Socks5Session::ProxyConfig proxy_config;
		proxy_config.proxy_endpoint = boost::asio::ip::tcp::endpoint(
			boost::asio::ip::make_address_v4(m_strLoginServer), m_usLoginPort);
		proxy_config.auth_username = m_strLoginName;
		proxy_config.auth_password = m_strLoginPass;
		// 目标服务器配置
		Socks5Session::TargetEndpoint target{
			target.address = boost::asio::ip::make_address_v4(id.dst_ip.v4),
			target.port = id.dst_port
		};
		auto session = std::make_shared<Socks5Session>(
			io_,
			id,
			proxy_config,
			target,
			[this](const uint8_t* data, size_t size) {
			//这里是数据回调处理	
			m_statics.m_llDown += size;
			m_pTunDev->Write((void*)data, size);
		});
		session->start();
		session_map_[id] = session;
	}
	session_map_[id]->forward_data(data, size);
}
