#pragma once
#include "SessioId.h"

class Socks5Session : public std::enable_shared_from_this<Socks5Session>
{
public:

	// 添加数据接收回调类型
	using DataCallback = std::function<void(const uint8_t* data, size_t size)>;
	// 代理服务器配置
	struct ProxyConfig {
		boost::asio::ip::tcp::endpoint proxy_endpoint; // 代理服务器地址（IP+端口）
		std::string auth_username;                     // 认证用户名（可选）
		std::string auth_password;                     // 认证密码（可选）
	};

	// 目标终端描述
	struct TargetEndpoint {
		boost::asio::ip::address_v4 address;  // 目标服务器IP地址
		uint16_t port;                     // 目标服务器端口
	};

	Socks5Session(
		boost::asio::io_context& io,
		SessionID id,
		const ProxyConfig& proxy_config,
		const TargetEndpoint& target,
		DataCallback callback  // 新增回调参数
	);
	~Socks5Session();
	// 数据转发接口
	void forward_data(const uint8_t* data, size_t size);
	void start();
private:
	void async_connect_proxy();
	// 代理连接成功后的处理
	void handle_proxy_connected();

	// 读取握手响应
	void async_read_handshake_response();

	//发送密码认证请求
	void send_auth();

	//读取密码认证请求
	void async_read_auth_response();

	// 发送连接请求
	void send_connect_request();

	// 读取连接响应
	void async_read_connect_response();

	std::vector<uint8_t> build_syn_ack(
		uint32_t client_ip,      // 客户端IP（网络字节序）
		uint32_t server_ip,      // 服务器IP（网络字节序）
		uint16_t client_port,    // 客户端端口（主机字节序）
		uint16_t server_port,    // 服务器端口（主机字节序）
		uint32_t client_isn,     // 客户端的初始序列号
		uint32_t server_isn      // 服务器的初始序列号
	);

	// 连接建立成功后的处理
	void on_connection_established();

	// 启动异步写操作
	void start_async_write();

	// 启动异步读操作
	void start_async_read();

private:
	// 核心成员定义
	boost::asio::io_context& io_context_;
	boost::asio::ip::tcp::socket proxy_socket_;  // 与代理服务器的连接
	ProxyConfig proxy_config_;                   // 代理配置信息
	TargetEndpoint target_;                      // 目标服务器信息
	std::string target_address_str_;             // 目标地址字符串形式（用于SOCKS5请求）
	DataCallback data_callback_;          // 数据接收回调
	std::queue<std::vector<uint8_t>> send_queue_;  // 发送队列
	std::vector<uint8_t> recv_buffer_;    // 接收缓冲区



										  // 解析器用于DNS查询（如果需要）
	boost::asio::ip::tcp::resolver resolver_;


	// 协议处理状态
	enum class State {
		ConnectingProxy,
		HandshakeSent,
		AuthSent,
		RequestSent,
		Established
	} state_ = State::ConnectingProxy;

	// 工具函数：异步写数据
	template <typename Handler>
	void async_write_packet(const std::vector<uint8_t>& data, Handler handler) {
		boost::asio::async_write(
			proxy_socket_,
			boost::asio::buffer(data.data(),data.size()),
			handler);
	}

	// 工具函数：异步读数据
	template <typename Handler>
	void async_read_packet(size_t expect_size, Handler handler) {
		read_buffer_.resize(expect_size);
		boost::asio::async_read(
			proxy_socket_,
			boost::asio::buffer(read_buffer_.data(),expect_size),
			handler);
	}

	// 错误处理
	void handle_error(const std::string& msg, boost::system::error_code ec = {});

	// 接收缓冲区
	std::vector<uint8_t> read_buffer_;
	size_t expected_response_size_ = 0;

	SessionID id_;
};

