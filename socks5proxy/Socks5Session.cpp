#include "stdafx.h"
#include "Socks5Session.h"
#include "DatapacketDefine.h"
#include "proto.h"
#include "Sock5Client.h"
Socks5Session::Socks5Session(boost::asio::io_context& io, SessionID id, const ProxyConfig& proxy_config, const TargetEndpoint& target, DataCallback callback /* 新增回调参数 */)
	:io_context_(io),
	id_(id),
	proxy_socket_(io),
	proxy_config_(proxy_config),
	target_(target),
	resolver_(io),
	data_callback_(callback)  // 存储回调
{
	target_address_str_ = target.address.to_string();
}

Socks5Session::~Socks5Session()
{
}

void hexdump(shared_ptr<std::vector<uint8_t>> packet) {
	const size_t bytes_per_line = 16;
	size_t address = 0;
	std::vector<uint8_t> packetdata = *packet.get();
	for (size_t i = 0; i < packetdata.size(); i += bytes_per_line) {
		// 打印地址
		std::cout << std::hex << std::setw(8) << std::setfill('0')
			<< address << "  ";

		// 打印十六进制
		for (size_t j = 0; j < bytes_per_line; ++j) {
			if (i + j < packetdata.size()) {
				std::cout << std::hex << std::setw(2) << std::setfill('0')
					<< static_cast<int>(static_cast<unsigned char>(packetdata[i + j])) << " ";
			}
			else {
				std::cout << "   "; // 对齐空白
			}
			if (j == 7) std::cout << " "; // 分隔每8字节
		}

		std::cout << " ";

		// 打印ASCII字符（可打印的）
		for (size_t j = 0; j < bytes_per_line; ++j) {
			if (i + j >= packetdata.size()) break;
			/*unsigned*/ char c = packetdata[i + j];
			std::cout << std::dec << std::setw(1) << std::setfill('0') << (('!' < c && c <= '~') ? c : '.');
		}
		std::cout << "\n";
		address += bytes_per_line;
	}
}

void Socks5Session::forward_data(const uint8_t* data, size_t size)
{
	// 解析客户端发送的 TCP 包（假设 data 包含完整 IP/TCP 头）
	const openvpn_iphdr* ip = reinterpret_cast<const openvpn_iphdr*>(data);
	const openvpn_tcphdr* tcp = reinterpret_cast<const openvpn_tcphdr*>(data + sizeof(openvpn_iphdr));

	

	// 假设 packet 是完整的 IP 数据包
	const uint8_t* ip_header = data;
	size_t ip_header_len = (ip_header[0] & 0x0F) * 4;  // IPv4 头长度

	const uint8_t* tcp_header = data + ip_header_len;
	size_t tcp_header_len = ((tcp_header[12] & 0xF0) >> 4) * 4;  // TCP 头长度

	const uint8_t* app_data = tcp_header + tcp_header_len;  // 应用数据起始位置
	size_t app_data_size = size - ip_header_len - tcp_header_len;  // 应用数据大小
	if (app_data_size <= 0)
	{
		return;
	}
	auto getdata = std::make_shared<std::vector<uint8_t>>();
	getdata->insert(getdata->begin(), app_data, app_data + app_data_size);
	//hexdump(getdata);

	// 更新客户端序列号和确认号
	id_.client_seq = ntohl(tcp->seq) + app_data_size; // 正确递增
	id_.client_ack = ntohl(tcp->ack_seq);
	
	// 将数据加入发送队列
	bool write_in_progress = !send_queue_.empty();
	send_queue_.emplace(app_data, app_data + app_data_size);

	if (!write_in_progress) {
		start_async_write();
	}
}

void Socks5Session::start()
{
	async_connect_proxy();
}

void Socks5Session::async_connect_proxy()
{
	proxy_socket_.async_connect(
		proxy_config_.proxy_endpoint,
		[self = shared_from_this()](boost::system::error_code ec) {
		if (!ec) {
			self->handle_proxy_connected();
		}
		else {
			self->handle_error("Connect to proxy failed", ec);
		}
	});
}

void Socks5Session::handle_proxy_connected()
{
	// 发送 SOCKS5 握手请求
	std::vector<uint8_t> handshake_packet;
	handshake_packet = {
		0x05, // SOCKS版本
		0x01, // 支持的认证方法数量
		0x02  // 方法2：用户名/密码认证
	};
	async_write_packet(
		handshake_packet,
		[self = shared_from_this()](boost::system::error_code ec, size_t) {
		if (!ec) {
			self->state_ = State::HandshakeSent;
			self->async_read_handshake_response();
		}
		else {
			self->handle_error("Send handshake failed", ec);
		}
	});
}




void Socks5Session::async_read_handshake_response()
{
	async_read_packet(
		2, // 预期读取2字节
		[self = shared_from_this()](boost::system::error_code ec, size_t) {
		if (!ec) {
			// 验证响应：版本5 + 选择的方法
			if (self->read_buffer_[0] == 0x05 &&
				self->read_buffer_[1] == 0x02) {
				self->send_auth();
			}
			else {
				self->handle_error("Unsupported auth method");
			}
		}
		else {
			self->handle_error("Read handshake response failed", ec);
		}
	});
}

void Socks5Session::send_auth()
{
	// 发送 SOCKS5 握手请求
	std::vector<uint8_t> handshake_packet;
	handshake_packet = {
		0x01, // // 子协商版本
		static_cast<uint8_t>(proxy_config_.auth_username.size())

	};
	handshake_packet.insert(handshake_packet.end(), proxy_config_.auth_username.begin(), proxy_config_.auth_username.end());
	handshake_packet.push_back(static_cast<uint8_t>(proxy_config_.auth_password.size()));
	handshake_packet.insert(handshake_packet.end(), proxy_config_.auth_password.begin(), proxy_config_.auth_password.end());
	async_write_packet(
		handshake_packet,
		[self = shared_from_this()](boost::system::error_code ec, size_t){
		if (!ec)
		{
			self->state_ = State::AuthSent;
			self->async_read_auth_response();
		}
		else {
			self->handle_error("Send handshake failed", ec);
		}
	});
}


void Socks5Session::async_read_auth_response()
{
	async_read_packet(
		2, // 预期读取2字节
		[self = shared_from_this()](boost::system::error_code ec, size_t) {
		if (!ec) {
			// 验证认证结果
			if (self->read_buffer_[1] == 0x00) {
				self->send_connect_request();
			}
			else {
				self->handle_error("Unsupported auth method");
			}
		}
		else {
			self->handle_error("Read handshake response failed", ec);
		}
	});
}

void Socks5Session::send_connect_request()
{
	std::vector<uint8_t> request_packet;

	// 构造SOCKS5 CONNECT请求
	request_packet = {
		0x05,                      // SOCKS版本
		0x01,                      // CONNECT命令
		0x00,                      // 保留字段
		0x01                     // 地址类型（0x01=ipv4）
	};
	// 添加IP和端口
	
	auto bytes = target_.address.to_bytes();
	request_packet.insert(
		request_packet.end(),
		bytes.begin(),
		bytes.end());
	request_packet.push_back(static_cast<uint8_t>((target_.port >> 8) & 0xFF)); // 端口高位
	request_packet.push_back(static_cast<uint8_t>(target_.port & 0xFF)); // 端口低位
	async_write_packet(
		request_packet,
		[self = shared_from_this()](boost::system::error_code ec, size_t) {
		if (!ec) {
			self->state_ = State::RequestSent;
			self->async_read_connect_response();
		}
		else {
			self->handle_error("Send connect request failed", ec);
		}
	});
}

void Socks5Session::async_read_connect_response()
{
	async_read_packet(
		4, // 最小响应头长度
		[self = shared_from_this()](boost::system::error_code ec, size_t) {
		if (!ec) {
			// 验证基础响应
			if (self->read_buffer_[0] != 0x05 ||
				self->read_buffer_[1] != 0x00) {
				self->handle_error("Connection rejected");
				return;
			}

			// 解析剩余响应（根据地址类型）
			size_t addr_type_offset = 3;
			switch (self->read_buffer_[3]) {
			case 0x01: // IPv4 (4 bytes + 2 bytes port)
				self->expected_response_size_ = 4 + 2;
				break;
			case 0x03: // 域名 (1 byte len + N bytes + 2 bytes port)
				self->expected_response_size_ = 1 + self->read_buffer_[4] + 2;
				break;
			case 0x04: // IPv6 (16 bytes + 2 bytes port)
				self->expected_response_size_ = 16 + 2;
				break;
			default:
				self->handle_error("Invalid address type");
				return;
			}

			// 继续读取剩余响应
			self->async_read_packet(
				self->expected_response_size_ - 4,
				[self](boost::system::error_code ec, size_t) {
				if (!ec) {
					self->state_ = State::Established;
					self->on_connection_established();
				}
				else {
					self->handle_error("Read connect response failed", ec);
				}
			});
		}
		else {
			self->handle_error("Read connect response header failed", ec);
		}
	});
}

void Socks5Session::on_connection_established()
{
	// 此处应触发上层回调，开始数据转发
	//std::cout << "SOCKS5 tunnel established to "
		//<< target_address_str_ << ":" << target_.port << "\n";

	// 启动双向异步读写
	start_async_write();
	start_async_read();
}

void Socks5Session::start_async_write()
{
	if (send_queue_.empty()) return;

	auto& buffer = send_queue_.front();
	boost::asio::async_write(
		proxy_socket_,
		boost::asio::buffer(buffer),
		[self = shared_from_this()](boost::system::error_code ec, size_t written) {
		if (!ec) {
			self->send_queue_.pop();
			if (!self->send_queue_.empty()) {
				self->start_async_write();
			}
		}
		else {
			self->handle_error("Async write failed", ec);
		}
	});
}

void Socks5Session::start_async_read()
{
	recv_buffer_.resize(2048);  // 2KB 缓冲区
	proxy_socket_.async_receive(
		boost::asio::buffer(recv_buffer_),
		[self = shared_from_this()](boost::system::error_code ec, size_t read) {
		if (!ec) {

			// 在读取到数据后更新序列号
			self->id_.server_seq += read; // 服务器发送的数据长度
			self->id_.client_ack = self->id_.client_seq; // 客户端的确认号应为client_seq

														 // 构造返回给客户端的 TCP 包（关键：动态设置 SEQ/ACK）
			std::vector<uint8_t> packet = build_response_packet(
				boost::asio::ip::address_v4(self->id_.src_ip.v4), self->id_.src_port,
				boost::asio::ip::address_v4(self->id_.dst_ip.v4), self->id_.dst_port,
				self->recv_buffer_.data(), read,
				self->id_.server_seq,  // SEQ 使用服务器的发送序列号
				self->id_.client_seq   // ACK 使用客户端的发送序列号
			);

			// 将数据通过回调传递
			if (self->data_callback_) {
				self->data_callback_(packet.data(), packet.size());
			}

			//self->accumulated_data_->insert(self->accumulated_data_->end(), self->recv_buffer_.begin(), self->recv_buffer_.begin() + read);
			// 继续读取
			self->start_async_read();
		}
		else if (ec != boost::asio::error::eof) {
			self->handle_error("Async read failed", ec);
		}
	});
}

void Socks5Session::handle_error(const std::string& msg, boost::system::error_code ec)
{
	std::cerr << "SOCKS5 Error [" << ec << "]: " << msg << "\n";
	proxy_socket_.close();
	std::lock_guard<std::mutex> lock(CSock5Client::session_map_mutex_);
	CSock5Client::session_map_.erase(id_); // 从map移除
}

