#include "stdafx.h"
#include "Socks5Session.h"
#include "DatapacketDefine.h"
#include "proto.h"
#include "Sock5Client.h"
#include <random>
Socks5Session::Socks5Session(boost::asio::io_context& io, SessionID id, const ProxyConfig& proxy_config, const TargetEndpoint& target, DataCallback callback /* �����ص����� */)
	:io_context_(io),
	id_(id),
	proxy_socket_(io),
	proxy_config_(proxy_config),
	target_(target),
	resolver_(io),
	data_callback_(callback)  // �洢�ص�
{
	target_address_str_ = target.address.to_string();
	// ��������ĳ�ʼ���к�
	/*std::random_device rd;
	std::mt19937 gen(rd());
	std::uniform_int_distribution<uint32_t> dis(0, UINT32_MAX);
	id_.server_seq = dis(gen);*/
}

Socks5Session::~Socks5Session()
{
}

void hexdump(shared_ptr<std::vector<uint8_t>> packet) {
	const size_t bytes_per_line = 16;
	size_t address = 0;
	std::vector<uint8_t> packetdata = *packet.get();
	for (size_t i = 0; i < packetdata.size(); i += bytes_per_line) {
		// ��ӡ��ַ
		std::cout << std::hex << std::setw(8) << std::setfill('0')
			<< address << "  ";

		// ��ӡʮ������
		for (size_t j = 0; j < bytes_per_line; ++j) {
			if (i + j < packetdata.size()) {
				std::cout << std::hex << std::setw(2) << std::setfill('0')
					<< static_cast<int>(static_cast<unsigned char>(packetdata[i + j])) << " ";
			}
			else {
				std::cout << "   "; // ����հ�
			}
			if (j == 7) std::cout << " "; // �ָ�ÿ8�ֽ�
		}

		std::cout << " ";

		// ��ӡASCII�ַ����ɴ�ӡ�ģ�
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
	// �����ͻ��˷��͵� TCP �������� data �������� IP/TCP ͷ��
	const openvpn_iphdr* ip = reinterpret_cast<const openvpn_iphdr*>(data);
	const openvpn_tcphdr* tcp = reinterpret_cast<const openvpn_tcphdr*>(data + sizeof(openvpn_iphdr));

	// ���� packet �������� IP ���ݰ�
	const uint8_t* ip_header = data;
	size_t ip_header_len = (ip_header[0] & 0x0F) * 4;  // IPv4 ͷ����

	const uint8_t* tcp_header = data + ip_header_len;
	size_t tcp_header_len = ((tcp_header[12] & 0xF0) >> 4) * 4;  // TCP ͷ����

	const uint8_t* app_data = tcp_header + tcp_header_len;  // Ӧ��������ʼλ��
	size_t app_data_size = size - ip_header_len - tcp_header_len;  // Ӧ�����ݴ�С
	//if (app_data_size <= 0)
	//{
	//	return;
	//}
	//auto getdata = std::make_shared<std::vector<uint8_t>>();
	//getdata->insert(getdata->begin(), app_data, app_data + app_data_size);
	////hexdump(getdata);

	//// ���¿ͻ������кź�ȷ�Ϻ�
	//id_.client_seq = ntohl(tcp->seq) + app_data_size; // ��ȷ����
	//id_.client_ack = ntohl(tcp->ack_seq);
	//
	//// �����ݼ��뷢�Ͷ���
	//bool write_in_progress = !send_queue_.empty();
	//send_queue_.emplace(app_data, app_data + app_data_size);

	//if (!write_in_progress) {
	//	start_async_write();
	//}

	bool is_pure_ack = (app_data_size == 0) && (tcp->flags & OPENVPN_TCPH_ACK_MASK);

	if (app_data_size > 0 || is_pure_ack) {
		// �������к��߼�����������ACK��
		if (tcp->flags & OPENVPN_TCPH_SYN_MASK) {
			id_.client_seq = ntohl(tcp->seq) + 1; // SYNռһ�����
		}
		else {
			id_.client_seq = ntohl(tcp->seq) + app_data_size;
		}
		id_.client_ack = ntohl(tcp->ack_seq);

		// ת������TCP�������ACK��
		auto packet = std::make_shared<std::vector<uint8_t>>(data, data + size);
		bool write_in_progress = !send_queue_.empty();
		send_queue_.emplace(packet->begin(),packet->end());

		if (!write_in_progress) {
			start_async_write();
		}
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
	// ���� SOCKS5 ��������
	std::vector<uint8_t> handshake_packet;
	handshake_packet = {
		0x05, // SOCKS�汾
		0x01, // ֧�ֵ���֤��������
		0x02  // ����2���û���/������֤
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
		2, // Ԥ�ڶ�ȡ2�ֽ�
		[self = shared_from_this()](boost::system::error_code ec, size_t) {
		if (!ec) {
			// ��֤��Ӧ���汾5 + ѡ��ķ���
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
	// ���� SOCKS5 ��������
	std::vector<uint8_t> handshake_packet;
	handshake_packet = {
		0x01, // // ��Э�̰汾
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
		2, // Ԥ�ڶ�ȡ2�ֽ�
		[self = shared_from_this()](boost::system::error_code ec, size_t) {
		if (!ec) {
			// ��֤��֤���
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

	// ����SOCKS5 CONNECT����
	request_packet = {
		0x05,                      // SOCKS�汾
		0x01,                      // CONNECT����
		0x00,                      // �����ֶ�
		0x01                     // ��ַ���ͣ�0x01=ipv4��
	};
	// ���IP�Ͷ˿�
	
	auto bytes = target_.address.to_bytes();
	request_packet.insert(
		request_packet.end(),
		bytes.begin(),
		bytes.end());
	request_packet.push_back(static_cast<uint8_t>((target_.port >> 8) & 0xFF)); // �˿ڸ�λ
	request_packet.push_back(static_cast<uint8_t>(target_.port & 0xFF)); // �˿ڵ�λ
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
		4, // ��С��Ӧͷ����
	[self = shared_from_this()](boost::system::error_code ec, size_t) {
		if (!ec) {
			// ��֤������Ӧ
			if (self->read_buffer_[0] != 0x05 ||
				self->read_buffer_[1] != 0x00) {
				self->handle_error("Connection rejected");
				return;
			}

			// ����ʣ����Ӧ�����ݵ�ַ���ͣ�
			size_t addr_type_offset = 3;
			switch (self->read_buffer_[3]) {
			case 0x01: // IPv4 (4 bytes + 2 bytes port)
				self->expected_response_size_ = 4 + 2;
				break;
			case 0x03: // ���� (1 byte len + N bytes + 2 bytes port)
				self->expected_response_size_ = 1 + self->read_buffer_[4] + 2;
				break;
			case 0x04: // IPv6 (16 bytes + 2 bytes port)
				self->expected_response_size_ = 16 + 2;
				break;
			default:
				self->handle_error("Invalid address type");
				return;
			}

			// ������ȡʣ����Ӧ
			self->async_read_packet(
				self->expected_response_size_,
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

std::vector<boost::uint8_t> Socks5Session::build_syn_ack(
	uint32_t client_ip, /* �ͻ���IP�������ֽ��� */
	uint32_t server_ip, /* ������IP�������ֽ��� */
	uint16_t client_port, /* �ͻ��˶˿ڣ������ֽ��� */ 
	uint16_t server_port, /* �������˿ڣ������ֽ��� */ 
	uint32_t client_isn, /* �ͻ��˵ĳ�ʼ���к� */ 
	uint32_t server_isn /* �������ĳ�ʼ���к� */)
{

	// ========================
	// 1. ����TCPѡ�����ݣ����뵽4�ֽڣ�
	// ========================
	const uint8_t tcp_options[] = {
		0x02, 0x04, 0x05, 0xB4,    // MSSѡ�1460 (0x05B4)
		0x01, 0x01,           // NOP���ʹ�ܳ���8�ֽ�
		0x04, 0x02, 0x01,               // SACK_PERMѡ��
		0x03, 0x03, 0x0A          // ������������1024 (2^10)
	};
	const int options_len = sizeof(tcp_options); // 12�ֽ�

	// Ԥ�������ݰ��ڴ棨IPͷ + TCPͷ + ѡ�
	std::vector<uint8_t> packet(sizeof(openvpn_iphdr) + sizeof(openvpn_tcphdr) + options_len);
	// ����IPͷ��
	openvpn_iphdr* iph = reinterpret_cast<openvpn_iphdr*>(packet.data());
	memset(iph, 0, sizeof(openvpn_iphdr)); // ����
	iph->version_len = 0x45;       // IPv4 + 5 words header
	iph->tos = 0;
	iph->tot_len = htons(sizeof(openvpn_iphdr) + sizeof(openvpn_tcphdr) + options_len);
	iph->id = 0;       // �����ʶ��
	iph->frag_off = htons(0x4000); // Don't fragment
	iph->ttl = 64;
	iph->protocol = IPPROTO_TCP;
	iph->check = 0;             // �������������
	iph->saddr = server_ip;
	iph->daddr = client_ip;

	// ����TCPͷ��
	openvpn_tcphdr* tcph = reinterpret_cast<openvpn_tcphdr*>(packet.data() + sizeof(openvpn_iphdr));
	tcph->source = htons(server_port);
	tcph->dest = htons(client_port);
	tcph->seq = htonl(server_isn);
	tcph->ack_seq = htonl(client_isn + 1); // SYN����seq+1
	// ͷ�����ȼ��㣨����ѡ�
	const uint8_t tcp_header_len = (sizeof(openvpn_tcphdr) + options_len) / 4;
	tcph->doff_res = tcp_header_len << 4;  // ����ƫ���ֶ�
	tcph->flags = OPENVPN_TCPH_SYN_MASK|OPENVPN_TCPH_ACK_MASK; // ����ƫ��5 words + SYN+ACK��־
	tcph->window = htons(42340);
	tcph->check = 0;            // �������������
	tcph->urg_ptr = 0;

	// ����IPУ���
	iph->check = calculate_checksum(reinterpret_cast<uint8_t*>(iph), sizeof(openvpn_iphdr));

	// ���TCPѡ��
	uint8_t* options_ptr = reinterpret_cast<uint8_t*>(tcph) + sizeof(openvpn_tcphdr);
	std::memcpy(options_ptr, tcp_options, options_len);

	// ����TCPУ��ͣ�����αͷ����
	uint16_t tcp_len = sizeof(openvpn_tcphdr) + options_len;
	tcph->check = tcp_checksum(
		server_ip,
		client_ip,
		reinterpret_cast<uint8_t*>(tcph),
		tcp_len
	);

	return packet;
}


void Socks5Session::on_connection_established()
{
	// �˴�Ӧ�����ϲ�ص�����ʼ����ת��
	//std::cout << "SOCKS5 tunnel established to "
		//<< target_address_str_ << ":" << target_.port << "\n";

		// ����SYN-ACK��
	std::vector<uint8_t> syn_ack_packet = build_syn_ack(
		htonl(boost::asio::ip::address_v4(id_.src_ip.v4).to_uint()),
		htonl(boost::asio::ip::address_v4(id_.dst_ip.v4).to_uint()),
		id_.src_port,
		id_.dst_port,
		id_.client_seq,
		id_.server_seq
	);

	// ����SYN-ACK���ͻ���
	if (data_callback_) {
		data_callback_(syn_ack_packet.data(), syn_ack_packet.size());
	}

	// ���·��������кţ�SYNռ��1����ţ�
	id_.server_seq += 1;



	// ����˫���첽��д
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
	recv_buffer_.resize(2048);  // 2KB ������
	proxy_socket_.async_receive(
		boost::asio::buffer(recv_buffer_),
		[self = shared_from_this()](boost::system::error_code ec, size_t read) {
		if (!ec) {

			// �ڶ�ȡ�����ݺ�������к�
			self->id_.server_seq += read; // ���������͵����ݳ���
			self->id_.client_ack = self->id_.client_seq; // �ͻ��˵�ȷ�Ϻ�ӦΪclient_seq

														 // ���췵�ظ��ͻ��˵� TCP �����ؼ�����̬���� SEQ/ACK��
			std::vector<uint8_t> packet = build_response_packet(
				boost::asio::ip::address_v4(self->id_.src_ip.v4), self->id_.src_port,
				boost::asio::ip::address_v4(self->id_.dst_ip.v4), self->id_.dst_port,
				self->recv_buffer_.data(), read,
				self->id_.server_seq,  // SEQ ʹ�÷������ķ������к�
				self->id_.client_seq   // ACK ʹ�ÿͻ��˵ķ������к�
			);

			// ������ͨ���ص�����
			if (self->data_callback_) {
				self->data_callback_(packet.data(), packet.size());
			}

			//self->accumulated_data_->insert(self->accumulated_data_->end(), self->recv_buffer_.begin(), self->recv_buffer_.begin() + read);
			// ������ȡ
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
	CSock5Client::session_map_.erase(id_); // ��map�Ƴ�
}

