#pragma once
#include "SessioId.h"

class Socks5Session : public std::enable_shared_from_this<Socks5Session>
{
public:

	// ������ݽ��ջص�����
	using DataCallback = std::function<void(const uint8_t* data, size_t size)>;
	// �������������
	struct ProxyConfig {
		boost::asio::ip::tcp::endpoint proxy_endpoint; // �����������ַ��IP+�˿ڣ�
		std::string auth_username;                     // ��֤�û�������ѡ��
		std::string auth_password;                     // ��֤���루��ѡ��
	};

	// Ŀ���ն�����
	struct TargetEndpoint {
		boost::asio::ip::address_v4 address;  // Ŀ�������IP��ַ
		uint16_t port;                     // Ŀ��������˿�
	};

	Socks5Session(
		boost::asio::io_context& io,
		SessionID id,
		const ProxyConfig& proxy_config,
		const TargetEndpoint& target,
		DataCallback callback  // �����ص�����
	);
	~Socks5Session();
	// ����ת���ӿ�
	void forward_data(const uint8_t* data, size_t size);
	void start();
private:
	void async_connect_proxy();
	// �������ӳɹ���Ĵ���
	void handle_proxy_connected();

	// ��ȡ������Ӧ
	void async_read_handshake_response();

	//����������֤����
	void send_auth();

	//��ȡ������֤����
	void async_read_auth_response();

	// ������������
	void send_connect_request();

	// ��ȡ������Ӧ
	void async_read_connect_response();

	std::vector<uint8_t> build_syn_ack(
		uint32_t client_ip,      // �ͻ���IP�������ֽ���
		uint32_t server_ip,      // ������IP�������ֽ���
		uint16_t client_port,    // �ͻ��˶˿ڣ������ֽ���
		uint16_t server_port,    // �������˿ڣ������ֽ���
		uint32_t client_isn,     // �ͻ��˵ĳ�ʼ���к�
		uint32_t server_isn      // �������ĳ�ʼ���к�
	);

	// ���ӽ����ɹ���Ĵ���
	void on_connection_established();

	// �����첽д����
	void start_async_write();

	// �����첽������
	void start_async_read();

private:
	// ���ĳ�Ա����
	boost::asio::io_context& io_context_;
	boost::asio::ip::tcp::socket proxy_socket_;  // ����������������
	ProxyConfig proxy_config_;                   // ����������Ϣ
	TargetEndpoint target_;                      // Ŀ���������Ϣ
	std::string target_address_str_;             // Ŀ���ַ�ַ�����ʽ������SOCKS5����
	DataCallback data_callback_;          // ���ݽ��ջص�
	std::queue<std::vector<uint8_t>> send_queue_;  // ���Ͷ���
	std::vector<uint8_t> recv_buffer_;    // ���ջ�����



										  // ����������DNS��ѯ�������Ҫ��
	boost::asio::ip::tcp::resolver resolver_;


	// Э�鴦��״̬
	enum class State {
		ConnectingProxy,
		HandshakeSent,
		AuthSent,
		RequestSent,
		Established
	} state_ = State::ConnectingProxy;

	// ���ߺ������첽д����
	template <typename Handler>
	void async_write_packet(const std::vector<uint8_t>& data, Handler handler) {
		boost::asio::async_write(
			proxy_socket_,
			boost::asio::buffer(data.data(),data.size()),
			handler);
	}

	// ���ߺ������첽������
	template <typename Handler>
	void async_read_packet(size_t expect_size, Handler handler) {
		read_buffer_.resize(expect_size);
		boost::asio::async_read(
			proxy_socket_,
			boost::asio::buffer(read_buffer_.data(),expect_size),
			handler);
	}

	// ������
	void handle_error(const std::string& msg, boost::system::error_code ec = {});

	// ���ջ�����
	std::vector<uint8_t> read_buffer_;
	size_t expected_response_size_ = 0;

	SessionID id_;
};

