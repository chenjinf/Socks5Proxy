#pragma once
#include <vector>
#include <cstdint>
#include <algorithm>
#include <random>
#include "proto.h"

// TCPαͷ��������У��ͼ��㣩
struct PseudoHeader {
	uint32_t src_ip;
	uint32_t dst_ip;
	uint8_t  reserved;
	uint8_t  protocol;
	uint16_t tcp_length;
};

inline bool IsLocalOrPrivateIP(uint32_t ip) {
	// ˽�е�ַ��Χ��10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16
	return ((ip & 0xFF000000) == 0x0A000000) ||    // 10.0.0.0/8
		((ip & 0xFFF00000) == 0xAC100000) ||   // 172.16.0.0/12
		((ip & 0xFFFF0000) == 0xC0A80000);     // 192.168.0.0/16
}

// ���������ʼ���к�
inline uint32_t generate_initial_seq() {
	static std::random_device rd;
	static std::mt19937 gen(rd());
	static std::uniform_int_distribution<uint32_t> dis(0, 0xFFFFFFFF);
	return dis(gen);
}

// ����16λУ���
inline uint16_t calculate_checksum(const void* data, size_t length, uint32_t initial = 0) {
	const uint16_t* ptr = static_cast<const uint16_t*>(data);
	uint32_t sum = initial;

	while (length > 1) {
		sum += *ptr++;
		length -= 2;
	}

	if (length > 0) {
		sum += *(reinterpret_cast<const uint8_t*>(ptr)) << 8; //��8λ
	}

	// �۵�32λ��16λ
	while (sum >> 16) {
		sum = (sum & 0xFFFF) + (sum >> 16);
	}

	return static_cast<uint16_t>(~sum);
}

inline std::vector<uint8_t> build_response_packet(
	const boost::asio::ip::address_v4& client_ip,
	uint16_t client_port,
	const boost::asio::ip::address_v4& server_ip,
	uint16_t server_port,
	const uint8_t* payload,
	size_t payload_len,
	uint32_t& server_seq,  // ���ô����Զ�̬�������к�
	uint32_t client_ack     // �ͻ��˵����ȷ�Ϻ�
) {
	std::vector<uint8_t> packet;

	// ====================== 1. ����IPͷ ======================
	openvpn_iphdr ip_hdr;
	ip_hdr.version_len = 0x45;         // IPv4��ͷ��20�ֽ�
	ip_hdr.tos = 0;
	ip_hdr.tot_len = htons(sizeof(openvpn_iphdr) + sizeof(openvpn_tcphdr) + payload_len);
	ip_hdr.id = htons(static_cast<uint16_t>(rand() % 0xFFFF));
	ip_hdr.frag_off = 0x4000; // Don't fragment
	ip_hdr.ttl = 128;
	ip_hdr.protocol = IPPROTO_TCP;
	ip_hdr.saddr = htonl(server_ip.to_uint()); // αװΪ������IP
	ip_hdr.daddr = htonl(client_ip.to_uint());
	ip_hdr.check = 0; // �����㣬������

						 // ====================== 2. ����TCPͷ ======================
	openvpn_tcphdr tcp_hdr;
	tcp_hdr.source = htons(server_port);
	tcp_hdr.dest = htons(client_port);
	tcp_hdr.seq = htonl(server_seq);    // ʹ�÷��������к�
	tcp_hdr.ack_seq = htonl(client_ack);    // �ͻ��˵����ȷ�Ϻ�
	tcp_hdr.doff_res = (sizeof(openvpn_tcphdr) / 4) << 4; // ����ƫ��5��20�ֽڣ�
	tcp_hdr.flags = OPENVPN_TCPH_ACK_MASK | OPENVPN_TCPH_PSH_MASK;   // ����ΪACK+PUSH���ݰ�
	tcp_hdr.window = htons(65535);      // ��󴰿�
	tcp_hdr.urg_ptr = 0;
	tcp_hdr.check = 0; // ������

						  // ====================== 3. ����У��� ======================
						  // ����IPͷ��У���
	ip_hdr.check = calculate_checksum(&ip_hdr, sizeof(openvpn_iphdr));

	// ����TCPУ��ͣ�����αͷ����
	PseudoHeader pseudo_hdr;
	pseudo_hdr.src_ip = ip_hdr.saddr;
	pseudo_hdr.dst_ip = ip_hdr.daddr;
	pseudo_hdr.reserved = 0;
	pseudo_hdr.protocol = IPPROTO_TCP;
	pseudo_hdr.tcp_length = htons(sizeof(openvpn_tcphdr) + payload_len);

	uint32_t tcp_sum = calculate_checksum(&pseudo_hdr, sizeof(PseudoHeader));
	tcp_sum = calculate_checksum(&tcp_hdr, sizeof(openvpn_tcphdr), tcp_sum);
	tcp_hdr.check = calculate_checksum(payload, payload_len, tcp_sum);

	// ====================== 4. ��װ�������ݰ� ======================
	packet.reserve(sizeof(openvpn_iphdr) + sizeof(openvpn_tcphdr) + payload_len);
	packet.insert(packet.end(), reinterpret_cast<uint8_t*>(&ip_hdr),
		reinterpret_cast<uint8_t*>(&ip_hdr) + sizeof(openvpn_iphdr));
	packet.insert(packet.end(), reinterpret_cast<uint8_t*>(&tcp_hdr),
		reinterpret_cast<uint8_t*>(&tcp_hdr) + sizeof(openvpn_tcphdr));
	packet.insert(packet.end(), payload, payload + payload_len);

	// ====================== 5. �������к� ======================
	server_seq += payload_len; // ��Ҫ�����·������������к�

	return packet;
}