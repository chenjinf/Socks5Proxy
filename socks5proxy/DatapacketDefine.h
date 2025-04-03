#pragma once
#include <vector>
#include <cstdint>
#include <algorithm>
#include <random>
#include "proto.h"

// TCP伪头部（用于校验和计算）
struct PseudoHeader {
	uint32_t src_ip;
	uint32_t dst_ip;
	uint8_t  reserved;
	uint8_t  protocol;
	uint16_t tcp_length;
};

inline bool IsLocalOrPrivateIP(uint32_t ip) {
	// 私有地址范围：10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16
	return ((ip & 0xFF000000) == 0x0A000000) ||    // 10.0.0.0/8
		((ip & 0xFFF00000) == 0xAC100000) ||   // 172.16.0.0/12
		((ip & 0xFFFF0000) == 0xC0A80000);     // 192.168.0.0/16
}

// 生成随机初始序列号
inline uint32_t generate_initial_seq() {
	static std::random_device rd;
	static std::mt19937 gen(rd());
	static std::uniform_int_distribution<uint32_t> dis(0, 0xFFFFFFFF);
	return dis(gen);
}

// 计算16位校验和
inline uint16_t calculate_checksum(const void* data, size_t length, uint32_t initial = 0) {
	const uint16_t* ptr = static_cast<const uint16_t*>(data);
	uint32_t sum = initial;

	while (length > 1) {
		sum += *ptr++;
		length -= 2;
	}

	if (length > 0) {
		sum += *(reinterpret_cast<const uint8_t*>(ptr)) << 8; //高8位
	}

	// 折叠32位到16位
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
	uint32_t& server_seq,  // 引用传递以动态更新序列号
	uint32_t client_ack     // 客户端的最后确认号
) {
	std::vector<uint8_t> packet;

	// ====================== 1. 构造IP头 ======================
	openvpn_iphdr ip_hdr;
	ip_hdr.version_len = 0x45;         // IPv4，头长20字节
	ip_hdr.tos = 0;
	ip_hdr.tot_len = htons(sizeof(openvpn_iphdr) + sizeof(openvpn_tcphdr) + payload_len);
	ip_hdr.id = htons(static_cast<uint16_t>(rand() % 0xFFFF));
	ip_hdr.frag_off = 0x4000; // Don't fragment
	ip_hdr.ttl = 128;
	ip_hdr.protocol = IPPROTO_TCP;
	ip_hdr.saddr = htonl(server_ip.to_uint()); // 伪装为服务器IP
	ip_hdr.daddr = htonl(client_ip.to_uint());
	ip_hdr.check = 0; // 先置零，最后计算

						 // ====================== 2. 构造TCP头 ======================
	openvpn_tcphdr tcp_hdr;
	tcp_hdr.source = htons(server_port);
	tcp_hdr.dest = htons(client_port);
	tcp_hdr.seq = htonl(server_seq);    // 使用服务器序列号
	tcp_hdr.ack_seq = htonl(client_ack);    // 客户端的最后确认号
	tcp_hdr.doff_res = (sizeof(openvpn_tcphdr) / 4) << 4; // 数据偏移5（20字节）
	tcp_hdr.flags = OPENVPN_TCPH_ACK_MASK | OPENVPN_TCPH_PSH_MASK;   // 假设为ACK+PUSH数据包
	tcp_hdr.window = htons(65535);      // 最大窗口
	tcp_hdr.urg_ptr = 0;
	tcp_hdr.check = 0; // 先置零

						  // ====================== 3. 计算校验和 ======================
						  // 计算IP头部校验和
	ip_hdr.check = calculate_checksum(&ip_hdr, sizeof(openvpn_iphdr));

	// 计算TCP校验和（包括伪头部）
	PseudoHeader pseudo_hdr;
	pseudo_hdr.src_ip = ip_hdr.saddr;
	pseudo_hdr.dst_ip = ip_hdr.daddr;
	pseudo_hdr.reserved = 0;
	pseudo_hdr.protocol = IPPROTO_TCP;
	pseudo_hdr.tcp_length = htons(sizeof(openvpn_tcphdr) + payload_len);

	uint32_t tcp_sum = calculate_checksum(&pseudo_hdr, sizeof(PseudoHeader));
	tcp_sum = calculate_checksum(&tcp_hdr, sizeof(openvpn_tcphdr), tcp_sum);
	tcp_hdr.check = calculate_checksum(payload, payload_len, tcp_sum);

	// ====================== 4. 组装完整数据包 ======================
	packet.reserve(sizeof(openvpn_iphdr) + sizeof(openvpn_tcphdr) + payload_len);
	packet.insert(packet.end(), reinterpret_cast<uint8_t*>(&ip_hdr),
		reinterpret_cast<uint8_t*>(&ip_hdr) + sizeof(openvpn_iphdr));
	packet.insert(packet.end(), reinterpret_cast<uint8_t*>(&tcp_hdr),
		reinterpret_cast<uint8_t*>(&tcp_hdr) + sizeof(openvpn_tcphdr));
	packet.insert(packet.end(), payload, payload + payload_len);

	// ====================== 5. 更新序列号 ======================
	server_seq += payload_len; // 重要：更新服务器发送序列号

	return packet;
}