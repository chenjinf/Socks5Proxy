#pragma once
#include <cstdint>
#include <functional> // 用于 std::hash
#include <boost/asio/ip/address.hpp>
#include <boost/functional/hash.hpp>

// IPv4/IPv6 通用地址包装
union NetworkAddress {
	boost::asio::ip::address_v4::bytes_type v4;
	boost::asio::ip::address_v6::bytes_type v6;
};

// 会话唯一标识结构
struct SessionID {
	NetworkAddress src_ip;    // 源IP地址
	NetworkAddress dst_ip;    // 目标IP地址
	uint16_t src_port;        // 源端口（主机字节序）
	uint16_t dst_port;        // 目标端口（主机字节序）
	uint8_t protocol;         // 协议类型（IPPROTO_TCP/IPPROTO_UDP）

							  // 新增序列号跟踪字段
	uint32_t client_seq = 0;  // 客户端最后发送的序列号
	uint32_t server_seq = 0;  // 服务器最后发送的序列号
	uint32_t client_ack = 0;  // 客户端最后确认的序列号
	uint32_t server_ack = 0;  // 服务器最后确认的序列号

							  // 相等比较运算符（用于哈希容器）
	bool operator==(const SessionID& other) const {
		return src_ip.v4 == other.src_ip.v4 &&
			dst_ip.v4 == other.dst_ip.v4 &&
			src_port == other.src_port &&
			dst_port == other.dst_port &&
			protocol == other.protocol;
	}
};

// 哈希特化（C++17 起可省略，但仍需显式声明）
namespace std {
	template<>
	struct hash<SessionID> {
		size_t operator()(const SessionID& id) const {
			size_t seed = 0;
			// 组合哈希值
			boost::hash_combine(seed, hash_bytes(id.src_ip.v4.data(), 4));
			boost::hash_combine(seed, hash_bytes(id.dst_ip.v4.data(), 4));
			boost::hash_combine(seed, id.src_port);
			boost::hash_combine(seed, id.dst_port);
			boost::hash_combine(seed, id.protocol);
			return seed;
		}

	private:
		// 辅助函数：处理字节数组哈希
		static size_t hash_bytes(const void* ptr, size_t len) {
			const char* p = static_cast<const char*>(ptr);
			size_t result = 0;
			for (size_t i = 0; i < len; ++i) {
				result = (result * 131) + p[i];
			}
			return result;
		}
	};
}