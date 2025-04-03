#pragma once
#include <cstdint>
#include <functional> // ���� std::hash
#include <boost/asio/ip/address.hpp>
#include <boost/functional/hash.hpp>

// IPv4/IPv6 ͨ�õ�ַ��װ
union NetworkAddress {
	boost::asio::ip::address_v4::bytes_type v4;
	boost::asio::ip::address_v6::bytes_type v6;
};

// �ỰΨһ��ʶ�ṹ
struct SessionID {
	NetworkAddress src_ip;    // ԴIP��ַ
	NetworkAddress dst_ip;    // Ŀ��IP��ַ
	uint16_t src_port;        // Դ�˿ڣ������ֽ���
	uint16_t dst_port;        // Ŀ��˿ڣ������ֽ���
	uint8_t protocol;         // Э�����ͣ�IPPROTO_TCP/IPPROTO_UDP��

							  // �������кŸ����ֶ�
	uint32_t client_seq = 0;  // �ͻ�������͵����к�
	uint32_t server_seq = 0;  // ����������͵����к�
	uint32_t client_ack = 0;  // �ͻ������ȷ�ϵ����к�
	uint32_t server_ack = 0;  // ���������ȷ�ϵ����к�

							  // ��ȱȽ�����������ڹ�ϣ������
	bool operator==(const SessionID& other) const {
		return src_ip.v4 == other.src_ip.v4 &&
			dst_ip.v4 == other.dst_ip.v4 &&
			src_port == other.src_port &&
			dst_port == other.dst_port &&
			protocol == other.protocol;
	}
};

// ��ϣ�ػ���C++17 ���ʡ�ԣ���������ʽ������
namespace std {
	template<>
	struct hash<SessionID> {
		size_t operator()(const SessionID& id) const {
			size_t seed = 0;
			// ��Ϲ�ϣֵ
			boost::hash_combine(seed, hash_bytes(id.src_ip.v4.data(), 4));
			boost::hash_combine(seed, hash_bytes(id.dst_ip.v4.data(), 4));
			boost::hash_combine(seed, id.src_port);
			boost::hash_combine(seed, id.dst_port);
			boost::hash_combine(seed, id.protocol);
			return seed;
		}

	private:
		// ���������������ֽ������ϣ
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