/*
*  OpenVPN -- An application to securely tunnel IP networks
*             over a single TCP/UDP port, with support for SSL/TLS-based
*             session authentication and key exchange,
*             packet encryption, packet authentication, and
*             packet compression.
*
*  Copyright (C) 2002-2017 OpenVPN Technologies, Inc. <sales@openvpn.net>
*
*  This program is free software; you can redistribute it and/or modify
*  it under the terms of the GNU General Public License version 2
*  as published by the Free Software Foundation.
*
*  This program is distributed in the hope that it will be useful,
*  but WITHOUT ANY WARRANTY; without even the implied warranty of
*  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
*  GNU General Public License for more details.
*
*  You should have received a copy of the GNU General Public License along
*  with this program; if not, write to the Free Software Foundation, Inc.,
*  51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
*/

#ifndef PROTO_H
#define PROTO_H
#include <stdint.h>
#include <in6addr.h>
#define in_addr_t uint32_t


#pragma pack(1)

/*
* Tunnel types
*/
#define DEV_TYPE_UNDEF 0
#define DEV_TYPE_NULL  1
#define DEV_TYPE_TUN   2    /* point-to-point IP tunnel */
#define DEV_TYPE_TAP   3    /* ethernet (802.3) tunnel */

/* TUN topologies */

#define TOP_UNDEF   0
#define TOP_NET30   1
#define TOP_P2P     2
#define TOP_SUBNET  3

/*
* IP and Ethernet protocol structs.  For portability,
* OpenVPN needs its own definitions of these structs, and
* names have been adjusted to avoid collisions with
* native structs.
*/

#define OPENVPN_ETH_ALEN 6            /* ethernet address length */
struct openvpn_ethhdr
{
	uint8_t dest[OPENVPN_ETH_ALEN];   /* destination ethernet addr */
	uint8_t source[OPENVPN_ETH_ALEN]; /* source ethernet addr   */

#define OPENVPN_ETH_P_IPV4   0x0800   /* IPv4 protocol */
#define OPENVPN_ETH_P_IPV6   0x86DD   /* IPv6 protocol */
#define OPENVPN_ETH_P_ARP    0x0806   /* ARP protocol */
	uint16_t proto;                   /* packet type ID field */
};

struct openvpn_arp {
#define ARP_MAC_ADDR_TYPE 0x0001
	uint16_t mac_addr_type;     /* 0x0001 */

	uint16_t proto_addr_type;   /* 0x0800 */
	uint8_t mac_addr_size;      /* 0x06 */
	uint8_t proto_addr_size;    /* 0x04 */

#define ARP_REQUEST 0x0001
#define ARP_REPLY   0x0002
	uint16_t arp_command;       /* 0x0001 for ARP request, 0x0002 for ARP reply */

	uint8_t mac_src[OPENVPN_ETH_ALEN];
	in_addr_t ip_src;
	uint8_t mac_dest[OPENVPN_ETH_ALEN];
	in_addr_t ip_dest;
};

// IP包头
struct openvpn_iphdr {
#define OPENVPN_IPH_GET_VER(v) (((v) >> 4) & 0x0F)
#define OPENVPN_IPH_GET_LEN(v) (((v) & 0x0F) << 2)
	uint8_t version_len;     // 版本|首部长度 各4位。

	uint8_t tos;             // Type of service 服务类型，占8位。
	uint16_t tot_len;		 // 总长度（字节数），占16位
	uint16_t id;			 // 标识

#define OPENVPN_IP_OFFMASK 0x1fff
	uint16_t frag_off;       // 3位的标志 + 13位的片偏移

	uint8_t ttl;             // 8位的生成时间

#define OPENVPN_IPPROTO_IGMP 2  /* IGMP protocol */
#define OPENVPN_IPPROTO_TCP  6  /* TCP protocol */
#define OPENVPN_IPPROTO_UDP 17  /* UDP protocol */
	uint8_t protocol;        // 协议类型，8位。

	uint16_t check;          // 首部校验和
	uint32_t saddr;          // 源IP地址
	uint32_t daddr;          // 目的IP地址
							 /*The options start here.选项（可选） */
};

/*
* IPv6 header
*/
struct openvpn_ipv6hdr {
	uint8_t version_prio;
	uint8_t flow_lbl[3];
	uint16_t payload_len;
	uint8_t nexthdr;
	uint8_t hop_limit;

	struct  in6_addr saddr;
	struct  in6_addr daddr;
};


/*
* UDP header
*/
struct openvpn_udphdr {
	uint16_t source;
	uint16_t dest;
	uint16_t len;
	uint16_t check;
};

/*
* TCP header, per RFC 793.
*/
struct openvpn_tcphdr {
	uint16_t source;       /* 16位的源端口号 */
	uint16_t dest;         /* 16位的目的端口号 */
	uint32_t seq;          /* 32位序号 */
	uint32_t ack_seq;      /* 32位的确认号 */

#define OPENVPN_TCPH_GET_DOFF(d) (((d) & 0xF0) >> 2)
	uint8_t doff_res;      /* 4位长度 + 4位保留*/

#define OPENVPN_TCPH_FIN_MASK (1<<0)
#define OPENVPN_TCPH_SYN_MASK (1<<1)
#define OPENVPN_TCPH_RST_MASK (1<<2)
#define OPENVPN_TCPH_PSH_MASK (1<<3)
#define OPENVPN_TCPH_ACK_MASK (1<<4)
#define OPENVPN_TCPH_URG_MASK (1<<5)
#define OPENVPN_TCPH_ECE_MASK (1<<6)
#define OPENVPN_TCPH_CWR_MASK (1<<7)
	uint8_t flags;         /* 8位标志 从高到低分别是CWR、ECE、URG、ACK、PSH、RST、SYN、FIN*/

	uint16_t window;       /* 16位的窗口大小 */
	uint16_t check;        /* 16位的校验和 */
	uint16_t urg_ptr;      /* 16位紧急指针 */
						   /* 其后跟选项 - 最多40字节*/
};

#define OPENVPN_TCPOPT_EOL     0
#define OPENVPN_TCPOPT_NOP     1
#define OPENVPN_TCPOPT_MAXSEG  2  // TCP选项：最大报文段长度选项。
#define OPENVPN_TCPOLEN_MAXSEG 4  

struct ip_tcp_udp_hdr {
	struct openvpn_iphdr ip;
	union {
		struct openvpn_tcphdr tcp;
		struct openvpn_udphdr udp;
	} u;
};

#pragma pack()

/*
* The following macro is used to update an
* internet checksum.  "acc" is a 32-bit
* accumulation of all the changes to the
* checksum (adding in old 16-bit words and
* subtracting out new words), and "cksum"
* is the checksum value to be updated.
*/
#define ADJUST_CHECKSUM(acc, cksum) { \
        int _acc = acc; \
        _acc += (cksum); \
        if (_acc < 0) { \
            _acc = -_acc; \
            _acc = (_acc >> 16) + (_acc & 0xffff); \
            _acc += _acc >> 16; \
            (cksum) = (uint16_t) ~_acc; \
        } else { \
            _acc = (_acc >> 16) + (_acc & 0xffff); \
            _acc += _acc >> 16; \
            (cksum) = (uint16_t) _acc; \
        } \
}

#define ADD_CHECKSUM_32(acc, u32) { \
        acc += (u32) & 0xffff; \
        acc += (u32) >> 16;    \
}

#define SUB_CHECKSUM_32(acc, u32) { \
        acc -= (u32) & 0xffff; \
        acc -= (u32) >> 16;    \
}

/*
* We are in a "liberal" position with respect to MSS,
* i.e. we assume that MSS can be calculated from MTU
* by subtracting out only the IP and TCP header sizes
* without options.
*
* (RFC 879, section 7).
*/
#define MTU_TO_MSS(mtu) (mtu - sizeof(struct openvpn_iphdr) \
                         - sizeof(struct openvpn_tcphdr))

void mss_fixup_ipv4(BYTE *buf, int nBuflen, int maxmss);
#endif /* ifndef PROTO_H */

