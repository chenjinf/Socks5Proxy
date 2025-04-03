#include "stdafx.h"
#include "proto.h"


void mss_fixup_ipv4(BYTE *buf, int nBuflen, int maxmss)
{
	if (nBuflen < (int)sizeof(struct openvpn_iphdr))
	{
		return;
	}
	//verify_align_4(buf);
	const struct openvpn_iphdr *pip = (struct openvpn_iphdr *)buf;
	int hlen = OPENVPN_IPH_GET_LEN(pip->version_len);

	// 是TCP协议，且片偏移=0，首部长度小于nBuflen，且除了IP包头之外剩余空间可容纳下一个TCP头
	if (pip->protocol == OPENVPN_IPPROTO_TCP
		&& (ntohs(pip->frag_off) & OPENVPN_IP_OFFMASK) == 0
		&& hlen <= nBuflen
		&& nBuflen - hlen >= (int)sizeof(struct openvpn_tcphdr))
	{
		//加上IP包头的长度，tc指向了tcp头。
		struct openvpn_tcphdr *tc = (struct openvpn_tcphdr *)(buf + hlen);
		if (tc->flags & OPENVPN_TCPH_SYN_MASK)
		{
			// 取长度。
			hlen = OPENVPN_TCPH_GET_DOFF(tc->doff_res);
			// 取紧跟在头部之后的选项。
			uint8_t *opt = (uint8_t *)(tc + 1);
			// 选项的长度等于总长度减去头部长度。
			int olen = hlen - sizeof(struct openvpn_tcphdr);
			int optlen = 0;
			// 如选项存在则继续解析TCP包中的选项。
			// 典型的TCP头部选项结构: kind(1字节)|length(1字节)|info(可变长度)。选项的第一个字段kind说明选项的类型。有的TCP选项没有后面两个字段，仅包含1字节的kind字段。
			// 第二个字段length（如果有的的话）指定该选项的总长度，该长度包括kind字段和length字段占据的2字节。第三个字段info（如果有的话）是选项的具体信息。
			// 常见的TCP选项有7种：
			// kind=0是选项表结束选项。
			// kind=1是空操作（nop）选项，没有特殊含义，一般用于将TCP选项的总长度填充为4字节的整数倍。
			// kind=2是最大报文段长度选项。TCP连接初始化时，通信双方使用该选项来协商最大报文段长度（Max Segement Size，MSS）。
			//       TCP模块通常将MSS设置为（MTU-40）字节（减掉的这40字节包括20字节的TCP头部和20字节的IP头部）。
			//       这样携带TCP报文段的IP数据报的长度就不会超过MTU（假设TCP头部和IP头部都不包含选项字段，并且这也是一般情况），
			//       从而避免本机发生IP分片。对以太网而言，MSS值是1460（1500-40）字节。
			// kind=3是窗口扩大因子选项。TCP连接初始化时，通信双方使用该选项来协商接收通告窗口的扩大因子。
			// kind=5是SACK实际工作的选项。该选项的参数告诉发送方本端已经收到并缓存的不连续的数据块，从而让发送端可以据此检查并重发丢失的数据块。
			// kind=8是时间戳选项。该选项提供了较为准确的计算通信双方之间的回路时间（Round Trip Time，RTT）的方法，从而为TCP流量控制提供重要信息。
			while (olen > 1)
			{
				if (*opt == OPENVPN_TCPOPT_EOL)
				{
					break;
				}
				else if (*opt == OPENVPN_TCPOPT_NOP)
				{
					optlen = 1;
				}
				else
				{
					optlen = *(opt + 1);
					if (optlen <= 0 || optlen > olen)
					{
						break;
					}
					if (*opt == OPENVPN_TCPOPT_MAXSEG)
					{
						if (optlen != OPENVPN_TCPOLEN_MAXSEG)
						{
							// OPENVPN_TCPOPT_MAXSEG（2）选项对于的长度应该是4
							continue;
						}
						unsigned short mssval = (opt[2] << 8) + opt[3];
						if (mssval > maxmss)
						{
							//std::string trace = std::string("mss one dest:") + IPTypeToString(pip->daddr);
							//DKTRACEA("%s\n", trace.c_str());
							int accumulate = htons(mssval);
							opt[2] = (maxmss >> 8) & 0xff;
							opt[3] = maxmss & 0xff;
							accumulate -= htons(maxmss);
							ADJUST_CHECKSUM(accumulate, tc->check);
						}
					}
				}
				olen -= optlen;
				opt += optlen;
			}// end while (olen > 1)
		}
	}
}
