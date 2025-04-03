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

	// ��TCPЭ�飬��Ƭƫ��=0���ײ�����С��nBuflen���ҳ���IP��ͷ֮��ʣ��ռ��������һ��TCPͷ
	if (pip->protocol == OPENVPN_IPPROTO_TCP
		&& (ntohs(pip->frag_off) & OPENVPN_IP_OFFMASK) == 0
		&& hlen <= nBuflen
		&& nBuflen - hlen >= (int)sizeof(struct openvpn_tcphdr))
	{
		//����IP��ͷ�ĳ��ȣ�tcָ����tcpͷ��
		struct openvpn_tcphdr *tc = (struct openvpn_tcphdr *)(buf + hlen);
		if (tc->flags & OPENVPN_TCPH_SYN_MASK)
		{
			// ȡ���ȡ�
			hlen = OPENVPN_TCPH_GET_DOFF(tc->doff_res);
			// ȡ������ͷ��֮���ѡ�
			uint8_t *opt = (uint8_t *)(tc + 1);
			// ѡ��ĳ��ȵ����ܳ��ȼ�ȥͷ�����ȡ�
			int olen = hlen - sizeof(struct openvpn_tcphdr);
			int optlen = 0;
			// ��ѡ��������������TCP���е�ѡ�
			// ���͵�TCPͷ��ѡ��ṹ: kind(1�ֽ�)|length(1�ֽ�)|info(�ɱ䳤��)��ѡ��ĵ�һ���ֶ�kind˵��ѡ������͡��е�TCPѡ��û�к��������ֶΣ�������1�ֽڵ�kind�ֶΡ�
			// �ڶ����ֶ�length������еĵĻ���ָ����ѡ����ܳ��ȣ��ó��Ȱ���kind�ֶκ�length�ֶ�ռ�ݵ�2�ֽڡ��������ֶ�info������еĻ�����ѡ��ľ�����Ϣ��
			// ������TCPѡ����7�֣�
			// kind=0��ѡ������ѡ�
			// kind=1�ǿղ�����nop��ѡ�û�����⺬�壬һ�����ڽ�TCPѡ����ܳ������Ϊ4�ֽڵ���������
			// kind=2������Ķγ���ѡ�TCP���ӳ�ʼ��ʱ��ͨ��˫��ʹ�ø�ѡ����Э������Ķγ��ȣ�Max Segement Size��MSS����
			//       TCPģ��ͨ����MSS����Ϊ��MTU-40���ֽڣ���������40�ֽڰ���20�ֽڵ�TCPͷ����20�ֽڵ�IPͷ������
			//       ����Я��TCP���Ķε�IP���ݱ��ĳ��ȾͲ��ᳬ��MTU������TCPͷ����IPͷ����������ѡ���ֶΣ�������Ҳ��һ���������
			//       �Ӷ����Ȿ������IP��Ƭ������̫�����ԣ�MSSֵ��1460��1500-40���ֽڡ�
			// kind=3�Ǵ�����������ѡ�TCP���ӳ�ʼ��ʱ��ͨ��˫��ʹ�ø�ѡ����Э�̽���ͨ�洰�ڵ��������ӡ�
			// kind=5��SACKʵ�ʹ�����ѡ���ѡ��Ĳ������߷��ͷ������Ѿ��յ�������Ĳ����������ݿ飬�Ӷ��÷��Ͷ˿��Ծݴ˼�鲢�ط���ʧ�����ݿ顣
			// kind=8��ʱ���ѡ���ѡ���ṩ�˽�Ϊ׼ȷ�ļ���ͨ��˫��֮��Ļ�·ʱ�䣨Round Trip Time��RTT���ķ������Ӷ�ΪTCP���������ṩ��Ҫ��Ϣ��
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
							// OPENVPN_TCPOPT_MAXSEG��2��ѡ����ڵĳ���Ӧ����4
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
