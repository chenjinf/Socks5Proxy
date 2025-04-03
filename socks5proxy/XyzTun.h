#pragma once
#include "stdafx.h"
#include "sockbase.h"
#include <string>

class ITunDataRead;

class IXyzTun
{
public:
	IXyzTun() { ; }
	virtual ~IXyzTun() { ; }
public:
	virtual BOOL Create(ITunDataRead *pReadIneterface, IP_TYPE ipLocal, IP_TYPE ipMask, IP_TYPE ipDns1, IP_TYPE ipDns2, bool bDefGetWay, const std::string& sNodeServerIp) = 0;
	/**
	* �ر�tun�豸���������·�ɱ��н������йص���ȫ��ɾ����
	*/
	virtual void Close() = 0;
	/**
	* ��������Ķγ���ѡ��
	*/
	virtual void SetTcpMss(int nMss) = 0;
	virtual BOOL IsReady() = 0;
	virtual BOOL Write(void *buf, int Packet_len) = 0;
protected:
private:
};