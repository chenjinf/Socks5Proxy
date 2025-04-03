#include "stdafx.h"
#include <string>
#include "HexStr.h"

static BYTE GetByte(char ch)
{
	if (ch >='0' && ch <= '9')
		return ch - 0x30;

	if (ch >='A' && ch <='F')
		return ch - ('A'-10);

	if ( ch >='a' && ch <='f')
		return ch -('a' - 10);

	return 0;
}


static BYTE GetByte(const char sz[2])
{
	return GetByte(sz[0])<<4 | GetByte(sz[1]);
}


bool StrToBcd(const char *sz, int nSzLen, void *buf, int len)
{
	if ( nSzLen % 2)
	{
		return false;
	}
	int j = 0;
	for (int i = 0; i < nSzLen ; i+=2)
	{
		((BYTE*)buf)[j++] = GetByte(sz +i);
	}
	return true;
}

static char GetHexHigh(BYTE by)
{
	by >>=4;
	by += 0x30;
	if ( by > '9')
	{
		by += 7;
	}
	return by;
}

static char GetHexLow(BYTE by)
{
	by &= 0x0F;
	by += 0x30;
	if ( by > '9')
	{
		by += 7;
	}
	return by;
}

bool BcdToStr(const void *buf, int len, char *sz, int szLen)
{
	if (szLen < len *2)
	{
		return false;
	}
	int j= 0;
	for (int i = 0; i < len ; i++)
	{
		sz[j++] = GetHexHigh(((BYTE*)buf)[i]); 
		sz[j++] = GetHexLow(((BYTE*)buf)[i]); 
	}
	return true;
}

std::string BcdToStr(const void *buf, int len)
{
	if (len <= 0)
	{
		return "";
	}
	
	int strBufLen = len * 2 + 1;
	char* pStrBuf = new char[strBufLen];
	memset(pStrBuf, 0, strBufLen);
	BcdToStr(buf, len, pStrBuf, strBufLen);
	std::string strRet = pStrBuf;
	delete [] pStrBuf;

	return strRet;
}

std::string BcdToStrFmt(const void* buf, int len)
{
	if (len <= 0)
	{
		return "";
	}
	int strBufLen = len * 3 + 1;
	char* pStrBuf = new char[strBufLen];
	memset(pStrBuf, 0, strBufLen);

	int j = 0;
	for (int i = 0; i < len; i++)
	{
		pStrBuf[j++] = GetHexHigh(((BYTE*)buf)[i]);
		pStrBuf[j++] = GetHexLow(((BYTE*)buf)[i]);
		pStrBuf[j++] = ' ';
	}

	std::string strRet = pStrBuf;
	delete[] pStrBuf;
	return strRet;
}
