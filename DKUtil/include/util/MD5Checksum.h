/**
 * \copyright (C)2016 万兆天空
 * \file MD5Checksum.h
 * \brief 定义 CMD5Checksum ，封装MD5文件校验和字符串校验
 * \version 1.1
 * \author duo
 * \date 20160826
 */
#pragma once
#include <Windows.h>

#include <string>
using std::wstring;
using std::string;

/**
 * \defgroup MD5CHECKS MD5校验
 * \{
 */

/**
 * \class CMD5Checksum
 * \brief 提供MD5文件校验和字符串校验的接口。
 * \ingroup MD5校验
 */
class CMD5Checksum  
{
public:
	/**
	 * \brief 获取字符串的MD5值
	 * \param strString 需要校验的字符串
	 * \return 返回结果值
	 */
	static string GetMD5OfString(const string& strString);
	/**
	 * \brief 获取文件的MD5值
	 * \param strFilePath 文件路径
	 * \return 如果获取MD5失败，返回空字符串。
	 */
	static wstring GetMD5(const wstring& strFilePath);

	/**
	 * \brief 计算一个缓冲区的MD5值。
	 */
	static string GetMD5(char* pBuff, unsigned long nleng);
	
	/**
	 * \brief 计算一个缓冲区的MD5值。 
	 */
	static void GetMD5(char* pBuffer, unsigned long nleng, OUT BYTE* OutBuf, ULONG cbOutBufLen);
protected:
	//constructor/destructor
	CMD5Checksum();
	virtual ~CMD5Checksum() {};
	//RSA MD5 implementation
	void Transform(BYTE Block[64]);
	void Update(BYTE* Input, ULONG nInputLen);
	string Final();
	void Final(OUT BYTE* OutBuf, ULONG cbOutBufLen);
	inline DWORD RotateLeft(DWORD x, int n);
	inline void FF( DWORD& A, DWORD B, DWORD C, DWORD D, DWORD X, DWORD S, DWORD T);
	inline void GG( DWORD& A, DWORD B, DWORD C, DWORD D, DWORD X, DWORD S, DWORD T);
	inline void HH( DWORD& A, DWORD B, DWORD C, DWORD D, DWORD X, DWORD S, DWORD T);
	inline void II( DWORD& A, DWORD B, DWORD C, DWORD D, DWORD X, DWORD S, DWORD T);
	//utility functions
	inline void DWordToByte(BYTE* OutputB, DWORD* Input, UINT nLength);
	inline void ByteToDWord(DWORD* OutputB, BYTE* Input, UINT nLength);
private:
	BYTE  m_lpszBuffer[64];	//input buffer
	ULONG m_nCount[2];			//number of bits, modulo 2^64 (lsb first)
	ULONG m_lMD5[4];			//MD5 checksum
};

/**
 * \}
 */