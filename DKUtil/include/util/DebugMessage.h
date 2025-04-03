/**
* \copyright (C)2016 万兆天空
* \file DebugMessage.h
* \brief 声明和实现打印调试信息到DebugView的接口
*
* - v1.0
*   -# DebugMessageA 打印ANSI格式的字符串到DebugView
*   -# DebugMessageW 打印UNICODE字符串到DebugView
* \author UNI
* \date 2009-11-7
* \version 1.0
 */
#pragma once
#include <Windows.h>

#ifdef UNICODE
#define DebugMessage DebugMessageW
#else
#define DebugMessage DebugMessageA
#endif

void DebugMessageA(char * szDebugMsg,...);
void DebugMessageW(wchar_t * szDebugMsg,...);

//发行版，去掉调试信息
//#define __RELEASE_VERSION

/**
 * \defgroup LOG_AND_DEBUG_MSG 调试信息和日志
 * \{
 */

/**
 * \brief 输出调试信息
 * 
 * Usage:	DebugMessageA("错误编号:%d",2);
 *
 * \param szDebugMsg 要输出的信息,其后跟着format参数
 * 
 */
inline void DebugMessageA(char * szDebugMsg,...)
{
#ifndef __RELEASE_VERSION
	va_list va_args;
	int len;
	char * buffer;

	va_start(va_args,szDebugMsg);
	//该函数返回格式化后的字符串长度，不计算Terminating Null
	len=_vscprintf(szDebugMsg,va_args)+1;		

	buffer=new char[len*sizeof(char)];
	if(!buffer)
	{
		OutputDebugStringA("输出调试信息错误，分配空间失败\n");
		return;
	}
	vsprintf_s(buffer,len,szDebugMsg,va_args);
	OutputDebugStringA(buffer);
	delete[] buffer;
#else
	return;
#endif
}

/**
* \brief 输出调试信息（宽字符版）
*
* Usage:	DebugMessageW(L"错误编号:%d",2);
*
* \param szDebugMsg 要输出的信息,其后跟着format参数
*
*/
inline void DebugMessageW(wchar_t * szDebugMsg,...)
{
#ifndef __RELEASE_VERSION
	va_list va_args;
	int len;
	wchar_t * buffer;

	va_start(va_args,szDebugMsg);
	len=_vscwprintf(szDebugMsg,va_args)+1;

	buffer=new wchar_t[len*sizeof(wchar_t)];
	if(!buffer)
	{
		OutputDebugStringW(L"输出调试信息错误，分配空间失败\n");
		return;
	}
	vswprintf_s(buffer,len,szDebugMsg,va_args);
	OutputDebugStringW(buffer);

	delete[] buffer;
#else
	return;
#endif
}
/**
 * \}
 */
