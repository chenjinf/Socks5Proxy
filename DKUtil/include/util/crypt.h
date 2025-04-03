/**
 * \copyright (C)2016 万兆天空
 * \file crypt.h 
 * \brief 这个文件定义了简单加解密缓冲区的接口。
 * 
 * SimpleXor_Crype用于强度要求不高的加密。例如：
 * \code
 * char OrignalMessage[] = "hello, world.";
 * char EncryptedMessage[64] = {0};
 * // 加密
 * SimpleXor_Crype(EncryptedMessage,OrignalMessage,strlen(OrignalMessage)+1);
 * // 解密
 * char DecryptedMessage[64] = {0};
 * SimpleXor_Crype(DecryptedMessage,EncryptedMessage,strlen(OrignalMessage)+1)
 * printf("%s\n",DecryptedMessage);
 * // 打印结果：hello, world.
 * \endcode
 *
 * \version 1.0
 * \author fanduoduo
 * \date 2016/11/11
 */
#pragma once


/**
 * \brief 简单的对称加解密加密算法函数，加密解密都用这一个函数。加密前后的数据长度不会发生变化。
 * \param dest 加密后的缓冲区
 * \param src 加密前的缓冲区
 * \param len 加密长度
 * \return 无
 */
void SimpleXor_Crype(char *dest, const char *src, int len);

/**
 * tea块加密解密算法（64位为一块）
 */
void tea_encry(void *aData, const void *aKey);
void tea_decry(void *aData, const void *aKey);

//key 128bit  16byte
void tea_encry(void *aData, int nLen, const void *aKey);
void tea_decry(void *aData, int nLen, const void *aKey);

void tea_encry_32rounds(void *aData, const void *aKey);
void tea_decry_32rounds(void *aData, const void *aKey);

void tea_encry_Line(void *aData, int nLen, const void *aKey, bool bLess = false);
void tea_decry_Line(void *aData, int nLen, const void *aKey, bool bLess = false);

//TEST SUIT.
bool TeaTEST();