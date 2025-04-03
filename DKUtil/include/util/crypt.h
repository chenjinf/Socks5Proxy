/**
 * \copyright (C)2016 �������
 * \file crypt.h 
 * \brief ����ļ������˼򵥼ӽ��ܻ������Ľӿڡ�
 * 
 * SimpleXor_Crype����ǿ��Ҫ�󲻸ߵļ��ܡ����磺
 * \code
 * char OrignalMessage[] = "hello, world.";
 * char EncryptedMessage[64] = {0};
 * // ����
 * SimpleXor_Crype(EncryptedMessage,OrignalMessage,strlen(OrignalMessage)+1);
 * // ����
 * char DecryptedMessage[64] = {0};
 * SimpleXor_Crype(DecryptedMessage,EncryptedMessage,strlen(OrignalMessage)+1)
 * printf("%s\n",DecryptedMessage);
 * // ��ӡ�����hello, world.
 * \endcode
 *
 * \version 1.0
 * \author fanduoduo
 * \date 2016/11/11
 */
#pragma once


/**
 * \brief �򵥵ĶԳƼӽ��ܼ����㷨���������ܽ��ܶ�����һ������������ǰ������ݳ��Ȳ��ᷢ���仯��
 * \param dest ���ܺ�Ļ�����
 * \param src ����ǰ�Ļ�����
 * \param len ���ܳ���
 * \return ��
 */
void SimpleXor_Crype(char *dest, const char *src, int len);

/**
 * tea����ܽ����㷨��64λΪһ�飩
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