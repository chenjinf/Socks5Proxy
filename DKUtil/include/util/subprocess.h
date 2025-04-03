#pragma once
#include <string>
using std::string;

namespace qcutil 
{
	namespace subprocess 
	{
		/**
		 * \brief
		 * 
		 * \param
		 * \return �������̺ͽ������з��صĽ����
		 * - -1 �����й���
		 * - -2 �����ӽ���ʧ�ܡ�
		 * - ���������̵ķ���ֵ��
		 */
		DWORD CreateProcessEx(const string strcommand, string& strRet, BOOL bShowWindow=FALSE);

		/**
		 * \brief ʹ��ShellExecuteExִ��һ���������һ����ִ���ļ��������ݲ������þ����Ƿ�ȴ���ִ����ɡ�
		 * \param command ��Ҫִ�е�������߿�ִ���ļ���
		 * \param file ��Ҫִ�еĿ�ִ���ļ���������Ҫ�򿪵��ļ���
		 * \param args �����в�����
		 * \param WaitMilliSeconds ���ֵΪ0�򲻵ȴ��ӽ��̽���ֱ�ӷ��أ������������ָ���ȴ���ʱʱ�䣬��ʱ������ɱ���ӽ��̺󷵻ء�
		 * \return 
		 * - ����1998��ʾִ���ӽ��̣������ʧ�ܡ�
		 * - �粻�ȴ��ӽ�����ɣ�������ӽ��̳ɹ�ִ���򷵻�0�����򷵻�1998.
		 * - ��ȴ��ӽ�����ɣ��򷵻�1999��ʾ�ȴ���ʱ����������ֵ��ʾ���̵��˳��롣
		 */
		DWORD ExecuteAndWaitExit(LPCWSTR command, LPCWSTR file, LPCWSTR args, BOOL bShowWindow=FALSE, DWORD WaitMilliSeconds=0);
	}
}
