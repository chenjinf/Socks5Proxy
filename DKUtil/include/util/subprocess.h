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
		 * \return 创建进程和进程运行返回的结果。
		 * - -1 命令行过长
		 * - -2 创建子进程失败。
		 * - 其他，进程的返回值。
		 */
		DWORD CreateProcessEx(const string strcommand, string& strRet, BOOL bShowWindow=FALSE);

		/**
		 * \brief 使用ShellExecuteEx执行一条命令或者一个可执行文件，并根据参数设置决定是否等待它执行完成。
		 * \param command 需要执行的命令或者可执行文件。
		 * \param file 需要执行的可执行文件或者命令要打开的文件。
		 * \param args 命令行参数。
		 * \param WaitMilliSeconds 如此值为0则不等待子进程结束直接返回，否则这个参数指定等待超时时间，超时后函数将杀死子进程后返回。
		 * \return 
		 * - 返回1998表示执行子进程（或命令）失败。
		 * - 如不等待子进程完成，则如果子进程成功执行则返回0，否则返回1998.
		 * - 如等待子进程完成，则返回1999表示等待超时，返回其他值表示进程的退出码。
		 */
		DWORD ExecuteAndWaitExit(LPCWSTR command, LPCWSTR file, LPCWSTR args, BOOL bShowWindow=FALSE, DWORD WaitMilliSeconds=0);
	}
}
