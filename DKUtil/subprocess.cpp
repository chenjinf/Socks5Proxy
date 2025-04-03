#include <windows.h>
#include "util/subprocess.h"
#include "util/StringEx.h"

#define Output
using std::wstring;

namespace qcutil
{
	namespace subprocess
	{
		DWORD CreateProcessEx(const string strcommand, string& strRet, BOOL bShowWindow/*=FALSE*/)
		{
			OSVERSIONINFO os_ver = { 0 };
			os_ver.dwOSVersionInfoSize = sizeof(OSVERSIONINFO);
			GetVersionEx(&os_ver);
			HANDLE h_read_pipe = 0;
			HANDLE h_write_pipe = 0;
			SECURITY_ATTRIBUTES sa;
			if (VER_PLATFORM_WIN32_NT == os_ver.dwPlatformId)
			{
				sa.nLength = sizeof(sa);
				sa.lpSecurityDescriptor = NULL;
				sa.bInheritHandle = true;
				CreatePipe(&h_read_pipe, &h_write_pipe, &sa, 0);
			}
			else
			{
				CreatePipe(&h_read_pipe, &h_write_pipe, NULL, 1024);
			}
			STARTUPINFOA si = { 0 };
			si.cb = sizeof(STARTUPINFOA);
			si.wShowWindow = bShowWindow ? SW_SHOW : SW_HIDE;
			si.dwFlags = STARTF_USESHOWWINDOW | STARTF_USESTDHANDLES;
			si.hStdOutput = h_write_pipe;
			si.hStdError = h_write_pipe;
			PROCESS_INFORMATION pi;
			string str_result = "";
			char pchr_cmd[512] = { 0 };
			if (strcommand.length() >= sizeof(pchr_cmd))
			{
				Output(L"传入的参数超过了最大长度512\r\n");
				return (DWORD)(-1);
			}
			strcpy_s(pchr_cmd, sizeof(pchr_cmd), strcommand.c_str());
			//strncpy(pchr_cmd, strcommand.c_str(), sizeof(pchr_cmd) - 1);

			DWORD dw_exit_code = (DWORD)(-2);
			if (CreateProcessA(NULL, pchr_cmd, NULL, NULL, TRUE, 0, NULL, NULL, &si, &pi))
			{
				Output(L"成功创建了子进程\r\n");
				DWORD dw_read = 0, dw_result = 0;
				BOOL bExitFlag = FALSE;
				char pchr_buffer[1024] = { 0 };
				while (!bExitFlag)
				{
					dw_result = WaitForSingleObject(pi.hProcess, 500);
					while (PeekNamedPipe(h_read_pipe, pchr_buffer, sizeof(pchr_buffer), &dw_read, NULL, NULL))
					{
						if (dw_read > 0)
						{
							DWORD dw_byte_read = 0;
							memset(pchr_buffer, 0, sizeof(pchr_buffer));
							if (ReadFile(h_read_pipe, pchr_buffer, dw_read, &dw_byte_read, NULL))
							{
								string strTemp = string(pchr_buffer, dw_byte_read);
								wstring wstr = String(strTemp).toStdWString();
								Output(L"%s\r\n", wstr.c_str());
								str_result += strTemp;
							}
						}
						else
						{
							break;
						}
					}
					if (dw_result != WAIT_TIMEOUT)
					{
						bExitFlag = TRUE;
					}
				}
				GetExitCodeProcess(pi.hProcess, &dw_exit_code);
				Output(L"进程退出代码:%d\r\n", dw_exit_code);
				CloseHandle(pi.hProcess);
				CloseHandle(pi.hThread);
			}
			CloseHandle(h_read_pipe);
			CloseHandle(h_write_pipe);
			strRet = str_result;
			return dw_exit_code;
		}

		DWORD ExecuteAndWaitExit(LPCWSTR command, LPCWSTR file, LPCWSTR args, BOOL bShowWindow/*=FALSE*/, DWORD WaitMilliSeconds/*=0*/)
		{
			SHELLEXECUTEINFOW ShExecInfo = {0};
			ShExecInfo.cbSize   = sizeof(SHELLEXECUTEINFO);
			ShExecInfo.fMask    = SEE_MASK_NOCLOSEPROCESS;
			ShExecInfo.hwnd     = NULL;
			ShExecInfo.lpVerb   = command;
			ShExecInfo.lpFile   = file;        
			ShExecInfo.lpParameters = args;    
			ShExecInfo.lpDirectory  = NULL;
			ShExecInfo.nShow    =	bShowWindow ? SW_SHOW : SW_HIDE;
			ShExecInfo.hInstApp = NULL;    
			BOOL bRet = ShellExecuteExW(&ShExecInfo);
			if (bRet && ShExecInfo.hProcess)
			{
				if (WaitMilliSeconds == 0)
				{
					return 0;
				}
				else
				{
					// 指定时间没结束,强行杀死进程
					if (WaitForSingleObject(ShExecInfo.hProcess, WaitMilliSeconds) == WAIT_TIMEOUT)
					{    
						TerminateProcess(ShExecInfo.hProcess, 0);
						return 1999;
					}
					else
					{
						DWORD dwExitCode = 2000;
						GetExitCodeProcess(ShExecInfo.hProcess, &dwExitCode);
						return dwExitCode;
					}
				}
			}
			else
			{
				// DWORD dwError = GetLastError();
				// DebugMessageW(L"Failed to create process with error %d", dwError);
				return 1998;
			}
		}

	}
}
