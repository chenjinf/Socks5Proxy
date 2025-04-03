#pragma once

class CWtThread 
{
public:
	CWtThread(void) 
	{
		m_hThread = NULL;
		m_dwTheadID = 0;
	}

	~CWtThread(void) 
	{
		Close();
	}

	BOOL CreateThread(IN LPTHREAD_START_ROUTINE lpStartAddress, IN LPVOID lpParameter = NULL) 
	{
		Close();
		m_hThread = ::CreateThread(NULL,	// default security attributes
			0,	// use default stack size
			lpStartAddress,	// thread function
			lpParameter,	// argument to thread function
			0,	// use default creation flags
			&m_dwTheadID);
		//ASSERT(m_hThread != NULL);
		return m_hThread != NULL;
	}

	BOOL Close()
	{
		//ֻ�رս��̾��.
		if (m_hThread == NULL)
		{
			return FALSE;
		}
		CloseHandle(m_hThread);
		m_hThread = NULL;
		m_dwTheadID = 0;
		return TRUE;
	}

	//ǿ��ɱ�߳�.�ǲ���Ҫ��Ҫ����.
	BOOL TerminateThread(IN DWORD dwExitCode = 0) 
	{
		return::TerminateThread(m_hThread, dwExitCode);
	}

	DWORD GetExitCodeThread()
	{
		DWORD dw =0;
		::GetExitCodeThread(m_hThread, &dw);
		return dw;
	}

	//�ж��Ƿ��Ѿ�������.��ʱ����
	BOOL IsLife() 
	{				
		if(m_hThread == 0)
			return 0;
		DWORD dw = WaitForSingleObject(m_hThread, 0);
		if (dw == WAIT_TIMEOUT) 
		{
			return TRUE;
		}
		return FALSE;
	}

	//�ȴ��̵߳�����. ��������ǰ�߳�
	void WaitToEnd() 
	{
		if(m_hThread == 0)
			return;
		WaitForSingleObject(m_hThread, INFINITE);
	}

	void WaitToEndKill(DWORD dwTime)
	{
		if(m_hThread == 0)
			return;
		WaitForSingleObject(m_hThread, dwTime);
		if ( IsLife() )
		{
			TerminateThread(0);
		}
	}

	HANDLE m_hThread;
	DWORD m_dwTheadID;
};


class CWtThreadEx : public CWtThread
{
public:
	virtual void OnThread() = 0;

	BOOL CreateThread()
	{
		return CWtThread::CreateThread(MyThread, this);
	}

	static DWORD WINAPI MyThread(void* lp)
	{
		CWtThreadEx *p = (CWtThreadEx*)lp;
		p->OnThread();
		return 0;
	}
};

class CWtThreadQuit
{
public:
	CWtThreadQuit()
	{
		ResetQuit();
	}

	static CWtThreadQuit *GetInstance()
	{
		static CWtThreadQuit q;
		return &q;
	}

	void SetQuit()
	{
		m_bQuit = true;
	}

	void ResetQuit()
	{
		m_bQuit = false;
	}

	bool GetQuit()
	{
		return m_bQuit;
	}

private:
	bool m_bQuit;
};
