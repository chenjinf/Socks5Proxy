#pragma once

class CTimeOut
{
public:
	CTimeOut(int nTimeOut)
	{
		SetTimeOut(nTimeOut);
	}

	void SetTimeOut(int nTimeOut)
	{
		m_ll = GetCurMinsTime();
		m_nTimeOut = nTimeOut;
	}

	BOOL IsTimeOutAndReset(int nTimeOut = -1)
	{
		if (nTimeOut != -1){
			m_nTimeOut = nTimeOut;
		}
		return IsTimeOutAndReset2(GetCurMinsTime());
	}

	BOOL IsTimeOut(LONGLONG llCur)
	{
		return m_ll > llCur? TRUE: llCur - m_ll > m_nTimeOut;
	}

	BOOL IsTimeOutAndReset2(LONGLONG llCur)
	{
		if (m_ll > llCur)
		{
			m_ll = llCur;
			return TRUE;
		}

		if (llCur - m_ll > m_nTimeOut)
		{
			m_ll = llCur;
			return TRUE;
		}
		return FALSE;

	}

	void Reset()
	{
		m_ll = GetCurMinsTime();
	}

private:
	LONGLONG GetCurMinsTime()
	{
		SYSTEMTIME st;
		::GetLocalTime(&st);
		FILETIME ft;
		::SystemTimeToFileTime(&st, &ft);

		LONGLONG ll = *(LONGLONG*)&ft;
		ll /= 10000;
		return ll;
	}

	LONGLONG m_ll;
	int m_nTimeOut;
};
