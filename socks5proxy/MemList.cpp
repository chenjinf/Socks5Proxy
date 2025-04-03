#include "stdafx.h"
#include "MemList.h"

CMemList::CMemList()
{
	m_hEvent = CreateEvent(NULL, TRUE, FALSE, NULL);
}

CMemList::~CMemList()
{
	CloseHandle(m_hEvent);
}

int CMemList::size()
{
	return (int)m_pData.size();
}

bool CMemList::empty()
{
	return m_pData.empty();
}

void CMemList::push(CAutoMem* mem)
{
	CAutoLock l(m_cs);
	m_pData.push_back(mem);
	SetEvent(m_hEvent);
}

void CMemList::wait_data(DWORD dwMillSecs)
{
	if(WAIT_OBJECT_0 == WaitForSingleObject(m_hEvent, dwMillSecs))
		ResetEvent(m_hEvent);
}

void CMemList::abort()
{
	CAutoLock l(m_cs);
	for (int i = 0; i < m_pData.size(); i++)
	{
		CAutoMem* ret = m_pData[i];
		delete ret;
	}
	m_pData.clear();
	SetEvent(m_hEvent);
}

CAutoMem* CMemList::pop()
{
	CAutoLock l(m_cs);
	if (m_pData.empty())
		return NULL;
	else
	{
		CAutoMem* ret = m_pData.front();
		m_pData.pop_front();
		return ret;
	}
}
