#pragma once

#include "util/AutoLock.h"
#include "util/AutoMemory.h"
#include <deque>

class CMemList
{
public:
	CMemList();
	~CMemList();
public:
	/**
	 * return the size of deque.
	 */
	int size();

	/**
	 * same as deque::empty.
	 */
	bool empty();

	/**
	 * push a block to list, and set event (then a thread which waiting for it can wake up).
	 */
	void push(CAutoMem* mem);

	/**
	 * waiting for data.
	 */
	void wait_data(DWORD dwMillSecs);

	/**
	 * abort waiting.
	 */
	void abort();

	/**
	 * pop a block from deque.
	 */
	CAutoMem* pop();

protected:
private:
	std::deque<CAutoMem*> m_pData;
	CLock_CS m_cs;
	HANDLE m_hEvent;
};
