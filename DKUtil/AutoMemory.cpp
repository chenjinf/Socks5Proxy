#include <windows.h>
#include "util/AutoMemory.h"
#include <sstream>

#ifndef ASSERT
#define ASSERT(exp) ((VOID) 0)
#endif

CAutoMem::CAutoMem(int len /*= 0*/ , BOOL bDelete /*= FALSE*/ , BOOL bZero /*= TRUE*/)
{
	m_bDelete = TRUE;
	m_bZero = bZero;
	m_nLen = 0;
	m_pBuffer = NULL;
	m_cbMaxLen = 0;				//ʵ�ʷ�����ڴ档
	Init(len, bDelete);
}

CAutoMem::CAutoMem(const void *buffer, int len , bool bDelete /*= TRUE*/, BOOL bZero /*= TRUE*/)
{
	m_bDelete = TRUE;
	m_bZero = bZero;
	m_nLen = 0;
	m_pBuffer = NULL;
	m_cbMaxLen = 0;				//ʵ�ʷ�����ڴ档
	Attach((void *)buffer, len ,bDelete);
}

int CAutoMem::WriteStr(const wchar_t* lpsz)
{
	if (!lpsz)
	{
		return 0;
	}

	if (!lpsz[0])
	{
		return 0;
	}

	if (m_nLen - m_nSeek <= 2)
	{
		return 0;
	}

	int nstrLen = (int)wcslen(lpsz);
	int iRet = Write((void *) lpsz, (nstrLen + 1) * sizeof(wchar_t));
	ASSERT(iRet >= 2);
	ASSERT(m_nSeek >= 2);
	if (iRet != (nstrLen + 1) * sizeof(wchar_t))
	{
		// �ռ䲻����д�������ַ�������Ҫ�ضϡ�
		// �����Ѿ��жϿ���ȷ��m_nLen - m_nSeek >= 2����������ֱ�Ӹ�ֵ0�ض��ַ�����
		m_pBuffer[m_nSeek - 1] = 0;
		m_pBuffer[m_nSeek - 2] = 0;
	}
	return iRet;
}

int CAutoMem::WriteRand(int nSize)
{
	int nCout = nSize /2 ;
	int nReturn = 0;
	for (int i = 0; i < nCout ; i++){
		nReturn += WriteShort(rand() * rand());
	}
	nCout = nSize - nCout *2;
	for (int i = 0; i < nCout ; i++){
		nReturn += WriteByte(rand());
	}
	return nReturn;
}

int CAutoMem::ReadInt(bool bLowBit /*= true */)
{
	int n = 0;
	if (bLowBit){
		Read(&n,4);
	}else{
		n = (((int)ReadByte()) << 24) | (((int)ReadByte()) << 16) | (((int)ReadByte()) << 8) | ReadByte();
	}
	return n;
}

UINT CAutoMem::ReadUInt(bool bLowBit /*= true*/)
{
	UINT n = 0;
	if (bLowBit){
		Read(&n,4);
	}else{
		n = (((UINT)ReadByte()) << 24) | (((UINT)ReadByte()) << 16) | (((UINT)ReadByte()) << 8) | ReadByte();
	}
	return n;
}

LONGLONG CAutoMem::ReadLongLong()
{
	LONGLONG n= 0;
	Read(&n,8);
	return n;
}

short CAutoMem::ReadShort(bool bLowBit /*= true*/)
{
	short n = 0;
	if (bLowBit)
	{
		Read(&n,2);
	}else{
		n = (((short)ReadByte()) << 8) | ReadByte();
	}
	return n;
}

USHORT CAutoMem::ReadUShort(bool bLowBit /*= true*/)
{
	USHORT n = 0;
	if (bLowBit)
	{
		Read(&n,2);
	}else{
		n = (((short)ReadByte()) << 8) | ReadByte();
	}
	return n;
}

byte CAutoMem::ReadByte()
{
	byte n = 0;
	Read(&n, 1);
	return n;
}

wstring CAutoMem::ReadLenString()
{
	wstring ret;
	if (GetNoUseLen() < 2)
	{
		return ret;
	}

	int nLen = ReadUShort();
	if (nLen == 0xffff)
	{
		if (GetNoUseLen() < 4)
			return ret;
		nLen = ReadInt();
	}

	if (GetNoUseLen() < nLen * sizeof(wchar_t))
	{
		return ret;
	}

	if (nLen == 0)
		return ret;

	wstring str;
	str.assign((wchar_t*)(m_pBuffer + m_nSeek), nLen);

	Seek(nLen * sizeof(wchar_t));
	return str;
}

void CAutoMem::WriteLenString(const wchar_t* lpsz)
{
	if (!lpsz)
	{
		if (GetNoUseLen() < 2)
		{
			ChgLenAndSeek(2 + GetCurSeek(), GetCurSeek());
		}
		WriteUSHORT(0);
		return;
	}

	int nStrLen = wcslen(lpsz);
	int nLen = nStrLen * sizeof(wchar_t);
	if (nStrLen >= 0xffff)
	{
		// �����ŵ���һ���������ȵ��ַ�������ô��6���ֽڱ�ʾ���ȡ�
		// 0xffff 0x00000000 ������ǳ������ȵ��ַ�������ô��0xffff��ͷ��
		if (GetNoUseLen() < nLen + 6)
		{
			ChgLenAndSeek(nLen + 6 + GetCurSeek(), GetCurSeek());
		}
		WriteUSHORT(0xffff);
		WriteInt(nStrLen);
	}
	else
	{
		if (GetNoUseLen() < nLen + 2)
		{
			ChgLenAndSeek(nLen + 2 + GetCurSeek(), GetCurSeek());
		}
		WriteUSHORT(nStrLen);
		if (nLen == 0)
		{
			//���ַ�����ֻ��Ҫ����0x00 00���ɡ�
			return;
		}
	}
	Write(lpsz, nLen);
}

string CAutoMem::ReadLenStringA()
{
	string ret;
	if (GetNoUseLen() < 2){
		return ret;
	}
	int nLen = ReadUShort();
	if (nLen == 0xffff){
		if (GetNoUseLen() < 4)
		{
			return ret;
		}
		nLen = ReadInt();
	}

	if (GetNoUseLen() < nLen){
		return ret;
	}

	if (nLen == 0)
	{
		return ret;
	}

	ret.assign((char *)(m_pBuffer + m_nSeek), nLen);
	Seek(nLen);
	return ret;
}

void CAutoMem::WriteLenStringA(const char * lpsz)
{
	if (lpsz == NULL){
		if (GetNoUseLen() < 2)
		{
			ChgLenAndSeek(2 + GetCurSeek(), GetCurSeek());
		}
		WriteUSHORT(0);
		return;
	}
	int nLen = (int)strlen(lpsz) ;
	if (nLen >= 0xffff){
		if (GetNoUseLen() < nLen + 6){
			ChgLenAndSeek(nLen + 6 + GetCurSeek(), GetCurSeek());
		}
		WriteUSHORT(0xffff);
		WriteInt(nLen);
	}else{
		if (GetNoUseLen() < nLen + 2){
			ChgLenAndSeek(nLen + 2 + GetCurSeek(), GetCurSeek());
		}
		WriteUSHORT(nLen);
	}
	Write(lpsz, nLen);
}

int CAutoMem::Replace(void *bufferOld, void *buffernew, int len)
{
	//int nSeek = GetCurSeek();
	int nReturn = 0;
	int nFind = FindNext(bufferOld, len, TRUE);
	if (-1 != nFind)
	{
		do {
			nReturn++;
			Seek(nFind, CAutoMem::current);
			Write(buffernew, len);
			nFind = FindNext(bufferOld, len, FALSE);
		} while (nFind != -1);
	}
	Seek(m_nSeek, CAutoMem::begin);
	return nReturn;
}

BOOL CAutoMem::StartsWith(const void *buf, int len)
{
	if (GetLen() < len){
		return FALSE;
	}
	return memcmp(m_pBuffer, buf, len) == 0;
}

int CAutoMem::FindNext(void *buffer, int len, BOOL bFindBegin /*= FALSE*/)
{
	int nBegin = 0;
	if (!bFindBegin) {
		nBegin = m_nSeek;
	}
	while (nBegin + len <= m_nLen) {
		if (0 == memcmp(buffer, m_pBuffer + nBegin, len)) {
			return bFindBegin ? nBegin : (nBegin - m_nSeek);
		}
		nBegin++;
	}
	return -1;
}

BOOL CAutoMem::CopyTo(CAutoMem * pMem)
{
	if (FALSE == pMem->ChgLen(GetLen())) {
		ASSERT(FALSE);
		return FALSE;
	}
	pMem->Write(GetBuffer(), GetLen());
	pMem->SeekToBegin();
	return TRUE;
}

CAutoMem* CAutoMem::Clone()
{
	CAutoMem *p = new CAutoMem(GetLen());
	p->Write(GetBuffer(), GetLen());
	p->Seek(GetCurSeek(), begin);
	return p;
}

CAutoMem* CAutoMem::NewMem(int nLen /*= 0*/)
{
	CAutoMem *pMem = new CAutoMem(nLen, TRUE, false);
	return pMem;
}

CAutoMem* CAutoMem::NewMem(const void *buf, int nLen)
{
	CAutoMem *pMem = NewMem(nLen);
	pMem->SeekToBegin();
	pMem->Write(buf, nLen);
	pMem->SeekToBegin();
	return pMem;
}

void CAutoMem::ChgOrder(void *buffer, int len)
{
	char temp;
	for (int i = 0; i < len / 2; i++) {
		temp = *(((char *) buffer) + i);
		*(((char *) buffer) + i) = *(((char *) buffer) + len - i - 1);
		*(((char *) buffer) + len - i - 1) = temp;
	}
}

int CAutoMem::SeekToBegin()
{
	m_nSeek = 0;
	return m_nSeek;
}

int CAutoMem::SeekToEnd()
{
	m_nSeek = m_nLen;
	return m_nSeek;
}

int CAutoMem::Seek(int nSeek, int nType /*= current*/)
{
	switch (nType) {
	case begin:
		m_nSeek = nSeek;
		break;
	case end:
		m_nSeek = m_nLen + nSeek;
		break;
	case current:
		m_nSeek += nSeek;
		break;
	default:
		ASSERT(FALSE);			//�����ʱʹ��nType�������;
		break;
	}
	if (m_nSeek >= 0 && m_nSeek <= m_nLen) {
		return m_nSeek;
	}
	//ASSERT(FALSE);
	if (m_nSeek < 0) {
		m_nSeek = 0;
	} else {
		m_nSeek = m_nLen;
	}
	//m_nSeek  = m_nSeek < 0 ? - m_nSeek: m_nSeek;
	//m_nSeek = nSeek > m_nLen ? m_nLen :m_nSeek;
	return m_nSeek;
}

void CAutoMem::Init(int len /* = 0 */ , BOOL bDelete /* = TRUE */)
{
	Destory();
	if (len < 0) {
		ASSERT(FALSE);
		len = 0;
	}
	m_bDelete = bDelete;
	m_nLen = len;
	m_nSeek = 0;
	if (len == 0) {
		m_pBuffer = NULL;
		m_cbMaxLen = 0;
	} else {
		if (len % 4 != 0) {
			len += (4 - len % 4);
		}
		m_pBuffer = new BYTE[len];
		if (m_pBuffer == NULL) {
			m_nLen = 0;
			m_cbMaxLen = 0;
			ASSERT(FALSE);
		} else {
			//int *pInt = (int *)m_pBuffer;
			//int nCount = len/4;
			//for (int i = 0; i < nCount ; i++, pInt++){
			//	*pInt = 0;
			//*((int*)(m_pBuffer + i)) = 
			//}
			if (m_bZero){
				ZeroMemory(m_pBuffer, len);
			}
			//
			m_cbMaxLen = len;
		}
	}
}

BOOL CAutoMem::ChgLenAndSeek(int nNewLen, int nSeekFromBegin)
{
	if (ChgLen(nNewLen))
	{
		Seek(nSeekFromBegin, begin);
		return TRUE;
	}
	return FALSE;
}

CAutoMem::~CAutoMem()
{
	Destory();
}

int CAutoMem::Write(const void *buffer, int len)
{
	ASSERT(m_nLen >= m_nSeek);
	if (len <= 0)
	{
		return 0;
	}

	if (m_nSeek + len > m_nLen) 
	{
		int nWrite = m_nLen - m_nSeek;
		if (nWrite == 0)
		{
			//�ռ�������
			return 0;
		}
		memcpy(m_pBuffer + m_nSeek, buffer, nWrite);
		m_nSeek = m_nLen;
		return nWrite;
	}
	memcpy(m_pBuffer + m_nSeek, buffer, len);
	m_nSeek += len;
	return len;
}

int CAutoMem::Read(void *buffer, int len)
{
	if (m_nSeek + len > m_nLen) {
		int nRead = m_nLen - m_nSeek;
		if (0 == nRead)
		{
			return 0;
		}
		memcpy(buffer, m_pBuffer + m_nSeek , nRead);
		m_nSeek = m_nLen;
		return nRead;
	}
	memcpy(buffer, m_pBuffer + m_nSeek, len);
	m_nSeek += len;
	return len;
}

int CAutoMem::Attach(const void *buffer, int len, BOOL bDelete /*= FALSE*/)
{
	ASSERT(buffer);
	if (m_bDelete) {
		Destory();
	}
	if (len < 0) {
		ASSERT(FALSE);
		len = 0;
	}
	m_bDelete = bDelete;
	m_nSeek = 0;
	m_pBuffer = (BYTE *) buffer;
	m_cbMaxLen = m_nLen = len;
	return len;
}

void CAutoMem::Destory()
{
	if (m_bDelete) 
	{
		if (m_nLen == 1 && m_pBuffer != NULL) 
		{
			delete m_pBuffer;
		} 
		else if (m_nLen > 1 && m_pBuffer != NULL) 
		{
			delete [] m_pBuffer;
		} 
		else if (m_pBuffer != NULL) 
		{
			delete m_pBuffer;
		}
	}
	else 
	{
		m_pBuffer = NULL;
	}
	m_pBuffer = NULL;
	m_nLen = 0;
	m_nSeek = 0;
	m_cbMaxLen = 0;
}

// Ԥ�����ڴ档
static const int realloc_step = 64;

BOOL CAutoMem::ChgLen(int nNewLen)
{
	if (nNewLen < 0)
	{
		return FALSE;
	}

	if (nNewLen == GetLen()) 
	{
		SeekToBegin();
		return TRUE;
	}

	if (m_cbMaxLen < nNewLen)
	{
		// ��Ҫ���·����ڴ棬���Ѿɵ����ݿ������µ����ݡ������α굽��ʼλ��
		//
		// ����һ���ֲ��������ڶ���
		// ָ�����CAutoMem�ڲ��Ļ��������ͷţ�ע�����Init����FALSE������
		int alloc_cnt = nNewLen;
		// ÿ���������ȶ���realloc_stepΪ��λ���������롣��������Ϊ�˱����ڲ���С���ڴ��ʱ���ظ������ڴ档
		if (nNewLen - m_cbMaxLen < realloc_step)
		{
			alloc_cnt = m_cbMaxLen + realloc_step;
		}

		CAutoMem mem;
		mem.Init(alloc_cnt, FALSE); 
		SeekToBegin();
		ASSERT(m_nLen < alloc_cnt);
		Read(mem.GetBuffer(), GetLen());
		// ��������Ȼ��Attach���ֲ������Ļ������С�
		Destory();
		if (mem.GetLen()) 
		{
			// ATTACH���������ͷţ�ע�����TRUE������
			// m_nLen = nNewLen
			// m_cbMaxLen = alloc_cnt
			Attach(mem.GetBuffer(), nNewLen, TRUE); 
			m_cbMaxLen = alloc_cnt;
		}
	}
	else 
	{
		if (nNewLen > m_nLen) 
		{
			// ����м��λ��Ϊ0
			if (m_bZero)
			{
				ZeroMemory(GetBuffer() + m_nLen, nNewLen - m_nLen);
			}
		}

		if (nNewLen == 0) 
		{
			Destory();
		}
		m_nLen = nNewLen;
		SeekToBegin();
	}
	return TRUE;
}

int CAutoMem::WriteMust(const void *buf, int len)
{
	if (GetNoUseLen() < len){
		ChgLenAndSeek(GetCurSeek() + len, GetCurSeek());
	}
	return Write(buf, len);
}

#define CHECK_TESTSUIT_RET(b) if(!(b)) return FALSE;
BOOL TestSuit_CAutoMem()
{
	{
		CAutoMem mem;
		// Seek & change len & read/write.
		mem.ChgLen(1);
		CHECK_TESTSUIT_RET(1 == mem.WriteByte(139));
		mem.SeekToBegin();
		CHECK_TESTSUIT_RET(139 == mem.ReadByte());

		mem.ChgLen(2);
		CHECK_TESTSUIT_RET(139 == mem.ReadByte());
		CHECK_TESTSUIT_RET(0 == mem.ReadByte());


		mem.ChgLenAndSeek(4, 2);
		CHECK_TESTSUIT_RET(mem.GetCurSeek() == 2);
		CHECK_TESTSUIT_RET(2 == mem.WriteUSHORT(65535));
		CHECK_TESTSUIT_RET(4 == mem.GetCurSeek());

		// ��дԽ����ԣ�����mem�������������Լ�������д���ݿ����᲻�������
		CHECK_TESTSUIT_RET(0 == mem.WriteUSHORT(123));
		CHECK_TESTSUIT_RET(4 == mem.GetCurSeek() && 4 == mem.GetLen() && 0 == mem.GetNoUseLen());
		CHECK_TESTSUIT_RET(0 == mem.ReadUShort());
		CHECK_TESTSUIT_RET(4 == mem.GetCurSeek() && 4 == mem.GetLen() && 0 == mem.GetNoUseLen());

		mem.SeekToBegin();
		CHECK_TESTSUIT_RET(139 == mem.ReadByte());
		CHECK_TESTSUIT_RET(0 == mem.ReadByte());
		CHECK_TESTSUIT_RET(65535 == mem.ReadUShort());
		CHECK_TESTSUIT_RET(4 == mem.GetCurSeek() && 4 == mem.GetLen() && 0 == mem.GetNoUseLen());

		// ����ڴ�Ĳ��ԡ�
		mem.ChgLenAndSeek(1111, 4);
		CHECK_TESTSUIT_RET(1111 == mem.GetLen() && 1111 - 4 == mem.GetNoUseLen());
		mem.SeekToBegin();
		CHECK_TESTSUIT_RET(139 == mem.ReadByte());
		CHECK_TESTSUIT_RET(0 == mem.ReadByte());
		CHECK_TESTSUIT_RET(65535 == mem.ReadUShort());
		CHECK_TESTSUIT_RET(4 == mem.GetCurSeek() && 1111 == mem.GetLen() && 1111-4 == mem.GetNoUseLen());
	}

	//����������ٲ��ԣ����๹�캯��
	//Attach��Destory
	{
		CAutoMem mem;
		mem.Init(411);
		CHECK_TESTSUIT_RET(NULL != mem.GetBuffer() && 411 == mem.GetLen() && 411 == mem.GetNoUseLen() && 0 == mem.GetCurSeek());
		mem.Destory();
		CHECK_TESTSUIT_RET(NULL == mem.GetBuffer() && 0 == mem.GetLen() && 0 == mem.GetNoUseLen() && 0 == mem.GetCurSeek());
	}

	{
		CAutoMem mem(411, FALSE);
		CHECK_TESTSUIT_RET(NULL != mem.GetBuffer() && 411 == mem.GetLen() && 411 == mem.GetNoUseLen() && 0 == mem.GetCurSeek());
		BYTE* pBuf = mem.GetBuffer();
		mem.Destory();
		CHECK_TESTSUIT_RET(NULL == mem.GetBuffer() && 0 == mem.GetLen() && 0 == mem.GetNoUseLen() && 0 == mem.GetCurSeek());
		try
		{
			// ���������� - ����C++�쳣����Ҫ����Ϊ���ǣ����� SEH �쳣 (/EHa)��
			// ������������ڴ�ʱ�����޷���׽���쳣��
			CHECK_TESTSUIT_RET(*(unsigned long*)pBuf == 0);
			delete [] pBuf;
		}
		catch(...)
		{
			return FALSE;
		}
	}

	{
		//CopyTo��Clone��NewMem
		CAutoMem mem(411);
		mem.WriteUINT(1234);
		CAutoMem mem2;
		mem.CopyTo(&mem2);
		CHECK_TESTSUIT_RET(NULL != mem2.GetBuffer() && 411 == mem2.GetLen() && 411 == mem2.GetNoUseLen() && 0 == mem2.GetCurSeek());
		CHECK_TESTSUIT_RET(1234 == mem2.ReadUInt());

		CAutoMem* pmem3 = mem.Clone();
		CHECK_TESTSUIT_RET(NULL != pmem3);
		CHECK_TESTSUIT_RET(NULL != pmem3->GetBuffer());
		CHECK_TESTSUIT_RET(pmem3->GetCurSeek() == 4);
		pmem3->SeekToBegin();
		CHECK_TESTSUIT_RET(pmem3->ReadUInt() == 1234);
		delete pmem3;

		CAutoMem* pMem4 = CAutoMem::NewMem(311);
		CHECK_TESTSUIT_RET(pMem4 != NULL 
			&& NULL != pMem4->GetBuffer() 
			&& 311 == pMem4->GetLen() 
			&& 311 == pMem4->GetNoUseLen() 
			&& 0 == pMem4->GetCurSeek());
		pMem4->WriteUINT(1234);
		pMem4->SeekToBegin();
		CHECK_TESTSUIT_RET(pMem4->ReadUInt() == 1234);
		delete pMem4;
	}

	// �ַ�������
	// WriteStr
	{
		CAutoMem mem;
		const wchar_t* pStr = L"WriteStr ReadLenString WriteLenString ReadLenStringA WriteLenStringA";
		// δ����ռ䣬Ӧ��д��ʧ�ܡ�
		CHECK_TESTSUIT_RET(0 == mem.WriteStr(pStr));
		mem.ChgLenAndSeek(4, 0);
		// Խ�磨�ضϣ���⣬�ܳ���Ϊ4������ֻ��д��һ�����ַ���L'\0'��
		CHECK_TESTSUIT_RET(4 == mem.WriteStr(pStr));
		CHECK_TESTSUIT_RET(4 == mem.GetCurSeek());
		mem.SeekToBegin();
		CHECK_TESTSUIT_RET((USHORT)L'W' == mem.ReadUShort());
		CHECK_TESTSUIT_RET(0 == mem.ReadShort());
		// ���ڸ�������Ŀռ�
		mem.ChgLenAndSeek(256, 0);
		int cbSize = sizeof(wchar_t) * (wcslen(pStr) + 1);
		CHECK_TESTSUIT_RET(cbSize == mem.WriteStr(pStr));
		CHECK_TESTSUIT_RET(0 == wcscmp((const wchar_t*)mem.GetBuffer(), pStr));
	}

	// �ַ�������
	// ReadLenString WriteLenString ReadLenStringA WriteLenStringA
	{
		// ��ͨ�ַ���
		{
			CAutoMem mem;
			const wchar_t* pStr = L"WriteStr ReadLenString WriteLenString ReadLenStringA WriteLenStringA";
			mem.WriteLenString(pStr);
			CHECK_TESTSUIT_RET(wcslen(pStr)*sizeof(wchar_t) + 2 == mem.GetLen());
			CHECK_TESTSUIT_RET(wcslen(pStr)*sizeof(wchar_t) + 2 == mem.GetCurSeek());
			mem.SeekToBegin();
			wstring t = mem.ReadLenString();
			CHECK_TESTSUIT_RET(0 == wcscmp(pStr, t.c_str()));
		}

		{
			CAutoMem mem;
			const char* pStr = "WriteStr ReadLenString WriteLenString ReadLenStringA WriteLenStringA";
			mem.WriteLenStringA(pStr);
			CHECK_TESTSUIT_RET(strlen(pStr) + 2 == mem.GetLen());
			CHECK_TESTSUIT_RET(strlen(pStr) + 2 == mem.GetCurSeek());
			mem.SeekToBegin();
			string t = mem.ReadLenStringA();
			CHECK_TESTSUIT_RET(0 == strcmp(pStr, t.c_str()));
		}

		//���ַ�������ָ��
		{
			CAutoMem mem;
			const wchar_t* pStr = NULL;
			mem.WriteLenString(pStr);
			CHECK_TESTSUIT_RET(2 == mem.GetLen());
			CHECK_TESTSUIT_RET(2 == mem.GetCurSeek());

			wstring t = mem.ReadLenString();
			CHECK_TESTSUIT_RET(t.empty());
		}
		{
			CAutoMem mem;
			const char* pStr = NULL;
			mem.WriteLenStringA(pStr);
			CHECK_TESTSUIT_RET(2 == mem.GetLen());
			CHECK_TESTSUIT_RET(2 == mem.GetCurSeek());

			string t = mem.ReadLenStringA();
			CHECK_TESTSUIT_RET(t.empty());
		}
	}
	return TRUE;
}
