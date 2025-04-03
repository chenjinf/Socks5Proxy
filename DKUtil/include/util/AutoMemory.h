#pragma once

#include <string>

using std::wstring;
using std::string;

#ifndef OUT
#define OUT
#endif

class CAutoMem
{
public:
	explicit CAutoMem(int len = 0, BOOL bDelete = TRUE, BOOL bZero = TRUE);
	explicit CAutoMem(const void *buffer, int len , bool bDelete, BOOL bZero = TRUE);
	~CAutoMem();
public:
	/**
	 * ��ʼ���������len��Ϊ0������һ���ڴ棬������������Ϊ����
	 * ���������ݣ��������ԭ�����ݡ�
	 *
	 * \param len �»��������ȡ�ע��������Ļ�����������󳤶Ȳ�һ��Ϊlen���ڲ�����в��롣
	 * \param bDelete ������ΪTRUE�򵱴˶�������ʱ�����ڲ������������򲻻��ͷš��������Ĭ��ΪTRUE��
	 */
	void Init(int len = 0, BOOL bDelete = TRUE);

	/**
	 * ��һ���ڴ渳�赱ǰ�������õ�ǰ����ĳ��Ⱥ���󳤶�Ϊ���ĳ��ȡ�
	 * �ڸ��赱ǰ����֮ǰ�����ڲ���Ա���統ǰ���������ڴ滺�����������m_bDelete��־�����Ƿ��ͷŵ���ǰ���ڴ档
	 * ע��Attach���ú��α걻���õ���ʼλ���ˡ�
	 * 
	 * \param buffer ��Ҫ���ӵ��ڴ档
	 * \param len ���ڴ滺�����ĳ��ȣ����ֵ������ڵ���0��
	 * \param bDelete �����������ʱ,�Ƿ�Ҫdelete����ڴ�.
	 * \return �����³���
	 */
	int Attach(const void *buffer, int len, BOOL bDelete = FALSE);

	/**
	 * ���������ڴ棬���һ�����ݡ���m_bDelete = TRUEʱ���ͷ��ڲ���������
	 */
	void Destory();

	/**
	 * ���������������ݣ������α�Ӱ�죩������ָ���Ķ���
	 * ע�⣺Ŀ����󽫱����á�Ŀ�껺������������Ҵ�С����this���󻺳����Ĵ�С��ͬʱĿ�������α꽫������Ϊ0��
	 */
	BOOL CopyTo(CAutoMem * pMem);

	/**
	 * newһ��CWtMem���󲢽��������ݿ���һ�ݸ��������ص������������ɵ������ֶ�delete�ͷ�����
	 * ע�⣡Clone�ὫĿ����α�����Ϊ��this����һ����λ�á�
	 */
	CAutoMem *Clone();

	/**
	 * ����һ��ָ�����ȵĶ��󡣷��ص������������ɵ������ֶ�delete�ͷ�����ע���¶�����α걻����Ϊ0��
	 */
	static CAutoMem *NewMem(int nLen = 0);

	/**
	 * ����һ��ָ�����ȵĶ��󣬲��û�����buf��ʼ���������ص������������ɵ������ֶ�delete�ͷ�����ע���¶�����α걻����Ϊ0��
	 */
	static CAutoMem *NewMem(const void *buf, int nLen);

	void ZeroMem(){ memset(m_pBuffer, 0, m_nLen); }
public:
	int GetLen(){ return m_nLen; }
	
	int GetCurSeek(){ return m_nSeek; }

	BYTE* GetBuffer(){ return m_pBuffer; }
	BYTE* GetCurBuffer() { return (m_pBuffer + m_nSeek); }

	//�����������ʱ,�Ƿ�Ҫdelete����ڴ�.
	void SetDelete(BOOL bDelete){ m_bDelete = bDelete; }

	enum { begin = 1, current, end };

	int SeekToBegin();

	int SeekToEnd();

	int Seek(int nSeek, int nType = current);

	/**
	 * д�����lenָ�����ȵ����ݣ�����ռ䲻����ֻ���ʣ����ÿռ䡣
	 * ����ʵ��д��ĳ��ȡ�
	 */
	int Write(const void *buffer, int len);

	/**
	 * д�����lenָ�����ȵ����ݣ�������Ȳ�������ӳ��ȡ�
	 * ����ʵ��д��ĳ��ȣ��˷���ֵӦ����len��
	 */
	int WriteMust(const void *buf, int len);

	/**
	 * Writeϵ�к��������ڲ�����������дָ�����͵����ݡ�
	 */
	int WriteByte(BYTE nByte){ return Write(&nByte, 1); }
	int WriteChar(char ch){ return Write(&ch, 1); }
	int WriteInt(int nInt){	return Write(&nInt, 4); }
	int WriteUINT(UINT n){ return Write(&n, 4); }
	int WriteUSHORT(USHORT nUshort){ return Write(&nUshort, 2); }
	int WriteShort(short nShort){ return Write(&nShort, 2); }
	int WriteLONGLONG(LONGLONG ll) { return Write(&ll, 8); }
	int WriteRand(int nSize);
	/**
	 * д��һ���ַ����������ַ���β����L'\0'Ҳһ��д�롣
	 * ������Ҫд��L'\0'������Ҫ���û�������С����>2������ֱ�ӷ���0��
	 * ͬʱ������������ռ䲻�����ض��ַ�����
	 * 
	 * \param lpsz ��Ҫд����ַ��������ַ�������Ϊ�գ�����ֱ�ӷ���0��
	 * \return ������д��ĳ��ȡ�
	 */
	int WriteStr(const wchar_t* lpsz);

	/**
	 * ��ȡһ��(���α�λ�ÿ�ʼ��)���ݵ�����ָ����Ŀ�껺�����С�
	 * ��ʣ�����ݲ���ʱ�򷵻�ʵ�ʶ�ȡ�ĳ��ȣ����統�α��Ѿ���β��ʱ����0��
	 * ��ȡ�ɹ����α��Զ��ƶ����Ѷ�ȡ��������β����
	 *
	 * \param buffer ���α�����λ�ÿ�ʼ��һ���ڴ��ȡ�����
	 * \param len ϣ����ȡ�ĳ��ȡ�
	 * \return ����ʵ�ʶ�ȡ�ĳ��ȡ�
	 */
	int Read(void *buffer, int len);

	/**
	 * Readϵ�к�����ע��������α���ĩβ���򷵻�ֵΪ0�����Ե����߱����ڵ�����һϵ�к���ǰ�����ж��α�λ��
	 * �����������ж����α���ĩβ�������α굱ǰλ�õ�ֵΪ0.
	 * �����bLowBit������������ʾ�ֽ������bLowBit=true��˵�����ֽ��ڸߵ�ַ�����ֽ��ڵ͵�ַ��������Ĭ��
	 * ���ֽ��򣩣������෴��
	 */
	int ReadInt( bool bLowBit = true );
	UINT ReadUInt(bool bLowBit = true); 
	LONGLONG ReadLongLong( );
	short ReadShort( bool bLowBit = true);
	USHORT ReadUShort( bool bLowBit = true);
	BYTE ReadByte();

	/**
	 * ��д�����ȵ��ַ�����������Readϵ�к���һ�����������Ҳ��Ӱ���αꡣ
	 */
	wstring ReadLenString();
	string ReadLenStringA();

	/**
	 * д���ַ�������д���ַ������ȣ���д���ַ������ݡ��ַ������ݲ���0x0000��β��
	 * ��Ҫ��Ӧ��ReadLenString/ReadLenStringA����������ȷ�������ݡ�
	 * ��������ڴ治�㣬����������һ���㹻�����ַ������ڴ滺��������Ӱ�쳤�Ⱥ��α꣬
	 * �α꽫�������ַ���β����λ�á�
	 *
	 * \param lpsz ��Ҫд����ַ������ȡ���ò���ΪNULL�����ַ�������Ϊ�գ����д�볤��0x0000��
	 */
	void WriteLenString(const wchar_t* lpsz);
	void WriteLenStringA(const char * lpsz);


	/**
	 * ����������ڳ���
	 * �޸ĳ���Ϊ����nNewLenָ���Ĵ�С����Ҫʱ���·����ڴ��С���������α����õ���ʼλ�á�
	 * ��Seek()��ͬ���統ǰ����С���µĳ������������ֵ��ڴ潫����ʼ��Ϊ0��
	 */
	BOOL ChgLen(int nNewLen);

	/**
	 * �޸ĳ���Ϊ����nNewLenָ���Ĵ�С����Ҫʱ���·����ڴ��С���������α����õ�����nSeekFromBeginָ����λ�á�
	 */
	BOOL ChgLenAndSeek(int nNewLen, int nSeekFromBegin);

	/**
	 * ����û�в����ĳ��ȣ������ش��α�λ�õ�m_nLen�Ĵ�С
	 */

	int GetNoUseLen(){ return m_nLen - m_nSeek; }

	//BOOL RealDataFromFile(const wchar_t* lpszFilePath);

	//�ı��ڴ��˳��,����
	static void ChgOrder(void *buffer, int len);

	//������һ���ڴ�,�Ҳ�������-1
	int FindNext(void *buffer, int len, BOOL bFindBegin = FALSE);

	int Replace(void *bufferOld, void *buffernew, int len);

	BOOL StartsWith(const void *buf, int len);
private:
	  BYTE * m_pBuffer;
	  int m_nSeek;
	  int m_nLen;					//��ǰ���ݳ���
	  int m_cbMaxLen;				//�ɴ洢����󳤶ȣ��������ڴ�m_pBufferʱָ���ĳ��ȡ�
	  BYTE m_bDelete;
	  BYTE m_bZero;
};

BOOL TestSuit_CAutoMem();