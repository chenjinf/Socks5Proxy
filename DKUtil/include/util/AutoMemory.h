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
	 * 初始化，如参数len不为0则申请一块内存，并将长度设置为它。
	 * 如已有内容，则会销毁原有内容。
	 *
	 * \param len 新缓冲区长度。注意新申请的缓冲区长度最大长度不一定为len，内部会进行补齐。
	 * \param bDelete 如设置为TRUE则当此对象析构时销毁内部缓冲区，否则不会释放。这个参数默认为TRUE。
	 */
	void Init(int len = 0, BOOL bDelete = TRUE);

	/**
	 * 把一段内存赋予当前对象，设置当前对象的长度和最大长度为它的长度。
	 * 在赋予当前对象之前重置内部成员，如当前对象已有内存缓冲区，则根据m_bDelete标志决定是否释放掉当前的内存。
	 * 注意Attach调用后游标被设置到开始位置了。
	 * 
	 * \param buffer 需要附加的内存。
	 * \param len 新内存缓冲区的长度，这个值必须大于等于0。
	 * \param bDelete 当这个类销毁时,是否要delete这段内存.
	 * \return 返回新长度
	 */
	int Attach(const void *buffer, int len, BOOL bDelete = FALSE);

	/**
	 * 销毁所有内存，清空一切数据。当m_bDelete = TRUE时会释放内部缓冲区。
	 */
	void Destory();

	/**
	 * 拷贝自身所有内容（不受游标影响）到参数指定的对象。
	 * 注意：目标对象将被重置。目标缓冲会重新申请且大小等于this对象缓冲区的大小，同时目标对象的游标将被设置为0。
	 */
	BOOL CopyTo(CAutoMem * pMem);

	/**
	 * new一个CWtMem对象并将自身内容拷贝一份给它。返回的这个对象必须由调用者手动delete释放它。
	 * 注意！Clone会将目标的游标设置为和this对象一样的位置。
	 */
	CAutoMem *Clone();

	/**
	 * 创建一个指定长度的对象。返回的这个对象必须由调用者手动delete释放它。注意新对象的游标被设置为0。
	 */
	static CAutoMem *NewMem(int nLen = 0);

	/**
	 * 创建一个指定长度的对象，并用缓冲区buf初始化它。返回的这个对象必须由调用者手动delete释放它。注意新对象的游标被设置为0。
	 */
	static CAutoMem *NewMem(const void *buf, int nLen);

	void ZeroMem(){ memset(m_pBuffer, 0, m_nLen); }
public:
	int GetLen(){ return m_nLen; }
	
	int GetCurSeek(){ return m_nSeek; }

	BYTE* GetBuffer(){ return m_pBuffer; }
	BYTE* GetCurBuffer() { return (m_pBuffer + m_nSeek); }

	//当这个类销毁时,是否要delete这段内存.
	void SetDelete(BOOL bDelete){ m_bDelete = bDelete; }

	enum { begin = 1, current, end };

	int SeekToBegin();

	int SeekToEnd();

	int Seek(int nSeek, int nType = current);

	/**
	 * 写入参数len指定长度的数据，如果空间不足则只填充剩余可用空间。
	 * 返回实际写入的长度。
	 */
	int Write(const void *buffer, int len);

	/**
	 * 写入参数len指定长度的数据，如果长度不够就添加长度。
	 * 返回实际写入的长度，此返回值应等于len。
	 */
	int WriteMust(const void *buf, int len);

	/**
	 * Write系列函数，往内部缓冲区中填写指定类型的数据。
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
	 * 写入一个字符串，包括字符串尾部的L'\0'也一块写入。
	 * 由于需要写入L'\0'所以需要可用缓冲区大小必须>2，否则将直接返回0。
	 * 同时，如果缓冲区空间不足则会截断字符串。
	 * 
	 * \param lpsz 需要写入的字符串，此字符串不能为空，否则将直接返回0。
	 * \return 返回已写入的长度。
	 */
	int WriteStr(const wchar_t* lpsz);

	/**
	 * 读取一段(从游标位置开始的)数据到参数指定的目标缓冲区中。
	 * 当剩余内容不足时则返回实际读取的长度，例如当游标已经在尾部时返回0。
	 * 读取成功后游标自动移动到已读取缓冲区的尾部。
	 *
	 * \param buffer 将游标所在位置开始的一段内存读取到这里。
	 * \param len 希望读取的长度。
	 * \return 返回实际读取的长度。
	 */
	int Read(void *buffer, int len);

	/**
	 * Read系列函数，注意如果即游标在末尾，则返回值为0。所以调用者必须在调用这一系列函数前必须判断游标位置
	 * ，否则难以判断是游标在末尾，还是游标当前位置的值为0.
	 * 如带有bLowBit参数则用它表示字节序，如果bLowBit=true，说明高字节在高地址而低字节在低地址（编译器默认
	 * 的字节序），否则相反。
	 */
	int ReadInt( bool bLowBit = true );
	UINT ReadUInt(bool bLowBit = true); 
	LONGLONG ReadLongLong( );
	short ReadShort( bool bLowBit = true);
	USHORT ReadUShort( bool bLowBit = true);
	BYTE ReadByte();

	/**
	 * 读写带长度的字符串。和其他Read系列函数一样，这个函数也会影响游标。
	 */
	wstring ReadLenString();
	string ReadLenStringA();

	/**
	 * 写入字符串，先写入字符串长度，再写入字符串内容。字符串内容不以0x0000结尾。
	 * 需要对应的ReadLenString/ReadLenStringA函数才能正确读出内容。
	 * 如果现有内存不足，会重新申请一块足够容纳字符串的内存缓冲区。将影响长度和游标，
	 * 游标将设置在字符串尾部的位置。
	 *
	 * \param lpsz 需要写入的字符串长度。如该参数为NULL或者字符串内容为空，则仅写入长度0x0000。
	 */
	void WriteLenString(const wchar_t* lpsz);
	void WriteLenStringA(const char * lpsz);


	/**
	 * 这个函数用于长度
	 * 修改长度为参数nNewLen指定的大小（必要时重新分配内存大小），并将游标重置到开始位置。
	 * 和Seek()不同，如当前长度小于新的长度则新增部分的内存将被初始化为0。
	 */
	BOOL ChgLen(int nNewLen);

	/**
	 * 修改长度为参数nNewLen指定的大小（必要时重新分配内存大小），并将游标设置到参数nSeekFromBegin指定的位置。
	 */
	BOOL ChgLenAndSeek(int nNewLen, int nSeekFromBegin);

	/**
	 * 返回没有操作的长度，即返回从游标位置到m_nLen的大小
	 */

	int GetNoUseLen(){ return m_nLen - m_nSeek; }

	//BOOL RealDataFromFile(const wchar_t* lpszFilePath);

	//改变内存的顺序,倒序
	static void ChgOrder(void *buffer, int len);

	//查找下一段内存,找不到返回-1
	int FindNext(void *buffer, int len, BOOL bFindBegin = FALSE);

	int Replace(void *bufferOld, void *buffernew, int len);

	BOOL StartsWith(const void *buf, int len);
private:
	  BYTE * m_pBuffer;
	  int m_nSeek;
	  int m_nLen;					//当前数据长度
	  int m_cbMaxLen;				//可存储的最大长度，即分配内存m_pBuffer时指定的长度。
	  BYTE m_bDelete;
	  BYTE m_bZero;
};

BOOL TestSuit_CAutoMem();