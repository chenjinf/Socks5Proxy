#include "windows.h"
#include "util/crypt.h"

const char enkey[] = "dxxikwoxnixbccvamiwopoikdnwdvnwezdelfgac";
void SimpleXor_Crype(char *dest, const char *src, int len)
{
	if ((dest == NULL )||(src == NULL)||(len <= 0))
	{
//		ASSERT(0);
		return;
	}

	int iKey = 0;

	__try
	{
		for (int i = 0; i != len; i++)
		{
			dest[i] = (src[i] ^ (enkey[iKey] + len));
			if (iKey == sizeof(enkey) - 1)
			{
				iKey = 0;
			}
			else
			{
				iKey++;
			}
		}
	}
	__except(EXCEPTION_EXECUTE_HANDLER)
	{
//		ASSERT(0);
	}
}

void tea_encry_32rounds(void *aData, const void *aKey) {
	const unsigned long cnDelta = 0x9E3779B9;
	register unsigned long y = ((unsigned long *) aData)[0], z = ((unsigned long *) aData)[1];
	register unsigned long sum = 0;
	unsigned long a = ((unsigned long *) aKey)[0], b = ((unsigned long *) aKey)[1];
	unsigned long c = ((unsigned long *) aKey)[2], d = ((unsigned long *) aKey)[3];
	int n = 32;
	while (n-- > 0) {
		sum += cnDelta;
		y += (z << 4) + (a ^ z) +( sum ^ (z >> 5)) + b;
		z += (y << 4) + (c ^ y) + (sum ^ (y >> 5)) + d;
	}
	((unsigned long *) aData)[0] = y;
	((unsigned long *) aData)[1] = z;
}

void tea_decry_32rounds(void *aData, const void *aKey) 
{
	const unsigned long cnDelta = 0x9E3779B9;
	register unsigned long y = ((unsigned long *) aData)[0], z = ((unsigned long *) aData)[1];
	register unsigned long sum = 0xC6EF3720;
	unsigned long a = ((unsigned long *) aKey)[0], b = ((unsigned long *) aKey)[1];
	unsigned long c = ((unsigned long *) aKey)[2], d = ((unsigned long *) aKey)[3];
	int n = 32;
	while (n-- > 0) {
		z -= ((y << 4) + (c ^ y) + (sum ^ (y >> 5)) + d);
		y -= (z << 4) + (a ^ z) + (sum ^ (z >> 5)) + b;
		sum -= cnDelta;
	}
	((unsigned long *) aData)[0] = y;
	((unsigned long *) aData)[1] = z;
}

void tea_encry(void *aData, const void *aKey) {
	//if (m_bOldVersion){
	//	return CWtTea::tea_encry(aData, aKey);
	//}
	const unsigned long cnDelta = 0x9E3579B9;
	register unsigned long y = ((unsigned long *) aData)[0], z = ((unsigned long *) aData)[1];
	register unsigned long sum = 0;
	unsigned long a = ((unsigned long *) aKey)[0], b = ((unsigned long *) aKey)[1];
	unsigned long c = ((unsigned long *) aKey)[2], d = ((unsigned long *) aKey)[3];
	int n = 8;
	while (n-- > 0) {
		sum += cnDelta;
		y += (z << 4) + (a ^ z) +( sum ^ (z >> 5)) + b;
		z += (y << 4) + (c ^ y) + (sum ^ (y >> 5)) + d;
	} 
	((unsigned long *) aData)[0] = y;
	((unsigned long *) aData)[1] = z;
}

//  解密 64 bit data
void tea_decry(void *aData, const void *aKey) {
	//if (m_bOldVersion){
	//	return CWtTea::tea_decry(aData, aKey);
	//}
	const unsigned long cnDelta = 0x9E3579B9;
	register unsigned long y = ((unsigned long *) aData)[0], z = ((unsigned long *) aData)[1];
	register unsigned long sum =  0xf1abcdc8;//cnDelta << static_cast<int>(logbase(2, 8));
	unsigned long a = ((unsigned long *) aKey)[0], b = ((unsigned long *) aKey)[1];
	unsigned long c = ((unsigned long *) aKey)[2], d = ((unsigned long *) aKey)[3];
	int n = 8;

	// sum = delta << 5, in general sum = delta * n
	while (n-- > 0) {
		z -= ((y << 4) + (c ^ y) + (sum ^ (y >> 5)) + d);
		y -= (z << 4) + (a ^ z) + (sum ^ (z >> 5)) + b;
		sum -= cnDelta;
	}
	((unsigned long *) aData)[0] = y;
	((unsigned long *) aData)[1] = z;
}


//key 128bit  16byte
void tea_encry(void *aData, int nLen, const void *aKey) 
{
	int nCount = nLen / 8;
	BYTE *pData = (BYTE *) aData;
	for (int i = 0; i < nCount; i++) {
		tea_encry(pData, aKey);
		pData += 8;
	}
	nCount = nLen % 8;
	for (int i = 0; i < nCount; i++) {
		*pData ^= 0xc7;
		*pData ^= *(((BYTE *) aKey) + i);
		pData++;
	}
}

void tea_decry(void *aData, int nLen, const void *aKey) 
{
	int nCount = nLen / 8;
	BYTE *pData = (BYTE *) aData;
	for (int i = 0; i < nCount; i++) {
		tea_decry(pData, aKey);
		pData += 8;
	}
	nCount = nLen % 8;
	for (int i = 0; i < nCount; i++) {
		*pData ^= *(((BYTE *) aKey) + i);
		*pData ^= 0xc7;
		pData++;
	}
}


bool TeaTEST()
{
#define testcnt (8 * 16)
	char mm1[testcnt];
	char mm3[testcnt];
	for (int i = 0; i!=sizeof(mm1); i++)
	{
		mm1[i] = i;
		mm3[i] = i;
	}

	char mm2[testcnt];
	char mm4[testcnt];
	memcpy(mm2, mm1, sizeof(mm1));
	memcpy(mm4, mm3, sizeof(mm3));

	for (int i = 0; i < sizeof(mm1)/8 ; i++){
		tea_encry(mm2 + i*8, "ksjflsjkflssjflsdjflsdffwoerupwe");
		tea_decry(mm2 + i*8, "ksjflsjkflssjflsdjflsdffwoerupwe");
		tea_encry_32rounds(mm4 + i*8, "ksjflsjkflssjflsdjflsdffwoerupwe");
		tea_decry_32rounds(mm4 + i*8, "ksjflsjkflssjflsdjflsdffwoerupwe");
	}

	if (memcmp(mm1, mm2, sizeof(mm1)) != 0)
	{
		return false;
	}

	if (memcmp(mm3, mm4, sizeof(mm3)) != 0)
	{
		return false;
	}

	return true;
}

//线性TEA，必须整个加解密, 预防相同数据得相同结果
void tea_encry_Line(void *aData, int nLen, const void *aKey, bool bLess)
{
	typedef void (*PFUNC)(void *, const void *);
	PFUNC pFunc = tea_encry ;
	if (bLess == false){
		pFunc = tea_encry_32rounds;
	}
	int nCount = nLen / 8;
	BYTE *pData = (BYTE *) aData;
	BYTE byKey[16];
	memcpy(byKey, aKey, 16);
	for (int i = 0; i < nCount; i++) {
		pFunc(pData, byKey);
		memcpy(byKey, pData, 8);	//使用加密后的数据作为密钥前64位
		pData += 8;
	}
	nCount = nLen % 8;
	for (int i = 0; i < nCount; i++) {
		*pData ^= 0xc7;
		*pData ^= *(((BYTE *) byKey) + i);
		pData++;
	}
}

void tea_decry_Line(void *aData, int nLen, const void *aKey, bool bLess)
{
	typedef void ( *PFUNC)(void *, const void *);
	PFUNC pFunc  = tea_decry;
	if (bLess == false){
		pFunc = tea_decry_32rounds;
	}

	int nCount = nLen % 8;
	BYTE *pData = (BYTE *) aData;
	pData += nLen/8 * 8;
	BYTE *pDataBegin = (BYTE*)aData;
	BYTE byKey[16];
	memcpy(byKey, aKey, 16);

	if (nCount != 0){	//处理最后几位
		if (pData - pDataBegin >= 8){
			memcpy(byKey, pData-8, 8);
		}else{
			memcpy(byKey, aKey, 8);
		}
		for (int i = 0; i < nCount ; i++){
			*pData ^= 0xc7;
			*pData ^= *(((BYTE *) byKey) + i);
			pData++;

		}
		pData = pDataBegin + nLen / 8 *8;
	}
	pData -=8;

	nCount = nLen / 8;
	for (int i = 0; i < nCount; i++) {
		if (pData - pDataBegin >= 8){
			memcpy(byKey, pData-8, 8);
		}else{
			memcpy(byKey, aKey, 8);
		}
		pFunc(pData, byKey);
		pData -= 8;
	}
}

