#include "Basic.h"

//ȫ��placement new��ȫ��placement delete��ʵ��
#pragma code_seg("PAGE")
void* operator new(size_t, void* pObj)
{
	PAGED_CODE();
	return pObj;
}

#pragma code_seg("PAGE")
void operator delete(void*, UINT64)
{
	PAGED_CODE();
	return;
}