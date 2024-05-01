#include "Basic.h"

//全局placement new和全局placement delete的实现
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
