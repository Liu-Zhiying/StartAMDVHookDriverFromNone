#include "Basic.h"

//全局placement new和全局placement delete的实现

void* operator new(size_t, void* pObj)
{
	return pObj;
}

void operator delete(void*, UINT64)
{
	return;
}
