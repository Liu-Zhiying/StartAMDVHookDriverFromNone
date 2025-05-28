#include "Basic.h"

//ȫ��placement new��ȫ��placement delete��ʵ��
#pragma code_seg()
void* operator new(size_t, void* pObj)
{
	return pObj;
}

#pragma code_seg()
void operator delete(void*, UINT64)
{
	return;
}

//��װһ��Windows�ں��ڴ���亯��
#pragma code_seg()
PVOID AllocNonPagedMem(SIZE_TYPE byteCnt, ULONG tag)
{
#ifdef _BUILD_WIN_2004
	return ExAllocatePool2(POOL_FLAG_NON_PAGED, byteCnt, tag);
#else
	return ExAllocatePoolWithTag(POOL_TYPE::NonPagedPool, byteCnt, tag);
#endif
}

#pragma code_seg()
void FreeNonPagedMem(PVOID pMem, ULONG tag)
{
	ExFreePoolWithTag(pMem, tag);
}

#pragma code_seg()
PVOID AllocPagedMem(SIZE_TYPE byteCnt, ULONG tag)
{
#ifdef _BUILD_WIN_2004
	return ExAllocatePool2(POOL_FLAG_PAGED, byteCnt, tag);
#else
	return ExAllocatePoolWithTag(POOL_TYPE::PagedPool, byteCnt, tag);
#endif
}

#pragma code_seg()
void FreePagedMem(PVOID pMem, ULONG tag)
{
	ExFreePoolWithTag(pMem, tag);
}

#pragma code_seg()
PVOID AllocContiguousMem(SIZE_TYPE byteCnt, ULONG tag)
{
	UNREFERENCED_PARAMETER(tag);
	return MmAllocateContiguousMemory(byteCnt, HIGHEST_PHY_ADDR);
}

#pragma code_seg()
void FreeContigousMem(PVOID pMem, ULONG tag)
{
	UNREFERENCED_PARAMETER(tag);
	return MmFreeContiguousMemory(pMem);
}

#pragma code_seg()
PVOID AllocExecutableNonPagedMem(SIZE_TYPE byteCnt, ULONG tag)
{
#ifdef _BUILD_WIN_2004
	return ExAllocatePool2(POOL_FLAG_NON_PAGED_EXECUTE, byteCnt, tag);
#else
	return ExAllocatePoolWithTag(POOL_TYPE::NonPagedPoolExecute, byteCnt, tag);
#endif
}

#pragma code_seg()
void FreeExecutableNonPagedMem(PVOID pMem, ULONG tag)
{
	ExFreePoolWithTag(pMem, tag);
}

//��ѯ��ʽ�ȴ��ں˶����������Ŀǰû��ʹ�ã�
#pragma code_seg()
void WaitForSignleObjectInfinte(PVOID Object, KWAIT_REASON WaitReason, KPROCESSOR_MODE WaitMode, BOOLEAN Alertable)
{
	LARGE_INTEGER timeout = { 0 };
	NTSTATUS status = STATUS_SUCCESS;
	do
	{
		status = KeWaitForSingleObject(Object, WaitReason, WaitMode, Alertable, &timeout);
	} while (status != STATUS_SUCCESS);
}
