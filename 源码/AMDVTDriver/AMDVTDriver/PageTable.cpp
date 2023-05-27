#include "PageTable.h"

#pragma code_seg()
void GetPageTableBaseVirtualAddress(PTR_TYPE* pPxeOut, PTR_TYPE* pageSizeOut)
{
	//读取Cr3物理地址并使用Windows内核函数转换为虚拟地址
	//注意：MmGetVirtualForPhysical被微软标记为保留，除了名字外啥也没提
	PTR_TYPE pxePhyAddr = ReadCr3();

	PHYSICAL_ADDRESS temp = {};
	temp.QuadPart = (PTR_TYPE)pxePhyAddr;

	PTR_TYPE* pxeVirtualAddr = (PTR_TYPE*)MmGetVirtualForPhysical(temp);
	if (pxeVirtualAddr == NULL)
	{
		*pPxeOut = NULL;
		return;
	}

	//这里开始 根据各级页表 的 LargePage 标志位 判断 Windows 当前的页面大小
	//这里我并没有让Windows开启大页模式（不过操作这种东西，错了肯定炸），在4k页普通模式下测试通过
	*pPxeOut = (PTR_TYPE)pxeVirtualAddr;

	PTR_TYPE pageSize = 0x40000000;
	UINT32 count = 2;

	do
	{
		UINT32 shrParam = (21 + count * 9);
		temp.QuadPart = (PTR_TYPE)pxeVirtualAddr[(*pPxeOut >> shrParam) & 0x1ff];
		temp.QuadPart = GET_PHY_BASEARRD_IN_PAGETABLE(temp.QuadPart);
		pxeVirtualAddr = (PTR_TYPE*)MmGetVirtualForPhysical(temp);
		if (count-- && !(pxeVirtualAddr[(*pPxeOut >> shrParam) & 0x1ff] & 0x80))
			pageSize >>= 9;
		else
			break;
	} while (true);

	*pageSizeOut = pageSize;

	//显示结果
	KdPrint(("PXE: 0x%llx\n", *pPxeOut));
	KdPrint(("PPE: 0x%llx\n", (*pPxeOut) & 0xFFFFFFFFFFE00000));
	KdPrint(("PDE: 0x%llx\n", (*pPxeOut) & 0xFFFFFFFFC0000000));
	KdPrint(("PTE: 0x%llx\n", (*pPxeOut) & 0xFFFFFF1000000000));
	KdPrint(("PageSize: 0x%llx\n", pageSize));
	return;
}

#pragma code_seg()
NTSTATUS AllocPageTableInfoBlock(const PT_G_INFO* pPtGInfo, PVOID* pNewBlockOut)
{
	ULONG tag = MAKE_TAG('p', 't', '_', '0');
	PTR_TYPE* pMem = (PTR_TYPE*)ExAllocatePool2(POOL_FLAG_NON_PAGED, pPtGInfo->pageSize, tag);
	if (pMem == NULL)
	{
		return STATUS_RESOURCE_NOT_OWNED;
	}
	else
	{
		*pNewBlockOut = pMem;
		RtlZeroMemory(pMem, pPtGInfo->pageSize);
		return STATUS_SUCCESS;
	}
}

#pragma code_seg()
void AttachPageTableInfoBlockToList(PT_G_INFO* pPtGInfo, PVOID pBlock)
{
	while (InterlockedCompareExchange(&pPtGInfo->lockFlag, 1, 0)) continue;
	PTR_TYPE* pNewBlockHead = (PTR_TYPE*)pBlock;
	PTR_TYPE* pBlockHeadInList = (PTR_TYPE*)pPtGInfo->pArrInfoList;
	if (pPtGInfo->pArrInfoList == NULL)
	{
		*pNewBlockHead = (PTR_TYPE)pNewBlockHead;
		*(pNewBlockHead + 1) = (PTR_TYPE)pNewBlockHead;
		pPtGInfo->pArrInfoList = (PTR_TYPE)pNewBlockHead;
	}
	else
	{
		*(pNewBlockHead + 1) = (PTR_TYPE)pBlockHeadInList;
		*pNewBlockHead = *pBlockHeadInList;
		*(((PTR_TYPE**)(*pNewBlockHead)) + 1) = pNewBlockHead;
		*pBlockHeadInList = (PTR_TYPE)pNewBlockHead;
	}
	InterlockedDecrement(&pPtGInfo->lockFlag);
}

#pragma code_seg()
BOOLEAN DetachPageTableInfoBlockToList(PT_G_INFO* pPtGInfo, PVOID pBlock)
{
	while (InterlockedCompareExchange(&pPtGInfo->lockFlag, 1, 0)) continue;
	PTR_TYPE* pBlockHeadLast = *((PTR_TYPE**)pBlock);
	PTR_TYPE* pBlockHeadNext = *(((PTR_TYPE**)pBlock) + 1);
	if (pBlockHeadNext == (PTR_TYPE*)pBlock && pBlockHeadLast == (PTR_TYPE*)pBlock)
	{
		InterlockedDecrement(&pPtGInfo->lockFlag);
		return FALSE;
	}
	*(pBlockHeadLast + 1) = (PTR_TYPE)pBlockHeadNext;
	*pBlockHeadNext = (PTR_TYPE)pBlockHeadLast;
	if (pBlock == (PVOID)pPtGInfo->pArrInfoList)
		pPtGInfo->pArrInfoList = (PTR_TYPE)pBlockHeadLast;
	InterlockedDecrement(&pPtGInfo->lockFlag);
	return TRUE;
}

#pragma code_seg()
void FreePageTableInfoBlock(const PT_G_INFO* pPtGInfo, PVOID pBlock)
{
	UNREFERENCED_PARAMETER(pPtGInfo);
	ULONG tag = MAKE_TAG('p', 't', '_', '0');
	ExFreeMem(pBlock, tag);
}

#pragma code_seg()
NTSTATUS InitGlobalNewPageTableInfo(PT_G_INFO* pPtGInfo)
{
	GetPageTableBaseVirtualAddress(&pPtGInfo->pPxe, &pPtGInfo->pageSize);
	InterlockedExchange(&pPtGInfo->lockFlag, 0);
	pPtGInfo->pArrInfoList = 0;
	return STATUS_SUCCESS;
}

void DestroyPageTableInfoBlockList(PT_G_INFO* pPtGInfo)
{
	PVOID pBlock = (PVOID)pPtGInfo->pArrInfoList;
	while (DetachPageTableInfoBlockToList(pPtGInfo, pBlock))
	{
		FreePageTableInfoBlock(pPtGInfo, pBlock);
		pBlock = (PVOID)pPtGInfo->pArrInfoList;
	}
	FreePageTableInfoBlock(pPtGInfo, pBlock);
	pPtGInfo->pageSize = 0;
	pPtGInfo->pArrInfoList = NULL;
	pPtGInfo->pPxe = NULL;
}
