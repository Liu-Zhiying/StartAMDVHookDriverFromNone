#include "PageTable.h"
#include <intrin.h>

#pragma code_seg()
void GetPageTableBaseVirtualAddress(PTR_TYPE* pPxeOut)
{
	//��ȡCr3������ַ��ʹ��Windows�ں˺���ת��Ϊ�����ַ
	//ע�⣺MmGetVirtualForPhysical��΢�����Ϊ����������������ɶҲû��
	PTR_TYPE pxePhyAddr = __readcr3();
	pxePhyAddr &= 0xFFFFFFFFFFFFF000;

	PTR_TYPE testAddr = NULL;
	PTR_TYPE testPhyAddr = NULL;
	BOOLEAN matchedPxe = FALSE;

	//ͨ�������ڴ�ҳ���������ַȷ����ӳ��ҳ�����
	PTR_TYPE index = 0;
	for (index = 0; index < 0x200; index++)
	{
		//������ܵ�pxe��ַ
		testAddr = 0xFFFF000000000000;
		testAddr |= index << 39 | index << 30 | index << 21 | index << 12;

		//ȷ�Ͽ��Զ�
		if (MmIsAddressValid((PVOID)testAddr))
		{
			// MmIsAddressValid ֻ�ԷǷ�ҳ ���� ҳ�� һ���� �Ƿ�ҳ�ڴ� ֱ��ͨ����Χȷ����Pxe����
			testPhyAddr = MmGetPhysicalAddress((PVOID)testAddr).QuadPart;

			if (testPhyAddr == pxePhyAddr)
			{
				matchedPxe = TRUE;
				break;
			}
		}
	}

	if (!matchedPxe)
	{
		KdPrint(("Unmatched PXE\n"));
		return;
	}

	*pPxeOut = testAddr;

	/*

	�ϰ���룬ʹ����΢���ı���API

	PHYSICAL_ADDRESS temp = {};
	temp.QuadPart = (PTR_TYPE)pxePhyAddr;

	PTR_TYPE* pxeVirtualAddr = (PTR_TYPE*)MmGetVirtualForPhysical(temp);
	if (pxeVirtualAddr == NULL)
	{
		*pPxeOut = NULL;
		return;
	}

	*pPxeOut = (PTR_TYPE)pxeVirtualAddr;

	*/

	//��ʾ���
	KdPrint(("PXE: 0x%llx\n", *pPxeOut));
	KdPrint(("PPE: 0x%llx\n", (*pPxeOut) & 0xFFFFFFFFFFE00000));
	KdPrint(("PDE: 0x%llx\n", (*pPxeOut) & 0xFFFFFFFFC0000000));
	KdPrint(("PTE: 0x%llx\n", (*pPxeOut) & 0xFFFFFF8000000000));

	return;
}

#pragma code_seg()
NTSTATUS AllocPageTableInfoBlock(PT_G_INFO* pPtGInfo, PVOID* pNewBlockOut)
{
	//cas ������ƣ���ͬ
	while (InterlockedCompareExchange(&pPtGInfo->lockFlag, 1, 0)) continue;
	//�ڴ��tag�������ڴ�й©����
	ULONG tag = MAKE_TAG('p', 't', '_', '0');
	//�ϰ汾Windows��Ҫ�޸�
	PTR_TYPE* pMem = (PTR_TYPE*)ExAllocatePool2(POOL_FLAG_NON_PAGED, PAGE_SIZE, tag);
	if (pMem == NULL)
	{
		InterlockedDecrement(&pPtGInfo->lockFlag);
		return STATUS_RESOURCE_NOT_OWNED;
	}
	else
	{
		*pNewBlockOut = pMem;
		RtlZeroMemory(pMem, PAGE_SIZE);
		InterlockedDecrement(&pPtGInfo->lockFlag);
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
	//�ڴ��ͷ�tag
	ULONG tag = MAKE_TAG('p', 't', '_', '0');
	ExFreeMem(pBlock, tag);
}

#pragma code_seg()
NTSTATUS InitGlobalNewPageTableInfo(PT_G_INFO* pPtGInfo)
{
	GetPageTableBaseVirtualAddress(&pPtGInfo->pPxe);
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
	pPtGInfo->pArrInfoList = NULL;
	pPtGInfo->pPxe = NULL;
}

BOOLEAN ComparePtInfo(const PT_INFO* pPtInfo1, const PT_INFO* pPtInfo2)
{
	return pPtInfo1->phyAddressThis == pPtInfo2->phyAddressThis &&
		pPtInfo1->virtAddressMapping == pPtInfo2->virtAddressMapping &&
		pPtInfo1->virtAddressThis == pPtInfo2->virtAddressThis;
}

BOOLEAN InsertPageTableInfo(PT_G_INFO* pPtGInfo, const PT_INFO* pPtInfo)
{
	BOOLEAN bResult = FALSE;
	while (InterlockedCompareExchange(&pPtGInfo->lockFlag, 1, 0)) continue;
	PTR_TYPE* pStartBlock = (PTR_TYPE*)pPtGInfo->pArrInfoList, * pEndBlock = pStartBlock;
	do
	{
		PTR_TYPE count = (PTR_TYPE) * (pStartBlock + 2);
		PT_INFO* pPtInfoStart = (PT_INFO*)(pStartBlock + 3);
		if ((PAGE_SIZE - sizeof * pPtInfoStart * (count + 1)) > sizeof * pPtInfoStart)
		{
			bResult = TRUE;
			pPtInfoStart[count + 1] = *pPtInfo;
			++(*(pStartBlock + 2));
		}
		pStartBlock = (PTR_TYPE*)*pStartBlock;
	} while (pStartBlock != pEndBlock);
	InterlockedDecrement(&pPtGInfo->lockFlag);
	return bResult;
}

BOOLEAN RemovePageTableInfo(PT_G_INFO* pPtGInfo, const PT_INFO* pPtInfo)
{
	BOOLEAN bResult = FALSE;
	while (InterlockedCompareExchange(&pPtGInfo->lockFlag, 1, 0)) continue;
	PTR_TYPE* pStartBlock = (PTR_TYPE*)pPtGInfo->pArrInfoList, * pEndBlock = pStartBlock;
	do
	{
		PTR_TYPE index = 0, count = (PTR_TYPE) * (pStartBlock + 2);
		PT_INFO* pPtInfoStart = (PT_INFO*)(pStartBlock + 3);
		while (index < count)
		{
			if (ComparePtInfo(&pPtInfoStart[index], pPtInfo))
			{
				bResult = TRUE;
				PTR_TYPE copyBytes = sizeof * pPtInfoStart * (count - index - 1);
				if (copyBytes)
					RtlCopyMemory(&pPtInfoStart[index], &pPtInfoStart[index + 1], copyBytes);
			}
			++index;
		}
		pStartBlock = (PTR_TYPE*)*pStartBlock;
	} while (pStartBlock != pEndBlock);
	InterlockedDecrement(&pPtGInfo->lockFlag);
	return bResult;
}