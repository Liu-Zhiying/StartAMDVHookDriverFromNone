#include "PageTable.h"
#include <intrin.h>

const ULONG PT_TAG = MAKE_TAG('p', 't', 'm', ' ');

//获取页表基地址（虚拟地址）
#pragma code_seg("PAGE")
void GetSysPXEVirtAddr(PTR_TYPE* pPxeOut)
{
	PAGED_CODE();
	//读取Cr3物理地址并使用Windows内核函数转换为虚拟地址
	//注意：MmGetVirtualForPhysical被微软标记为保留，除了名字外啥也没提
	PTR_TYPE pxePhyAddr = __readcr3();
	pxePhyAddr &= 0xFFFFFFFFFFFFF000;

	PTR_TYPE testAddr = NULL;
	PTR_TYPE testPhyAddr = NULL;
	BOOLEAN matchedPxe = FALSE;

	//通过测试内存页面和物理地址确认自映射页表编号
	PTR_TYPE index = 0;
	for (index = 0; index < 0x200; index++)
	{
		//构造可能的pxe地址
		testAddr = 0xFFFF000000000000;
		testAddr |= index << 39 | index << 30 | index << 21 | index << 12;

		//确认可以读
		if (MmIsAddressValid((PVOID)testAddr))
		{
			// MmIsAddressValid 只对非分页 但是 页表 一定是 非分页内存 直接通过范围确认在Pxe表内
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
		*pPxeOut = NULL;
		return;
	}
	
	*pPxeOut = testAddr;
	
	/*

	老版代码，使用了微软的保留API

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

	//显示结果
	KdPrint(("GetWinPageTableVirtualAddr(): PXE: 0x%llx\n", *pPxeOut));
	KdPrint(("GetWinPageTableVirtualAddr(): PPE: 0x%llx\n", (*pPxeOut) & 0xFFFFFFFFFFE00000));
	KdPrint(("GetWinPageTableVirtualAddr(): PDE: 0x%llx\n", (*pPxeOut) & 0xFFFFFFFFC0000000));
	KdPrint(("GetWinPageTableVirtualAddr(): PTE: 0x%llx\n", (*pPxeOut) & 0xFFFFFF8000000000));

	return;
}

#pragma code_seg("PAGE")
template<typename EntryType>
void SetPageTableEntry(EntryType* pEntry, PTR_TYPE pfn)
{
	pEntry->fields.present = true;
	pEntry->fields.writeable = true;
	pEntry->fields.userAccess = true;
	pEntry->fields.size = false;
	pEntry->fields.pagePpn = pfn;
}

#pragma code_seg("PAGE")
PTR_TYPE GetPfnFromPhyAddr(PTR_TYPE phyAddr)
{
	return (PTR_TYPE)(phyAddr >> 12);
}

#pragma code_seg("PAGE")
NTSTATUS BuildNptPageTable(PTR_TYPE pPhysicalMemory, PTR_TYPE pNptPageTable, 
						   PTR_TYPE* pLevel4PageTable, KernelVector<PVOID>& nptPageTableVirtAddrs,
						   UINT32 level = 5)
{
	NTSTATUS status = STATUS_SUCCESS;

	switch (level)
	{
	case 5:
	{
		PPHYSICAL_MEMORY_RANGE pPhysicalMemoryRanges = MmGetPhysicalMemoryRanges();

		if (pPhysicalMemoryRanges == NULL)
		{
			status = STATUS_INSUFFICIENT_RESOURCES;
			break;
		}

		PageTableLevel4* pNptLevel4PageTable = (PageTableLevel4*)MmAllocateContiguousMemory(sizeof(PageTableLevel4), highestPhyAddr);

		if (pNptLevel4PageTable == NULL)
		{
			status = STATUS_INSUFFICIENT_RESOURCES;
			break;
		}

		RtlZeroMemory(pNptLevel4PageTable, sizeof(*pNptLevel4PageTable));
		nptPageTableVirtAddrs.PushBack((PVOID)pNptLevel4PageTable);

		for (SIZE_TYPE memoryRangeIdx = 0; pPhysicalMemoryRanges[memoryRangeIdx].BaseAddress.QuadPart != 0 ||
			pPhysicalMemoryRanges[memoryRangeIdx].NumberOfBytes.QuadPart != 0; ++memoryRangeIdx)
		{
			PTR_TYPE memoryRangeBeg = pPhysicalMemoryRanges[memoryRangeIdx].BaseAddress.QuadPart;
			PTR_TYPE memoryRangeEnd = memoryRangeBeg + pPhysicalMemoryRanges[memoryRangeIdx].NumberOfBytes.QuadPart;

			while (memoryRangeBeg < memoryRangeEnd)
			{
				status = BuildNptPageTable(memoryRangeBeg, (PTR_TYPE)pNptLevel4PageTable, NULL, nptPageTableVirtAddrs, level - 1);
				if (!NT_SUCCESS(status))
					break;
				memoryRangeBeg += PAGE_SIZE;
			}

			if (!NT_SUCCESS(status))
				break;
		}

		ApicBase apicBase = {};
		apicBase.data = __readmsr(IA32_MSR_APIC_BASE);
		status = BuildNptPageTable((PTR_TYPE)apicBase.data * PAGE_SIZE, (PTR_TYPE)pNptLevel4PageTable, NULL, nptPageTableVirtAddrs, level - 1);
		if (!NT_SUCCESS(status))
			break;

		if (NT_SUCCESS(status))
			*pLevel4PageTable = (PTR_TYPE)pNptLevel4PageTable;

		break;
	}
	case 4:
	{
		PageTableLevel4* pTable = (PageTableLevel4*)pNptPageTable;
		PageTableLevel23* pSubTable = NULL;
		PageTableLevel4Entry* pEntry = (PageTableLevel4Entry*)&pTable->entries[pPhysicalMemory >> 39];
		if (!pEntry->fields.present)
		{
			pSubTable = (PageTableLevel23*)MmAllocateContiguousMemory(sizeof(PageTableLevel23), highestPhyAddr);
			if (pSubTable == NULL)
			{
				status = STATUS_INSUFFICIENT_RESOURCES;
				break;
			}
			nptPageTableVirtAddrs.PushBack((PVOID)pSubTable);
			RtlIsZeroMemory(pSubTable, sizeof(PageTableLevel23));
			SetPageTableEntry(pEntry, GetPfnFromPhyAddr(MmGetPhysicalAddress(pSubTable).QuadPart));
		}
		if (NT_SUCCESS(status))
			status = BuildNptPageTable(pPhysicalMemory, (PTR_TYPE)pSubTable, pLevel4PageTable, nptPageTableVirtAddrs, level - 1);
		break;
	}
	case 3:
	case 2:
	{
		INT32 rightShiftCnt = level == 3 ? 30 : 21;
		PageTableLevel23* pTable = (PageTableLevel23*)pNptPageTable;
		PageTableLevel23* pSubTable = NULL;
		PageTableLevel123Entry* pEntry = (PageTableLevel123Entry*)&pTable->entries[pPhysicalMemory >> rightShiftCnt];
		if (!pEntry->fields.present)
		{
			pSubTable = (PageTableLevel23*)MmAllocateContiguousMemory(sizeof(PageTableLevel23), highestPhyAddr);
			if (pSubTable == NULL)
			{
				status = STATUS_INSUFFICIENT_RESOURCES;
				break;
			}
			nptPageTableVirtAddrs.PushBack((PVOID)pSubTable);
			RtlIsZeroMemory(pSubTable, sizeof(PageTableLevel23));
			SetPageTableEntry(pEntry, GetPfnFromPhyAddr(MmGetPhysicalAddress(pSubTable).QuadPart));
		}
		if (NT_SUCCESS(status))
			status = BuildNptPageTable(pPhysicalMemory, (PTR_TYPE)pSubTable, pLevel4PageTable, nptPageTableVirtAddrs, level - 1);
		break;
	}
	case 1:
	{
		PageTableLevel23* pTable = (PageTableLevel23*)pNptPageTable;
		PageTableLevel123Entry* pEntry = (PageTableLevel123Entry*)&pTable->entries[pPhysicalMemory >> 12];
		if (!pEntry->fields.present)
			SetPageTableEntry(pEntry, GetPfnFromPhyAddr(pPhysicalMemory));
		break;
	}
	}
	return status;
}

#pragma code_seg("PAGE")
NTSTATUS PageTableManager::Init()
{
	PAGED_CODE();
	NTSTATUS status = STATUS_SUCCESS;

	do
	{
		//获取Windows页表地址
		//Windows 10 1607之后有页表随机化，确认随机化之后的页表基址
		GetSysPXEVirtAddr(&pSystemPxe);
		if (pSystemPxe == NULL)
		{
			KdPrint(("PageTableManager::Init(): Can not find system PXE virtual address."));
			status = STATUS_INVALID_PARAMETER;
			break;
		}

		if (pNptPageTable == INVALID_NPT_PAGE_TABLE)
		{
			KeWaitForSingleObject(&operationLock, Executive, KernelMode, FALSE, NULL);

			do
			{
				nptPageTableVirtAddrs.Clear();
				//if (!NT_SUCCESS(BuildNptPageTable(highestPhyAddr.QuadPart, highestPhyAddr.QuadPart, 
				//								  &pNptPageTable, nptPageTableVirtAddrs)))
				//	break;
			} while (false);

			if (!NT_SUCCESS(status))
				DeinitImpl();

			KeReleaseMutex(&operationLock, FALSE);
		}

	} while (false);

	return status;
}

#pragma code_seg("PAGE")
void PageTableManager::Deinit()
{
	PAGED_CODE();

	if (pNptPageTable != INVALID_NPT_PAGE_TABLE)
	{
		KeWaitForSingleObject(&operationLock, Executive, KernelMode, FALSE, NULL);

		DeinitImpl();

		KeReleaseMutex(&operationLock, FALSE);
	}
}

#pragma code_seg("PAGE")
void PageTableManager::DeinitImpl()
{
	PAGED_CODE();

	KeWaitForSingleObject(&operationLock, Executive, KernelMode, FALSE, NULL);

	if (pNptPageTable != INVALID_NPT_PAGE_TABLE)
	{
		for (SIZE_T idx = 0; idx < nptPageTableVirtAddrs.Length(); ++idx)
			MmFreeContiguousMemory(nptPageTableVirtAddrs[idx]);
		pNptPageTable = INVALID_NPT_PAGE_TABLE;
	}

	nptPageTableVirtAddrs.Clear();

	KeReleaseMutex(&operationLock, FALSE);
}

#pragma code_seg("PAGE")
PTR_TYPE PageTableManager::GetNtpPageTable()
{
	PAGED_CODE();
	PTR_TYPE pRetValue = INVALID_NPT_PAGE_TABLE;

	KeWaitForSingleObject(&operationLock, Executive, KernelMode, FALSE, NULL);

	pRetValue = pNptPageTable;

	KeReleaseMutex(&operationLock, FALSE);

	return pRetValue;
}
