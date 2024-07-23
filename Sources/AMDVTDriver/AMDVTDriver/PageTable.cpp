#include "PageTable.h"
#include <intrin.h>

#define GET_PFN_FROM_PHYADDR(phyAddr) (((phyAddr) >> 12) & 0xfffffff)
#define GET_PHYADDR_FROM_PFN(pfn) (((pfn) & 0xfffffff) << 12)
#define MUL_UNIT(value,rightShift) ((value) << (rightShift))

const ULONG PT_TAG = MAKE_TAG('p', 't', 'm', ' ');

//获取页表基地址（虚拟地址）
#pragma code_seg()
void GetSysPXEVirtAddr(PTR_TYPE* pPxeOut)
{
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

//页表条目填充
#pragma code_seg()
template<typename EntryType>
void SetPageTableEntry(EntryType* pEntry, PTR_TYPE pfn)
{
	pEntry->fields.present = true;
	pEntry->fields.writeable = true;
	pEntry->fields.userAccess = true;
	//pEntry->fields.size = false;
	pEntry->fields.pagePpn = pfn;
}

//level 0 （最低级别页表）的数据填充
#pragma code_seg()
NTSTATUS BuildNptPageTableeLevel1Impl(PageTableLevel123* pTable, PTR_TYPE startPhyAddr, PTR_TYPE endPhyAddr, PageTableRecords& records)
{
	UNREFERENCED_PARAMETER(records);
	constexpr PTR_TYPE rightShift = 12;
	constexpr PTR_TYPE unitMask1 = (static_cast<PTR_TYPE>(-1) << rightShift);
	constexpr PTR_TYPE unitMask2 = ~unitMask1;

	NTSTATUS status = STATUS_SUCCESS;

	do
	{
		if (endPhyAddr <= startPhyAddr)
		{
			status = STATUS_INVALID_PARAMETER;
			break;
		}

		PTR_TYPE startBase = startPhyAddr & unitMask1;
		PTR_TYPE startIdx = ((startPhyAddr >> rightShift) & 0x1ff);
		PTR_TYPE idxCnt = ((endPhyAddr - startBase) & unitMask1) >> rightShift;
		if ((endPhyAddr - startBase) & unitMask2)
			++idxCnt;
		PTR_TYPE endIdx = startIdx + idxCnt;

		if (endIdx > 0x200)
		{
			status = STATUS_INVALID_PARAMETER;
			break;
		}

		for (PTR_TYPE idx = startIdx; idx < endIdx; ++idx)
		{
			if (!pTable->entries[idx].fields.present)
				SetPageTableEntry(&pTable->entries[idx], GET_PFN_FROM_PHYADDR(startBase + MUL_UNIT(idx - startIdx, rightShift)));
		}
	} while (false);

	return status;
}

//Level 1 2 3 页表的创建，使用模板
#pragma code_seg()
template<typename TableType, typename SubTableType, PTR_TYPE rightShift, typename NextStep, NextStep nextStep>
NTSTATUS BuildNptPageTableLevel234Impl(TableType* pTable, PTR_TYPE startPhyAddr, PTR_TYPE endPhyAddr, PageTableRecords& records)
{
	NTSTATUS status = STATUS_SUCCESS;

	do
	{
		if (endPhyAddr <= startPhyAddr)
		{
			status = STATUS_INVALID_PARAMETER;
			break;
		}

		constexpr PTR_TYPE unitMask1 = (static_cast<PTR_TYPE>(-1) << rightShift);
		constexpr PTR_TYPE unitMask2 = ~unitMask1;
		PTR_TYPE startBase = startPhyAddr & unitMask1;
		PTR_TYPE startIdx = ((startPhyAddr >> rightShift) & 0x1ff);
		PTR_TYPE idxCnt = ((endPhyAddr - startBase) & unitMask1) >> rightShift;
		if ((endPhyAddr - startBase) & unitMask2)
			++idxCnt;
		PTR_TYPE endIdx = startIdx + idxCnt;

		if (endIdx > 0x200)
		{
			status = STATUS_INVALID_PARAMETER;
			break;
		}

		for (PTR_TYPE idx = startIdx; idx < endIdx; ++idx)
		{
			PTR_TYPE va = (PTR_TYPE)-1;
			//PTR_TYPE va = (PTR_TYPE)NULL;
			if (!pTable->entries[idx].fields.present)
			{
				SubTableType* pSubTable = (SubTableType*)MmAllocateContiguousMemory(sizeof *pSubTable, highestPhyAddr);
				if (pSubTable == NULL)
				{
					status = STATUS_INSUFFICIENT_RESOURCES;
					break;
				}

				va = (PTR_TYPE)pSubTable;
				PTR_TYPE pa = (PTR_TYPE)MmGetPhysicalAddress((PVOID)pSubTable).QuadPart;

				records.PushBack(PageTableRecord((PTR_TYPE)pSubTable, pa));

				SetPageTableEntry(&pTable->entries[idx], GET_PFN_FROM_PHYADDR(pa));

				RtlZeroMemory(pSubTable, sizeof *pSubTable);
			}
			else
			{
				//新建页表时记录了虚拟地址和物理地址
				//在记录项里面通过物理地址查找虚拟地址
				//避免了微软保留API的使用
				va = records.FindVaFromPa(GET_PHYADDR_FROM_PFN(pTable->entries[idx].fields.pagePpn));
				//PHYSICAL_ADDRESS addr = {};
				//addr.QuadPart = pTable->entries[idx].fields.pagePpn << 12;
				//va = (PTR_TYPE)MmGetVirtualForPhysical(addr);
			}

			if (va != -1)
			{
				PTR_TYPE newStartPhyAddr = startBase + MUL_UNIT(idx - startIdx, rightShift);
				PTR_TYPE newEndPhyAddr = newStartPhyAddr + MUL_UNIT(static_cast<PTR_TYPE>(1), rightShift);

				if (startPhyAddr > newStartPhyAddr)
					newStartPhyAddr = startPhyAddr;

				if (endPhyAddr < newEndPhyAddr)
					newEndPhyAddr = endPhyAddr;

				status = nextStep((SubTableType*)va, newStartPhyAddr, newEndPhyAddr, records);
				if (!NT_SUCCESS(status))
					break;
			}
		}

		if (!NT_SUCCESS(status))
			break;

	} while (false);

	return status;
}

using NPT_Level123_Processor = NTSTATUS(*)(PageTableLevel123*, PTR_TYPE, PTR_TYPE, PageTableRecords&);
using NPT_Level4_Processor = NTSTATUS(*)(PageTableLevel4*, PTR_TYPE, PTR_TYPE, PageTableRecords&);

//嵌套模板函数生成页表
constexpr NPT_Level123_Processor level1Processor = BuildNptPageTableeLevel1Impl;
constexpr NPT_Level123_Processor level2Processor = BuildNptPageTableLevel234Impl<PageTableLevel123, PageTableLevel123, 21, NPT_Level123_Processor, level1Processor>;
constexpr NPT_Level123_Processor level3Processor = BuildNptPageTableLevel234Impl<PageTableLevel123, PageTableLevel123, 30, NPT_Level123_Processor, level2Processor>;
constexpr NPT_Level4_Processor	 level4Processor = BuildNptPageTableLevel234Impl<PageTableLevel4, PageTableLevel123, 39, NPT_Level123_Processor, level3Processor>;

#pragma code_seg()
NTSTATUS BuildNptPageTable(PTR_TYPE* pLevel4PageTable, PageTableRecords& nptPageTableRecords)
{
	NTSTATUS status = STATUS_SUCCESS;

	do
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

		*pLevel4PageTable = (PTR_TYPE)pNptLevel4PageTable;

		RtlZeroMemory(pNptLevel4PageTable, sizeof(*pNptLevel4PageTable));

		for (SIZE_TYPE memoryRangeIdx = 0; pPhysicalMemoryRanges[memoryRangeIdx].BaseAddress.QuadPart != 0 ||
			pPhysicalMemoryRanges[memoryRangeIdx].NumberOfBytes.QuadPart != 0; ++memoryRangeIdx)
		{
			PTR_TYPE memoryRangeBeg = pPhysicalMemoryRanges[memoryRangeIdx].BaseAddress.QuadPart;
			PTR_TYPE memoryRangeEnd = memoryRangeBeg + pPhysicalMemoryRanges[memoryRangeIdx].NumberOfBytes.QuadPart;

			//从递归模板顶端调用函数生成页表
			status = level4Processor(pNptLevel4PageTable, memoryRangeBeg, memoryRangeEnd, nptPageTableRecords);
			if (!NT_SUCCESS(status))
				break;
		}

		if (!NT_SUCCESS(status))
			break;

		ApicBase apicBase = {};
		apicBase.data = __readmsr(IA32_MSR_APIC_BASE);
		PTR_TYPE startPhyAddr = apicBase.fields.apicBase * PAGE_SIZE;
		//瞎写的，没有参考CPU手册，写大些也没问题
		PTR_TYPE endPhyAddr = startPhyAddr + PAGE_SIZE * 16;

		status = level4Processor(pNptLevel4PageTable, startPhyAddr, endPhyAddr, nptPageTableRecords);
		if (!NT_SUCCESS(status))
			break;

	} while (false);

	return status;
}

#pragma code_seg()
bool PageTableManager::HandleNpf(VirtCpuInfo* pVirtCpuInfo, GenericRegisters* pGuestRegisters, PVOID pGuestVmcbPhyAddr, PVOID pHostVmcbPhyAddr)
{
	UNREFERENCED_PARAMETER(pGuestRegisters);
	UNREFERENCED_PARAMETER(pGuestVmcbPhyAddr);
	UNREFERENCED_PARAMETER(pHostVmcbPhyAddr);

	bool result = false;

	NpfExitInfo1 exitInfo = {};
	PTR_TYPE pa = pVirtCpuInfo->guestVmcb.controlFields.exitInfo2;
	exitInfo.data = pVirtCpuInfo->guestVmcb.controlFields.exitInfo1;

	if (!exitInfo.Fields.present)
	{
		PTR_TYPE paStart = pa - pa % PAGE_SIZE;
		PTR_TYPE paEnd = paStart + PAGE_SIZE;
		KIRQL oldIrql = {};

		KeAcquireSpinLock(&operationLock, &oldIrql);

		if (!NT_SUCCESS(level4Processor((PageTableLevel4*)pNptPageTable, paStart, paEnd, nptPageTableRecords)))
			KeBugCheck(MANUALLY_INITIATED_CRASH);

		KeReleaseSpinLock(&operationLock, oldIrql);

		result = true;
	}
	return result;
}

#pragma code_seg()
NTSTATUS PageTableManager::Init()
{
	NTSTATUS status = STATUS_SUCCESS;
	KIRQL oldIrql = {};

	KeAcquireSpinLock(&operationLock, &oldIrql);

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
			nptPageTableRecords.Clear();

			UINT64 ts = {}, te = {};

			KeQuerySystemTime(&ts);

			status = BuildNptPageTable(&pNptPageTable, nptPageTableRecords);

			KeQuerySystemTime(&te);

			KdPrint(("Elapsed time: %lld ns\n", (te - ts) * 100));

			if (!NT_SUCCESS(status))
			{
				KdPrint(("PageTableManager::Init(): BuildNptPageTable failed!"));
				break;
			}


			//level4Processor((PageTableLevel4*)pNptPageTable, 0xFFFFFFFFE000, 0xFFFFFFFFF000, nptPageTableRecords);

			

		}

	} while (false);

	if (!NT_SUCCESS(status))
		DeinitImpl();

	KeReleaseSpinLock(&operationLock, oldIrql);

	return status;
}

#pragma code_seg()
void PageTableManager::Deinit()
{
	KIRQL oldIrql = {};

	KeAcquireSpinLock(&operationLock, &oldIrql);

	DeinitImpl();

	KeReleaseSpinLock(&operationLock, oldIrql);
}

#pragma code_seg()
void PageTableManager::DeinitImpl()
{
	if (pNptPageTable != INVALID_NPT_PAGE_TABLE)
	{
		for (SIZE_TYPE idx = 0; idx < nptPageTableRecords.Length(); ++idx)
			MmFreeContiguousMemory((PVOID)nptPageTableRecords[idx].pVirtAddr);

		nptPageTableRecords.Clear();

		MmFreeContiguousMemory((PVOID)pNptPageTable);

		pNptPageTable = INVALID_NPT_PAGE_TABLE;
	}
}

#pragma code_seg()
PTR_TYPE PageTableManager::GetNtpPageTableVirtAddr()
{
	PTR_TYPE pRetValue = INVALID_NPT_PAGE_TABLE;
	KIRQL oldIrql = {};

	KeAcquireSpinLock(&operationLock, &oldIrql);

	pRetValue = pNptPageTable;

	KeReleaseSpinLock(&operationLock, oldIrql);

	return pRetValue;
}
