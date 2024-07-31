#include "PageTable.h"
#include <intrin.h>

constexpr ULONG PT_TAG = MAKE_TAG('p', 't', 'm', ' ');

#define GET_PFN_FROM_PHYADDR(phyAddr) (((phyAddr) >> 12) & 0xfffffff)
#define GET_PHYADDR_FROM_PFN(pfn) (((pfn) & 0xfffffff) << 12)
#define MUL_UNIT(value, rightShift) ((value) << (rightShift))

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

//页表条目填充
#pragma code_seg()
template<typename EntryType>
void SetPageTableEntry(EntryType* pEntry, PTR_TYPE pfn)
{
	EntryType entry = {};
	entry.fields.present = true;
	entry.fields.writeable = true;
	entry.fields.userAccess = true;
	entry.fields.pagePpn = pfn;
	*pEntry = entry;
}

//分配新的子页表并和当前页表项关联
#pragma code_seg()
template<typename EntryType, typename TableType>
NTSTATUS AllocNewPageTable(EntryType* fatherEntry, PageTableRecords& records, PTR_TYPE& va)
{
	NTSTATUS status = STATUS_SUCCESS;

	do
	{
		TableType* pSubTable = (TableType*)AllocNonPagedMem(sizeof * pSubTable, PT_TAG);
		if (pSubTable == NULL)
		{
			status = STATUS_INSUFFICIENT_RESOURCES;
			break;
		}

		va = (PTR_TYPE)pSubTable;
		PTR_TYPE pa = (PTR_TYPE)MmGetPhysicalAddress((PVOID)pSubTable).QuadPart;

		records.PushBack(PageTableRecord((PTR_TYPE)pSubTable, pa));

		SetPageTableEntry(fatherEntry, GET_PFN_FROM_PHYADDR(pa));

		RtlZeroMemory(pSubTable, sizeof * pSubTable);

	} while (false);

	return status;
}

#pragma warning(disable : 4127)
//*************************************页表构建函数开始*************************************

//高级别页表构建
#pragma code_seg()
template<typename TableType, typename SubTableType, PTR_TYPE level, bool checkLargePage, typename NextStep, NextStep nextStep>
NTSTATUS ProcessNptPageTableFrontLevelImpl(TableType* pTable, PTR_TYPE startPhyAddr, PTR_TYPE endPhyAddr, PageTableRecords& level123Records, PageTableRecords& level4Records)
{
	NTSTATUS status = STATUS_SUCCESS;

	do
	{
		if (endPhyAddr <= startPhyAddr)
		{
			status = STATUS_INVALID_PARAMETER;
			break;
		}

		constexpr PTR_TYPE rightShift = (level - 1) * 9 + 12;
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
			PTR_TYPE va = (PTR_TYPE)INVALID_ADDR;

			if (!pTable->entries[idx].fields.present)
			{
				if (level == 3)
					status = AllocNewPageTable<typename TableType::EntryType, SubTableType>(&pTable->entries[idx], level4Records, va);
				else
					status = AllocNewPageTable<typename TableType::EntryType, SubTableType>(&pTable->entries[idx], level123Records, va);
				if (!NT_SUCCESS(status))
					break;
			}
			else
			{
				//不处理大页
				if (checkLargePage && pTable->entries[idx].fields.size)
					return STATUS_SUCCESS;

				//新建页表时记录了虚拟地址和物理地址
				//在记录项里面通过物理地址查找虚拟地址
				//避免了微软保留API的使用

				if (level == 3)
					va = level4Records.FindVaFromPa(GET_PHYADDR_FROM_PFN(pTable->entries[idx].fields.pagePpn));
				else
					va = level123Records.FindVaFromPa(GET_PHYADDR_FROM_PFN(pTable->entries[idx].fields.pagePpn));

				if (va == -1)
				{
					status = STATUS_INSUFFICIENT_RESOURCES;
					break;
				}
			}

			PTR_TYPE newStartPhyAddr = startBase + MUL_UNIT(idx - startIdx, rightShift);
			PTR_TYPE newEndPhyAddr = newStartPhyAddr + MUL_UNIT(static_cast<PTR_TYPE>(1), rightShift);

			if (startPhyAddr > newStartPhyAddr)
				newStartPhyAddr = startPhyAddr;

			if (endPhyAddr < newEndPhyAddr)
				newEndPhyAddr = endPhyAddr;

			status = nextStep((SubTableType*)va, newStartPhyAddr, newEndPhyAddr, level123Records, level4Records);
			if (!NT_SUCCESS(status))
				break;
		}

		if (!NT_SUCCESS(status))
			break;

	} while (false);

	return status;
}


//（最低级别页表）的数据填充
#pragma code_seg()
template<PTR_TYPE level, bool isLargePage>
NTSTATUS ProcessNptPageTableeEndLevelImpl(PageTableLevel123* pTable, PTR_TYPE startPhyAddr, PTR_TYPE endPhyAddr, PageTableRecords& level123Records, PageTableRecords& level4Records)
{
	UNREFERENCED_PARAMETER(level123Records);
	UNREFERENCED_PARAMETER(level4Records);

	constexpr PTR_TYPE rightShift = (level - 1) * 9 + 12;
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
			{
				SetPageTableEntry(&pTable->entries[idx], GET_PFN_FROM_PHYADDR(startBase + MUL_UNIT(idx - startIdx, rightShift)));
				if (isLargePage)
					pTable->entries[idx].fields.size = true;
			}
		}
	} while (false);

	return status;
}

//*************************************页表构建函数结束*************************************

using NPT_Level123_Processor = NTSTATUS(*)(PageTableLevel123*, PTR_TYPE, PTR_TYPE, PageTableRecords&, PageTableRecords&);
using NPT_Level4_Processor   = NTSTATUS(*)(PageTableLevel4*, PTR_TYPE, PTR_TYPE, PageTableRecords&, PageTableRecords&);

//返回小页面处理函数指针
constexpr static NPT_Level4_Processor GetNptSmallPageProcessor()
{
	//嵌套模板函数，用于补全小页面的缺失
	constexpr NPT_Level123_Processor level1NptProcessor = ProcessNptPageTableeEndLevelImpl<1, false>;
	constexpr NPT_Level123_Processor level2NptProcessor = ProcessNptPageTableFrontLevelImpl<PageTableLevel123, PageTableLevel123, 2, true, NPT_Level123_Processor, level1NptProcessor>;
	constexpr NPT_Level123_Processor level3NptProcessor = ProcessNptPageTableFrontLevelImpl<PageTableLevel123, PageTableLevel123, 3, false, NPT_Level123_Processor, level2NptProcessor>;
	constexpr NPT_Level4_Processor	 level4NptProcessor = ProcessNptPageTableFrontLevelImpl<PageTableLevel4, PageTableLevel123, 4, false, NPT_Level123_Processor, level3NptProcessor>;
	return level4NptProcessor;
}

using NPT_Large_Level23_Processor = NTSTATUS(*)(PageTableLevel123*, PTR_TYPE, PTR_TYPE, PageTableRecords&, PageTableRecords&);
using NPT_Large_Level4_Processor  = NTSTATUS(*)(PageTableLevel4*, PTR_TYPE, PTR_TYPE, PageTableRecords&, PageTableRecords&);

//返回大页面构建函数指针
constexpr static NPT_Large_Level4_Processor GetNptLargePageProcessor()
{
	constexpr NPT_Large_Level23_Processor level2NptProcessor = ProcessNptPageTableeEndLevelImpl<2, true>;
	constexpr NPT_Large_Level23_Processor level3NptProcessor = ProcessNptPageTableFrontLevelImpl<PageTableLevel123, PageTableLevel123, 3, false, NPT_Large_Level23_Processor, level2NptProcessor>;
	constexpr NPT_Large_Level4_Processor  level4NptProcessor = ProcessNptPageTableFrontLevelImpl<PageTableLevel4, PageTableLevel123, 4, false, NPT_Large_Level23_Processor, level3NptProcessor>;
	return level4NptProcessor;
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

	if (!exitInfo.fields.present)
	{
		PTR_TYPE paStart = pa - pa % PAGE_SIZE;
		PTR_TYPE paEnd = paStart + PAGE_SIZE;

		if (!NT_SUCCESS(corePageTables[pVirtCpuInfo->otherInfo.cpuIdx].FixPageFault(paStart, paEnd)))
			KeBugCheck(MANUALLY_INITIATED_CRASH);

		result = true;
	}

	return result;
}

#pragma code_seg("PAGE")
PVOID PageTableManager::GetNCr3ForCore(UINT32 cpuIdx)
{
	PAGED_CODE();
	const CoreNptPageTableManager* pageTables = GetCoreNptPageTables();
	SIZE_TYPE cnt = GetCoreNptPageTablesCnt();
	if (cpuIdx >= cnt)
		return (PVOID)INVALID_ADDR;
	else
		return (PVOID)MmGetPhysicalAddress((PVOID)pageTables[cpuIdx].GetNptPageTable()).QuadPart;
}

#pragma code_seg()
NTSTATUS CoreNptPageTableManager::FixPageFault(PTR_TYPE startAddr, PTR_TYPE endAddr)
{
	constexpr NPT_Level4_Processor smallPageProcessor = GetNptSmallPageProcessor();

	return smallPageProcessor((PageTableLevel4*)pNptPageTable, startAddr, endAddr, level123Records, level4Records);
}

#pragma code_seg("PAGE")
void CoreNptPageTableManager::Deinit()
{
	PAGED_CODE();
	if (pNptPageTable != INVALID_ADDR)
	{
		for (SIZE_TYPE idx = 0; idx < level123Records.Length(); ++idx)
			FreeNonPagedMem((PVOID)level123Records[idx].pVirtAddr, PT_TAG);

		level123Records.Clear();

		for (SIZE_TYPE idx = 0; idx < level4Records.Length(); ++idx)
			FreeNonPagedMem((PVOID)level4Records[idx].pVirtAddr, PT_TAG);

		level4Records.Clear();

		FreeNonPagedMem((PVOID)pNptPageTable, PT_TAG);

		pNptPageTable = INVALID_ADDR;
	}
}

#pragma code_seg("PAGE")
NTSTATUS CoreNptPageTableManager::BuildNptPageTable()
{
	PAGED_CODE();
	NTSTATUS status = STATUS_SUCCESS;

	do
	{
		//分配的内存刚好是一个页面，使用该函数比使用MmAllocateContiguousMemory快很多，其他地方也是类似
		PageTableLevel4* pNptLevel4PageTable = (PageTableLevel4*)AllocNonPagedMem(sizeof * pNptLevel4PageTable, PT_TAG);
		if (pNptLevel4PageTable == NULL)
		{
			status = STATUS_INSUFFICIENT_RESOURCES;
			break;
		}

		pNptPageTable = (PTR_TYPE)pNptLevel4PageTable;

		RtlZeroMemory(pNptLevel4PageTable, sizeof(*pNptLevel4PageTable));

		NPT_Large_Level4_Processor largePageProcessor = GetNptLargePageProcessor();

		//构建页表
		//初始化时全部使用2MB大页，节约内存同时可以覆盖全部物理地址
		//需要HOOK时把对应部分改成小页即可
		status = largePageProcessor(pNptLevel4PageTable, 0x0, 0x000000FFFFFFFFFF, level123Records, level4Records);

	} while (false);
	
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

		if (corePageTables == NULL)
		{
			UINT32 cpuCnt = KeQueryActiveProcessorCountEx(ALL_PROCESSOR_GROUPS);
			corePageTables = (CoreNptPageTableManager*)AllocNonPagedMem(sizeof * corePageTables * cpuCnt, PT_TAG);
			if (corePageTables == NULL)
			{
				status = STATUS_INSUFFICIENT_RESOURCES;
				break;
			}
			pageTableCnt = cpuCnt;


			for (SIZE_TYPE idx = 0; idx < pageTableCnt; ++idx)
			{
				CallConstructor(&corePageTables[idx]);
				status = corePageTables[idx].BuildNptPageTable();
				if (!NT_SUCCESS(status))
					break;
			}
		}

	} while (false);

	if (!NT_SUCCESS(status))
		Deinit();

	return status;
}

#pragma code_seg("PAGE")
void PageTableManager::Deinit()
{
	PAGED_CODE();
	if (corePageTables != NULL)
	{
		for (SIZE_TYPE idx = 0; idx < pageTableCnt; ++idx)
		{
			corePageTables[idx].Deinit();
			CallDestroyer(&corePageTables[idx]);
		}
		FreeNonPagedMem(corePageTables, PT_TAG);
		corePageTables = NULL;
		pageTableCnt = 0;
	}
}