#include "PageTable.h"
#include <intrin.h>

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
	pEntry->fields.present = true;
	pEntry->fields.writeable = true;
	pEntry->fields.userAccess = true;
	pEntry->fields.pagePpn = pfn;
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
//*************************************页表构建函数开始*************************************
//禁用对C++17 if constexpr使用的警告
#pragma warning(disable : 4984)

//高级别页表构建
#pragma code_seg()
template<typename TableType, typename SubTableType, PTR_TYPE level, bool checkLargePage, typename NextStep, NextStep nextStep>
NTSTATUS ProcessNptPageTableFrontLevelImpl(TableType* pTable, PTR_TYPE startPhyAddr, PTR_TYPE endPhyAddr, PageTableRecords& level34Records, PageTableRecords& level2Records, PageTableRecords& level1Records)
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
				if constexpr (level == 2)
					status = AllocNewPageTable<typename TableType::EntryType, SubTableType>(&pTable->entries[idx], level1Records, va);
				else if constexpr (level == 3)
					status = AllocNewPageTable<typename TableType::EntryType, SubTableType>(&pTable->entries[idx], level2Records, va);
				else
					status = AllocNewPageTable<typename TableType::EntryType, SubTableType>(&pTable->entries[idx], level34Records, va);
				if (!NT_SUCCESS(status))
					break;
			}
			else
			{
				//不处理大页
				if constexpr (checkLargePage)
				{
					if (pTable->entries[idx].fields.size)
						return STATUS_SUCCESS;
				}

				//新建页表时记录了虚拟地址和物理地址
				//在记录项里面通过物理地址查找虚拟地址
				//避免了微软保留API的使用

				if constexpr (level == 2)
					va = level1Records.FindVaFromPa(GET_PHYADDR_FROM_PFN(pTable->entries[idx].fields.pagePpn));
				else if constexpr (level == 3)
					va = level2Records.FindVaFromPa(GET_PHYADDR_FROM_PFN(pTable->entries[idx].fields.pagePpn));
				else
					va = level34Records.FindVaFromPa(GET_PHYADDR_FROM_PFN(pTable->entries[idx].fields.pagePpn));

				if (va == INVALID_ADDR)
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

			status = nextStep((SubTableType*)va, newStartPhyAddr, newEndPhyAddr, level34Records, level2Records, level1Records);
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
NTSTATUS ProcessNptPageTableeEndLevelImpl(PageTableLevel123* pTable, PTR_TYPE startPhyAddr, PTR_TYPE endPhyAddr, PageTableRecords& level12Records, PageTableRecords & level3Records, PageTableRecords& level4Records)
{
	UNREFERENCED_PARAMETER(level12Records);
	UNREFERENCED_PARAMETER(level3Records);
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
				if constexpr (isLargePage)
					pTable->entries[idx].fields.size = true;
			}
		}
	} while (false);

	return status;
}

//*************************************页表构建函数结束*************************************

using NPT_Level123_Processor = NTSTATUS(*)(PageTableLevel123*, PTR_TYPE, PTR_TYPE, PageTableRecords&, PageTableRecords&, PageTableRecords&);
using NPT_Level4_Processor = NTSTATUS(*)(PageTableLevel4*, PTR_TYPE, PTR_TYPE, PageTableRecords&, PageTableRecords&, PageTableRecords&);

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

using NPT_Large_Level23_Processor = NTSTATUS(*)(PageTableLevel123*, PTR_TYPE, PTR_TYPE, PageTableRecords&, PageTableRecords&, PageTableRecords&);
using NPT_Large_Level4_Processor = NTSTATUS(*)(PageTableLevel4*, PTR_TYPE, PTR_TYPE, PageTableRecords&, PageTableRecords&, PageTableRecords&);

//返回大页面构建函数指针
constexpr static NPT_Large_Level4_Processor GetNptLargePageProcessor()
{
	constexpr NPT_Large_Level23_Processor level2NptProcessor = ProcessNptPageTableeEndLevelImpl<2, true>;
	constexpr NPT_Large_Level23_Processor level3NptProcessor = ProcessNptPageTableFrontLevelImpl<PageTableLevel123, PageTableLevel123, 3, false, NPT_Large_Level23_Processor, level2NptProcessor>;
	constexpr NPT_Large_Level4_Processor  level4NptProcessor = ProcessNptPageTableFrontLevelImpl<PageTableLevel4, PageTableLevel123, 4, false, NPT_Large_Level23_Processor, level3NptProcessor>;
	return level4NptProcessor;
}

//修改所有页表权限
#pragma code_seg()

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

		if (!NT_SUCCESS(corePageTables[pVirtCpuInfo->otherInfo.cpuIdx].FixPageFault(paStart, paEnd, true)))
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
PVOID CoreNptPageTableManager::FindPageTableForByAddr(PTR_TYPE pa, UINT32 level) const
{
	PVOID result = (PVOID)INVALID_ADDR;
	PTR_TYPE tempPa = INVALID_ADDR;
	PTR_TYPE tempVa = INVALID_ADDR;
	PTR_TYPE pageTableIdx = ((pa >> 39) & 0x1ff);
	SIZE_T levelIdx = 0;

	do
	{
		if (level >= 4)
		{
			result = (PVOID)pNptPageTable;
			break;
		}

		if (!((PageTableLevel4*)pNptPageTable)->entries[pageTableIdx].fields.present)
			break;

		tempPa = GET_PHYADDR_FROM_PFN(((PageTableLevel4*)pNptPageTable)->entries[pageTableIdx].fields.pagePpn);
		tempVa = level34Records.FindVaFromPa(tempPa);

		if (tempVa == INVALID_ADDR)
			break;
		else
			result = (PVOID)tempVa;

		for (levelIdx = 2; levelIdx >= level; --levelIdx)
		{
			pageTableIdx = ((pa >> (levelIdx * 9 + 12)) & 0x1ff);

			if (!((PageTableLevel123*)tempVa)->entries[pageTableIdx].fields.present)
				break;

			if (((PageTableLevel123*)tempVa)->entries[pageTableIdx].fields.size && levelIdx != level)
				break;

			tempPa = GET_PHYADDR_FROM_PFN(((PageTableLevel123*)tempVa)->entries[pageTableIdx].fields.pagePpn);
			if (levelIdx == 1)
				tempVa = level1Records.FindVaFromPa(tempPa);
			else if (levelIdx == 2)
				tempVa = level2Records.FindVaFromPa(tempPa);
			else
				tempVa = level34Records.FindVaFromPa(tempPa);

			if (tempVa == INVALID_ADDR)
				break;

			result = (PVOID)tempVa;
		}

		if (levelIdx >= level)
			result = (PVOID)INVALID_ADDR;

	} while (false);

	return result;
}

#pragma code_seg()
NTSTATUS CoreNptPageTableManager::FixPageFault(PTR_TYPE startAddr, PTR_TYPE endAddr, bool usingLargePage)
{
	constexpr NPT_Level4_Processor smallPageProcessor = GetNptSmallPageProcessor();
	constexpr NPT_Level4_Processor largePageProcessor = GetNptLargePageProcessor();

	if (usingLargePage)
		return largePageProcessor((PageTableLevel4*)pNptPageTable, startAddr, endAddr, level34Records, level2Records, level1Records);
	else
		return smallPageProcessor((PageTableLevel4*)pNptPageTable, startAddr, endAddr, level34Records, level2Records, level1Records);
}

#pragma code_seg()
NTSTATUS CoreNptPageTableManager::UsingSmallPage(PTR_TYPE phyAddr, bool isUsing)
{
	NTSTATUS status = STATUS_SUCCESS;
	PageTableLevel123* pTargetPageTable = (PageTableLevel123*)INVALID_ADDR;
	PTR_TYPE pageTableIdx = ((phyAddr >> 21) & 0x1ff);

	do
	{
		if ((phyAddr >> 12) & 0x1ff)
		{
			status = STATUS_INVALID_PARAMETER;
			break;
		}

		pTargetPageTable = (PageTableLevel123*)FindPageTableForByAddr(phyAddr, 2);

		if (pTargetPageTable == (PageTableLevel123*)INVALID_ADDR)
		{
			status = STATUS_INVALID_PARAMETER;
			break;
		}

		if (isUsing)
		{
			if (pTargetPageTable->entries[pageTableIdx].fields.present &&
				!pTargetPageTable->entries[pageTableIdx].fields.size)
				return STATUS_SUCCESS;

			//更改属性值到未映射状态
			pTargetPageTable->entries[pageTableIdx].fields.present = false;
			pTargetPageTable->entries[pageTableIdx].fields.size = false;
		}
		else
		{
			if (pTargetPageTable->entries[pageTableIdx].fields.present &&
				pTargetPageTable->entries[pageTableIdx].fields.size)
				return STATUS_SUCCESS;

			PTR_TYPE finalPa = GET_PHYADDR_FROM_PFN(pTargetPageTable->entries[pageTableIdx].fields.pagePpn);
			PTR_TYPE finalVa = level1Records.FindVaFromPa(finalPa);

			//删除Leve4页面
			if (finalVa != INVALID_ADDR)
			{
				FreeNonPagedMem((PVOID)finalVa, PT_TAG);
				level1Records.RemoveByPa(finalPa);
			}

			//还原属性值
			pTargetPageTable->entries[pageTableIdx].fields.present = true;
			pTargetPageTable->entries[pageTableIdx].fields.size = true;
			pTargetPageTable->entries[pageTableIdx].fields.pagePpn = GET_PFN_FROM_PHYADDR(phyAddr);
		}

	} while (false);

	return status;
}

#pragma code_seg()
NTSTATUS CoreNptPageTableManager::MapSmallPageByPhyAddr(PTR_TYPE begPhyAddr, PTR_TYPE endPhyAddr)
{
	return FixPageFault(begPhyAddr, endPhyAddr, false);
}

#pragma code_seg()
NTSTATUS CoreNptPageTableManager::SwapSmallPagePpn(PTR_TYPE phyAddr1, PTR_TYPE phyAddr2)
{
	PTR_TYPE pageTableIdx1 = ((phyAddr1 >> 12) & 0x1ff);
	PTR_TYPE pageTableIdx2 = ((phyAddr2 >> 12) & 0x1ff);
	PageTableLevel123* pageTable1 = (PageTableLevel123*)FindPageTableForByAddr(phyAddr1, 1);
	PageTableLevel123* pageTable2 = (PageTableLevel123*)FindPageTableForByAddr(phyAddr2, 1);
	PageTableLevel123Entry swapEntry = {};

	if (pageTable1 == (PageTableLevel123*)INVALID_ADDR || pageTable2 == (PageTableLevel123*)INVALID_ADDR)
		return STATUS_INVALID_PARAMETER;

	swapEntry = pageTable1->entries[pageTableIdx1];
	pageTable1->entries[pageTableIdx1].fields.pagePpn = pageTable2->entries[pageTableIdx2].fields.pagePpn;
	pageTable2->entries[pageTableIdx2].fields.pagePpn = swapEntry.fields.pagePpn;

	return STATUS_SUCCESS;
}

#pragma code_seg()
NTSTATUS CoreNptPageTableManager::GetNptFinalAddrForPhyAddr(PTR_TYPE phyAddr, PTR_TYPE& pNptFinalAddr, PTR_TYPE& level)
{
	PageTableLevel123* pageTable1 = (PageTableLevel123*)FindPageTableForByAddr(phyAddr, 2);
	PageTableLevel123* pageTable2 = (PageTableLevel123*)FindPageTableForByAddr(phyAddr, 1);

	if (pageTable1 == (PageTableLevel123*)INVALID_ADDR && pageTable2 == (PageTableLevel123*)INVALID_ADDR)
		return STATUS_UNSUCCESSFUL;

	if (pageTable2 != (PageTableLevel123*)INVALID_ADDR)
	{
		pNptFinalAddr = GET_PHYADDR_FROM_PFN(pageTable2->entries[(phyAddr >> 12) & 0x1ff].fields.pagePpn);
		level = 1;
	}
	else
	{
		pNptFinalAddr = GET_PHYADDR_FROM_PFN(pageTable1->entries[(phyAddr >> 21) & 0x1ff].fields.pagePpn);
		level = 2;
	}

	return STATUS_SUCCESS;
}

void ChangeAllPageTablePremessionSub(PageTableLevel123* pPageTable, UINT32 level, PageTableRecords& level34Records, PageTableRecords& level2Records, PageTableRecords& level1Records, PageTableLevel123Entry entry)
{

	for (SIZE_TYPE idx = 0; idx < GetArrayElementCnt(pPageTable->entries); ++idx)
	{
		if (level == 1 || pPageTable->entries[idx].fields.size)
		{
			//写入权限
			entry.fields.pagePpn = pPageTable->entries[idx].fields.pagePpn;
			entry.fields.size = pPageTable->entries[idx].fields.size;

			pPageTable->entries[idx] = entry;
		}
		else
		{
			PageTableLevel123* pSubPageTable = NULL;

			if (level == 2)
				pSubPageTable = (PageTableLevel123*)level1Records.FindVaFromPa(GET_PHYADDR_FROM_PFN(pPageTable->entries[idx].fields.pagePpn));
			else if (level == 3)
				pSubPageTable = (PageTableLevel123*)level2Records.FindVaFromPa(GET_PHYADDR_FROM_PFN(pPageTable->entries[idx].fields.pagePpn));
			else
				pSubPageTable = (PageTableLevel123*)level34Records.FindVaFromPa(GET_PHYADDR_FROM_PFN(pPageTable->entries[idx].fields.pagePpn));

			if (pSubPageTable != (PageTableLevel123*)INVALID_ADDR)
				ChangeAllPageTablePremessionSub(pSubPageTable, level - 1, level34Records, level2Records, level1Records, entry);
		}
	}
}

#pragma code_seg()
void CoreNptPageTableManager::ChangeAllPageTablePermession(PageTableLevel123Entry entry)
{
	entry.fields.present = true;

	PageTableLevel4* pPageTable = (PageTableLevel4*)pNptPageTable;

	for (SIZE_TYPE idx = 0; idx < GetArrayElementCnt(pPageTable->entries); ++idx)
	{
		PageTableLevel123* pSubPageTable = (PageTableLevel123*)level34Records.FindVaFromPa(GET_PHYADDR_FROM_PFN(pPageTable->entries[idx].fields.pagePpn));
		if (pSubPageTable != (PageTableLevel123*)INVALID_ADDR)
			ChangeAllPageTablePremessionSub(pSubPageTable, 3, level34Records, level2Records, level1Records, entry);
	}
}

#pragma code_seg()
NTSTATUS CoreNptPageTableManager::ChangePageTablePermession(PTR_TYPE pa, PageTableLevel123Entry entry, UINT32 level)
{

	PageTableLevel123* pageTable = (PageTableLevel123*)FindPageTableForByAddr(pa, level);
	PageTableLevel123Entry* pTargetEntry = NULL;

	if (pageTable == (PageTableLevel123*)INVALID_ADDR)
		return STATUS_UNSUCCESSFUL;

	pTargetEntry = &pageTable->entries[(pa >> (12 + (level - 1) * 9)) & 0x1ff];

	//写入权限
	entry.fields.pagePpn = pTargetEntry->fields.pagePpn;
	entry.fields.present = pTargetEntry->fields.present;
	entry.fields.size = pTargetEntry->fields.size;

	*pTargetEntry = entry;

	return STATUS_SUCCESS;
}

#pragma code_seg("PAGE")
void CoreNptPageTableManager::Deinit()
{
	PAGED_CODE();
	if (pNptPageTable != INVALID_ADDR)
	{
		for (SIZE_TYPE idx = 0; idx < level34Records.Length(); ++idx)
			FreeNonPagedMem((PVOID)level34Records[idx].pVirtAddr, PT_TAG);

		level34Records.Clear();

		for (SIZE_TYPE idx = 0; idx < level2Records.Length(); ++idx)
			FreeNonPagedMem((PVOID)level2Records[idx].pVirtAddr, PT_TAG);

		level2Records.Clear();

		for (SIZE_TYPE idx = 0; idx < level1Records.Length(); ++idx)
			FreeNonPagedMem((PVOID)level1Records[idx].pVirtAddr, PT_TAG);

		level1Records.Clear();

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

		constexpr NPT_Large_Level4_Processor largePageProcessor = GetNptLargePageProcessor();

		//构建页表
		//初始化时全部使用2MB大页，节约内存同时可以覆盖全部物理地址
		//需要HOOK时把对应部分改成小页即可
		status = largePageProcessor(pNptLevel4PageTable, 0x0, 0x000000FFFFFFFFFF, level34Records, level2Records, level1Records);

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