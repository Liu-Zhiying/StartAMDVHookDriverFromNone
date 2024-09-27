#include "Hook.h"

extern "C" PTR_TYPE LStarHookCallback;
extern "C" PTR_TYPE OldLStarEntry;
extern "C" void LStarHookEntry();

#pragma code_seg("PAGE")
void SetLStrHookEntryParameters(PTR_TYPE oldEntry, PTR_TYPE pCallback)
{
	LStarHookCallback = pCallback;
	OldLStarEntry = oldEntry;
}

#pragma code_seg("PAGE")
PTR_TYPE GetLStarHookEntry()
{
	return (PTR_TYPE)LStarHookEntry;
}

#pragma code_seg()
SIZE_TYPE NptHookManager::FindHookRecordByOriginVirtAddr(PVOID pOriginAddr)
{
	SIZE_TYPE result = (SIZE_TYPE)-1;

	for (SIZE_TYPE idx = 0; idx < hookRecords.Length(); ++idx)
	{
		if (hookRecords[idx].pOriginVirtAddr == pOriginAddr)
		{
			result = idx;
			break;
		}
	}

	return result;
}

#pragma code_seg()
SIZE_TYPE NptHookManager::FindSmallPageLevel3RefCntByPhyAddr(PTR_TYPE phyAddr)
{
	SIZE_TYPE result = (SIZE_TYPE)-1;

	for (SIZE_TYPE idx = 0; idx < level3Refs.Length(); ++idx)
	{
		if (level3Refs[idx].level3PhyAddr == phyAddr)
		{
			result = idx;
			break;
		}
	}

	return result;
}

#pragma code_seg()
SIZE_TYPE NptHookManager::FindSwapPageRefCntByPhyAddr(PTR_TYPE phyAddr)
{
	SIZE_TYPE result = (SIZE_TYPE)-1;

	for (SIZE_TYPE idx = 0; idx < swapPageRefs.Length(); ++idx)
	{
		if (((PTR_TYPE)MmGetPhysicalAddress(swapPageRefs[idx].pOriginVirtAddr).QuadPart) == phyAddr)
		{
			result = idx;
			break;
		}
	}

	return result;
}

#pragma code_seg()
SIZE_TYPE NptHookManager::FindSwapPageRefCntByOriginVirtAddr(PVOID pOriginAddr)
{
	SIZE_TYPE result = (SIZE_TYPE)-1;

	for (SIZE_TYPE idx = 0; idx < swapPageRefs.Length(); ++idx)
	{
		if (swapPageRefs[idx].pOriginVirtAddr == pOriginAddr)
		{
			result = idx;
			break;
		}
	}

	return result;
}

#pragma code_seg()
bool NptHookManager::HandleBreakpoint(VirtCpuInfo* pVirtCpuInfo, GenericRegisters* pGuestRegisters, PVOID pGuestVmcbPhyAddr, PVOID pHostVmcbPhyAddr)
{
	UNREFERENCED_PARAMETER(pGuestRegisters);
	UNREFERENCED_PARAMETER(pGuestVmcbPhyAddr);
	UNREFERENCED_PARAMETER(pHostVmcbPhyAddr);

	bool result = false;

	locker.ReadLock();

	SIZE_TYPE hookIdx = FindHookRecordByOriginVirtAddr((PVOID)pVirtCpuInfo->guestVmcb.statusFields.rip);

	if (hookIdx != -1)
	{
		pVirtCpuInfo->guestVmcb.statusFields.rip = (UINT64)hookRecords[hookIdx].pGotoVirtAddr;
		result = true;
	}

	locker.ReadUnlock();

	return result;
}

#pragma code_seg()
bool NptHookManager::HandleNpf(VirtCpuInfo* pVirtCpuInfo, GenericRegisters* pGuestRegisters, PVOID pGuestVmcbPhyAddr, PVOID pHostVmcbPhyAddr)
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
		result = pPageTableManager->HandleNpf(pVirtCpuInfo, pGuestRegisters, pGuestVmcbPhyAddr, pHostVmcbPhyAddr);
	}
	else
	{
		if (exitInfo.fields.execute)
		{
			//获取CPU IDX
			UINT32 cpuIdx = pVirtCpuInfo->otherInfo.cpuIdx;

			//获取核心NPT HOOK状态
			CoreNptHookStatus& hookStatus = coreNptHookStatus[pVirtCpuInfo->otherInfo.cpuIdx];

			//获取对应的核心页表管理器
			CoreNptPageTableManager& corePageTableManager = pPageTableManager->GetCoreNptPageTables()[cpuIdx];

			SIZE_TYPE swapPageIdx = (SIZE_TYPE)-1;
			PageTableLevel123Entry entry = {};

			PTR_TYPE tempPhyAddr1 = {}, tempPhyAddr2 = {};

			SwapPageRefCnt tempSwapPageInfo = {};

			locker.ReadLock();

			if (hookStatus.pLastActiveHookPageVirtAddr != NULL)
			{
				//根据虚拟地址查询交换页项目
				swapPageIdx = FindSwapPageRefCntByOriginVirtAddr((PVOID)hookStatus.pLastActiveHookPageVirtAddr);

				if (swapPageIdx != (SIZE_TYPE)-1)
				{
					//如果交换页存在，还原当前hook页面的交换（就是再次交换）
					const SwapPageRefCnt& swapPageRef = swapPageRefs[swapPageIdx];
					tempPhyAddr1 = MmGetPhysicalAddress(swapPageRef.pOriginVirtAddr).QuadPart;
					tempPhyAddr2 = MmGetPhysicalAddress(swapPageRef.pSwapVirtAddr).QuadPart;
					corePageTableManager.SwapSmallPagePpn(tempPhyAddr1, tempPhyAddr2);
				}
				else
				{
					//否则，上次活动hook页虚拟地址置空
					hookStatus.pLastActiveHookPageVirtAddr = NULL;
				}
			}

			//查询发生错误的页面是否为HOOK页面
			swapPageIdx = FindSwapPageRefCntByPhyAddr(pa & 0xFFFFFFFFFF000);

			if (swapPageIdx != (SIZE_TYPE)-1)
			{
				const SwapPageRefCnt& swapPageRef = swapPageRefs[swapPageIdx];

				//交换新hook页面
				tempPhyAddr1 = MmGetPhysicalAddress(swapPageRef.pOriginVirtAddr).QuadPart;
				tempPhyAddr2 = MmGetPhysicalAddress(swapPageRef.pSwapVirtAddr).QuadPart;
				corePageTableManager.SwapSmallPagePpn(tempPhyAddr1, tempPhyAddr2);
			
				//设置新hook页面可读可写可执行，其他页面均可读可写不可执行
				entry.fields.writeable = true;
				entry.fields.userAccess = true;
				entry.fields.executionDisabled = true;

				corePageTableManager.ChangeAllPageTablePermession(entry);

				entry.fields.executionDisabled = false;
				corePageTableManager.ChangePageTablePermession(pa, entry, 1);

				//更新状态
				hookStatus.pLastActiveHookPageVirtAddr = (PTR_TYPE)swapPageRefs[swapPageIdx].pOriginVirtAddr;
				hookStatus.premissionStatus = CoreNptHookStatus::PremissionStatus::HookPageExecuted;
			}
			else
			{
				//设置HOOK页面可读可写不可执行，其他页面均可读可写可执行
				entry.fields.writeable = true;
				entry.fields.userAccess = true;

				corePageTableManager.ChangeAllPageTablePermession(entry);

				entry.fields.executionDisabled = true;
				for (SIZE_TYPE idx = 0; idx < swapPageRefs.Length(); ++idx)
					corePageTableManager.ChangePageTablePermession(MmGetPhysicalAddress(swapPageRefs[idx].pOriginVirtAddr).QuadPart, entry, 1);

				//更新状态
				hookStatus.pLastActiveHookPageVirtAddr = NULL;
				hookStatus.premissionStatus = CoreNptHookStatus::PremissionStatus::HookPageNotExecuted;
			}

			locker.ReadUnlock();

			result = true;
		}
	}

	//if (result)
	//	pVirtCpuInfo->guestVmcb.controlFields.tlbControl = 0x3;

	return result;
}

bool NptHookManager::HandleCpuid(VirtCpuInfo* pVirtCpuInfo, GenericRegisters* pGuestRegisters, PVOID pGuestVmcbPhyAddr, PVOID pHostVmcbPhyAddr)
{
	UNREFERENCED_PARAMETER(pGuestVmcbPhyAddr);
	UNREFERENCED_PARAMETER(pHostVmcbPhyAddr);

	pGuestRegisters->rbx = (UINT64)STATUS_INVALID_PARAMETER;

	//eax为配置NPT HOOK的CPUID编号

	switch (((int)pVirtCpuInfo->guestVmcb.statusFields.rax))
	{
	case NPT_HOOK_TOOL_CPUID_FUNCTION:
	{
		NTSTATUS status = STATUS_SUCCESS;

		switch (((int)pGuestRegisters->rcx))
		{
		case CHANGE_PAGE_SIZE_CPUID_SUBFUNCTION:
		{
			ChangePageSizeInfo* pInfo = (ChangePageSizeInfo*)pGuestRegisters->rdx;

			status = pPageTableManager->GetCoreNptPageTables()[pInfo->cpuIdx].UsingSmallPage(pInfo->pLevel3PhyAddr, !pInfo->beLarge);

			pGuestRegisters->rbx = status;

			if (NT_SUCCESS(status) && !pInfo->beLarge)
			{
				status = pPageTableManager->GetCoreNptPageTables()[pInfo->cpuIdx].MapSmallPageByPhyAddr(pInfo->pLevel3PhyAddr, pInfo->pLevel3PhyAddr + 0x200000);
				if (!NT_SUCCESS(status))
				{
					pGuestRegisters->rbx = status;
					pPageTableManager->GetCoreNptPageTables()[pInfo->cpuIdx].UsingSmallPage(pInfo->pLevel3PhyAddr, !pInfo->beLarge);
				}
			}

			//刷新页表缓存
			//pVirtCpuInfo->guestVmcb.controlFields.tlbControl = 0x3;

			break;
		}
		case COPY_MEMORY_CPUID_SUBFUNCTION:
		{
			MemoryCopyInfo* pInfo = (MemoryCopyInfo*)pGuestRegisters->rdx;
			RtlCopyMemory(pInfo->pDestination, pInfo->pSource, pInfo->Length);
			break;
		}
		case GET_PHYSICAL_ADDRESS_SUBFUNCTION:
		{
			pGuestRegisters->rbx = MmGetPhysicalAddress((PVOID)pGuestRegisters->rdx).QuadPart;
			break;
		}
		case CHANGE_PAGE_TABLE_PERMISSION_CPUID_SUBFUNCTION:
		{
			const ChangePageTablePermissionInfo* pInfo = (ChangePageTablePermissionInfo*)pGuestRegisters->rdx;

			status = pPageTableManager->GetCoreNptPageTables()[pInfo->cpuIdx].ChangePageTablePermession(pInfo->physicalAddress, pInfo->permission, pInfo->level);

			pGuestRegisters->rbx = status;

			//if (NT_SUCCESS(status))
			//	pVirtCpuInfo->guestVmcb.controlFields.tlbControl = 0x3;

			break;
		}
		case SWAP_SMALL_PAGE_PPN_CPUID_SUBFUNCTION:
		{
			const SwapSmallPagePpnInfo* pInfo = (SwapSmallPagePpnInfo*)pGuestRegisters->rdx;

			status = pPageTableManager->GetCoreNptPageTables()[pInfo->cpuIdx].SwapSmallPagePpn(pInfo->physicalAddress1, pInfo->physicalAddress2);

			pGuestRegisters->rbx = status;

			//if (NT_SUCCESS(status))
			//	pVirtCpuInfo->guestVmcb.controlFields.tlbControl = 0x3;

			break;
		}
		case ADD_HOOK_ITEM_CPUID_SUBFUNCTION:
		{
			hookRecords.PushBack(*((const HookRecord*)pGuestRegisters->rdx));
			break;
		}
		case REMOVE_HOOK_ITEM_CPUID_SUBFUNCTION:
		{
			hookRecords.Remove((SIZE_TYPE)pGuestRegisters->rdx);
			break;
		}
		case ADD_LEVEL3_REF_ITEM_CPUID_SUBFUNCTION:
		{
			level3Refs.PushBack(*((const SmallPageLevel3RefCnt*)pGuestRegisters->rdx));
			break;
		}
		case REMOVE_LEVEL3_REF_ITEM_CPUID_SUBFUNCTION:
		{
			level3Refs.Remove((SIZE_TYPE)pGuestRegisters->rdx);
			break;
		}
		case ADD_SWAPPAGE_REF_CNT_CPUID_SUBFUNCTION:
		{
			swapPageRefs.PushBack(*((const SwapPageRefCnt*)pGuestRegisters->rdx));
			break;
		}
		case REMOVE_SWAPPAGE_REF_CNT_CPUID_SUBFUNCTION:
		{
			swapPageRefs.Remove((SIZE_TYPE)pGuestRegisters->rdx);
			break;
		}
		}

		pVirtCpuInfo->guestVmcb.statusFields.rip = pVirtCpuInfo->guestVmcb.controlFields.nRip;

		return true;
	}
	default:
		break;
	}
	return false;
}

#pragma code_seg("PAGE")
NTSTATUS NptHookManager::ChangeLargePageToSmallPage(PTR_TYPE pOriginLevel3PhyAddr)
{
	NTSTATUS status = STATUS_SUCCESS;
	SIZE_TYPE cpuCnt = pPageTableManager->GetCoreNptPageTablesCnt();

	PTR_TYPE regs[4] = {};
	ChangePageSizeInfo info = {};

	info.beLarge = false;
	info.pLevel3PhyAddr = pOriginLevel3PhyAddr;

	PROCESSOR_NUMBER processorNum = {};
	GROUP_AFFINITY affinity = {}, oldAffinity = {};

	for (ULONG idx = 0; idx < cpuCnt; ++idx)
	{
		KeGetProcessorNumberFromIndex(idx, &processorNum);
		affinity = {};
		affinity.Group = processorNum.Group;
		affinity.Mask = 1ULL << processorNum.Number;
		KeSetSystemGroupAffinityThread(&affinity, &oldAffinity);

		regs[0] = NPT_HOOK_TOOL_CPUID_FUNCTION;
		regs[1] = 0;
		regs[2] = CHANGE_PAGE_SIZE_CPUID_SUBFUNCTION;
		regs[3] = (PTR_TYPE)&info;

		info.cpuIdx = idx;

		SetRegsThenCpuid(&regs[0], &regs[1], &regs[2], &regs[3]);

		KeRevertToUserGroupAffinityThread(&oldAffinity);

		if (!NT_SUCCESS(regs[1]))
		{
			status = (NTSTATUS)regs[1];
			break;
		}
	}

	return status;
}

#pragma code_seg("PAGE")
NTSTATUS NptHookManager::ChangeSmallPageToLargePage(PTR_TYPE pOriginLevel3PhyAddr)
{
	NTSTATUS status = STATUS_SUCCESS;
	SIZE_TYPE cpuCnt = pPageTableManager->GetCoreNptPageTablesCnt();

	PTR_TYPE regs[4] = {};
	ChangePageSizeInfo info = {};

	info.beLarge = true;
	info.pLevel3PhyAddr = pOriginLevel3PhyAddr;

	PROCESSOR_NUMBER processorNum = {};
	GROUP_AFFINITY affinity = {}, oldAffinity = {};

	for (ULONG idx = 0; idx < cpuCnt; ++idx)
	{
		KeGetProcessorNumberFromIndex(idx, &processorNum);
		affinity = {};
		affinity.Group = processorNum.Group;
		affinity.Mask = 1ULL << processorNum.Number;
		KeSetSystemGroupAffinityThread(&affinity, &oldAffinity);

		regs[0] = NPT_HOOK_TOOL_CPUID_FUNCTION;
		regs[1] = 0;
		regs[2] = CHANGE_PAGE_SIZE_CPUID_SUBFUNCTION;
		regs[3] = (PTR_TYPE)&info;

		info.cpuIdx = idx;

		SetRegsThenCpuid(&regs[0], &regs[1], &regs[2], &regs[3]);

		KeRevertToUserGroupAffinityThread(&oldAffinity);

		if (!NT_SUCCESS(regs[1]))
		{
			status = (NTSTATUS)regs[1];
			break;
		}
	}

	return status;
}

#pragma code_seg("PAGE")
NTSTATUS NptHookManager::ChangePageTablePermission(PTR_TYPE physicalAddress, PageTableLevel123Entry permission)
{
	NTSTATUS status = STATUS_SUCCESS;
	SIZE_TYPE cpuCnt = pPageTableManager->GetCoreNptPageTablesCnt();

	PTR_TYPE regs[4] = {};
	ChangePageTablePermissionInfo info = {};

	info.physicalAddress = physicalAddress;
	info.permission = permission;
	info.level = 1;

	PROCESSOR_NUMBER processorNum = {};
	GROUP_AFFINITY affinity = {}, oldAffinity = {};

	for (ULONG idx = 0; idx < cpuCnt; ++idx)
	{
		KeGetProcessorNumberFromIndex(idx, &processorNum);
		affinity = {};
		affinity.Group = processorNum.Group;
		affinity.Mask = 1ULL << processorNum.Number;
		KeSetSystemGroupAffinityThread(&affinity, &oldAffinity);

		regs[0] = NPT_HOOK_TOOL_CPUID_FUNCTION;
		regs[1] = 0;
		regs[2] = CHANGE_PAGE_TABLE_PERMISSION_CPUID_SUBFUNCTION;
		regs[3] = (PTR_TYPE)&info;

		info.cpuIdx = idx;

		SetRegsThenCpuid(&regs[0], &regs[1], &regs[2], &regs[3]);

		KeRevertToUserGroupAffinityThread(&oldAffinity);

		if (!NT_SUCCESS(regs[1]))
		{
			status = (NTSTATUS)regs[1];
			break;
		}
	}

	return status;
}

NTSTATUS NptHookManager::CancelHookOperation(const SwapPageRefCnt& swapPageInfo)
{
	NTSTATUS status = STATUS_SUCCESS;
	SIZE_TYPE cpuCnt = pPageTableManager->GetCoreNptPageTablesCnt();

	PTR_TYPE regs[4] = {};

	PROCESSOR_NUMBER processorNum = {};
	GROUP_AFFINITY affinity = {}, oldAffinity = {};

	PTR_TYPE physicalAddress = INVALID_ADDR;

	PageTableLevel123Entry permission = {};
	permission.fields.writeable = true;
	permission.fields.userAccess = true;

	ChangePageTablePermissionInfo info = {};

	info.permission = permission;
	info.level = 1;

	regs[0] = NPT_HOOK_TOOL_CPUID_FUNCTION;
	regs[1] = NULL;
	regs[2] = GET_PHYSICAL_ADDRESS_SUBFUNCTION;
	regs[3] = (PTR_TYPE)swapPageInfo.pOriginVirtAddr;

	SetRegsThenCpuid(&regs[0], &regs[1], &regs[2], &regs[3]);

	physicalAddress = regs[1];

	info.physicalAddress = physicalAddress;

	for (ULONG idx = 0; idx < cpuCnt; ++idx)
	{
		KeGetProcessorNumberFromIndex(idx, &processorNum);
		affinity = {};
		affinity.Group = processorNum.Group;
		affinity.Mask = 1ULL << processorNum.Number;
		KeSetSystemGroupAffinityThread(&affinity, &oldAffinity);

		CoreNptHookStatus& hookStatus = coreNptHookStatus[idx];

		if (hookStatus.premissionStatus == CoreNptHookStatus::PremissionStatus::HookPageExecuted)
		{
			if (hookStatus.pLastActiveHookPageVirtAddr == (PTR_TYPE)swapPageInfo.pOriginVirtAddr)
			{
				regs[0] = NPT_HOOK_TOOL_CPUID_FUNCTION;
				regs[1] = NULL;
				regs[2] = GET_PHYSICAL_ADDRESS_SUBFUNCTION;
				regs[3] = (PTR_TYPE)swapPageInfo.pSwapVirtAddr;

				SetRegsThenCpuid(&regs[0], &regs[1], &regs[2], &regs[3]);

				SwapSmallPagePpnInfo info2 = {};

				info2.physicalAddress1 = physicalAddress;
				info2.physicalAddress2 = regs[1];

				regs[0] = NPT_HOOK_TOOL_CPUID_FUNCTION;
				regs[1] = 0;
				regs[2] = SWAP_SMALL_PAGE_PPN_CPUID_SUBFUNCTION;
				regs[3] = (PTR_TYPE)&info2;

				info2.cpuIdx = idx;

				SetRegsThenCpuid(&regs[0], &regs[1], &regs[2], &regs[3]);

				if (!NT_SUCCESS(regs[1]))
				{
					status = (NTSTATUS)regs[1];
					break;
				}
			}

			permission.fields.executionDisabled = true;

			regs[0] = NPT_HOOK_TOOL_CPUID_FUNCTION;
			regs[1] = 0;
			regs[2] = CHANGE_PAGE_TABLE_PERMISSION_CPUID_SUBFUNCTION;
			regs[3] = (PTR_TYPE)&info;

			info.cpuIdx = idx;

			SetRegsThenCpuid(&regs[0], &regs[1], &regs[2], &regs[3]);
		}
		else
		{
			permission.fields.executionDisabled = false;

			regs[0] = NPT_HOOK_TOOL_CPUID_FUNCTION;
			regs[1] = 0;
			regs[2] = CHANGE_PAGE_TABLE_PERMISSION_CPUID_SUBFUNCTION;
			regs[3] = (PTR_TYPE)&info;

			info.cpuIdx = idx;

			SetRegsThenCpuid(&regs[0], &regs[1], &regs[2], &regs[3]);
		}

		KeRevertToUserGroupAffinityThread(&oldAffinity);

		if (!NT_SUCCESS(regs[1]))
		{
			status = (NTSTATUS)regs[1];
			break;
		}
	}

	return status;
}

#pragma code_seg("PAGE")
NTSTATUS NptHookManager::AddHook(const HookRecord& record)
{
	NTSTATUS status = STATUS_SUCCESS;
	PTR_TYPE pOriginPhyAddr = NULL;
	PTR_TYPE pOriginPageVirtAddr = (PTR_TYPE)record.pOriginVirtAddr & 0xfffffffffffff000;
	SIZE_TYPE level3RefIdx = (SIZE_TYPE)-1;
	SIZE_TYPE swapPageIdx = (SIZE_TYPE)-1;
	SIZE_TYPE hookIdx = (SIZE_TYPE)-1;
	UINT8* swapPageVirtAddr = NULL;
	PTR_TYPE swapPagePhyAddr = INVALID_ADDR;
	bool allocedNewSwapPage = false;
	bool needChangePagePermission = false;
	PTR_TYPE regs[4] = {};
	MemoryCopyInfo copyMemInfo = {};
	int stepCnt = 0;
	
	locker.WriteLock();

	do
	{
		hookIdx = FindHookRecordByOriginVirtAddr(record.pOriginVirtAddr);

		if (hookIdx != -1)
		{
			status = STATUS_UNSUCCESSFUL;
			break;
		}

		regs[0] = NPT_HOOK_TOOL_CPUID_FUNCTION;
		regs[1] = NULL;
		regs[2] = GET_PHYSICAL_ADDRESS_SUBFUNCTION;
		regs[3] = (PTR_TYPE)record.pOriginVirtAddr;

		SetRegsThenCpuid(&regs[0], &regs[1], &regs[2], &regs[3]);

		pOriginPhyAddr = regs[1];

		stepCnt = 1;

		//分配交换页

		swapPageIdx = FindSwapPageRefCntByOriginVirtAddr((PVOID)pOriginPageVirtAddr);

		if (swapPageIdx == -1)
		{
			swapPageVirtAddr = (UINT8*)AllocExecutableNonPagedMem(PAGE_SIZE, HOOK_TAG);
			if (swapPageVirtAddr == NULL)
			{
				status = STATUS_INSUFFICIENT_RESOURCES;
				break;
			}

			//拷贝数据
			RtlCopyMemory(swapPageVirtAddr, (PVOID)pOriginPageVirtAddr, PAGE_SIZE);
			//写入断点
			swapPageVirtAddr[(PTR_TYPE)record.pOriginVirtAddr & 0xfff] = 0xcc;
			//标记新分配了交换页
			allocedNewSwapPage = true;

			//插入交换页对条目
			SwapPageRefCnt newItem((PVOID)pOriginPageVirtAddr, swapPageVirtAddr, 1);

			regs[0] = NPT_HOOK_TOOL_CPUID_FUNCTION;
			regs[1] = NULL;
			regs[2] = ADD_SWAPPAGE_REF_CNT_CPUID_SUBFUNCTION;
			regs[3] = (PTR_TYPE)&newItem;

			SetRegsThenCpuid(&regs[0], &regs[1], &regs[2], &regs[3]);
		}
		else
		{
			//增加引用计数
			++swapPageRefs[swapPageIdx].refCnt;

			//写入int3断点
			UINT8 breakpointData = 0xcc;
			
			copyMemInfo.pSource = &breakpointData;
			copyMemInfo.pDestination = (UINT8*)swapPageRefs[swapPageIdx].pSwapVirtAddr + ((PTR_TYPE)record.pOriginVirtAddr & 0xfff);
			copyMemInfo.Length = 1;

			regs[0] = NPT_HOOK_TOOL_CPUID_FUNCTION;
			regs[1] = NULL;
			regs[2] = COPY_MEMORY_CPUID_SUBFUNCTION;
			regs[3] = (PTR_TYPE)&copyMemInfo;

			SetRegsThenCpuid(&regs[0], &regs[1], &regs[2], &regs[3]);
		}

		stepCnt = 2;
		//获取交换页的物理地址
		regs[0] = NPT_HOOK_TOOL_CPUID_FUNCTION;
		regs[1] = NULL;
		regs[2] = GET_PHYSICAL_ADDRESS_SUBFUNCTION;
		regs[3] = (PTR_TYPE)swapPageVirtAddr;

		SetRegsThenCpuid(&regs[0], &regs[1], &regs[2], &regs[3]);
		swapPagePhyAddr = regs[1];

		//设置交换页对应的页表为小页
		//先查询是否有设置为小页的记录

		level3RefIdx = FindSmallPageLevel3RefCntByPhyAddr(swapPagePhyAddr & 0xFFFFFFFFFFE00000);

		if (level3RefIdx == -1)
		{
			//如果没有查询到为小页的记录，就设置为小页，并新增记录
			status = ChangeLargePageToSmallPage(swapPagePhyAddr & 0xFFFFFFFFFFE00000);
			if (!NT_SUCCESS(status))
				break;

			SmallPageLevel3RefCnt newItem(swapPagePhyAddr & 0xFFFFFFFFFFE00000, 1);

			regs[0] = NPT_HOOK_TOOL_CPUID_FUNCTION;
			regs[1] = NULL;
			regs[2] = ADD_LEVEL3_REF_ITEM_CPUID_SUBFUNCTION;
			regs[3] = (PTR_TYPE)&newItem;

			SetRegsThenCpuid(&regs[0], &regs[1], &regs[2], &regs[3]);
		}
		else
		{
			//否则，递增引用计数
			level3Refs[level3RefIdx].refCnt++;
		}

		stepCnt = 3;

		//设置原始页对应的页表为小页
		//先查询是否有设置为小页的记录

		level3RefIdx = FindSmallPageLevel3RefCntByPhyAddr(pOriginPhyAddr & 0xFFFFFFFFFFE00000);

		if (level3RefIdx == -1)
		{
			//如果没有查询到为小页的记录，就设置为小页，设置权限，并新增记录
			status = ChangeLargePageToSmallPage(pOriginPhyAddr & 0xFFFFFFFFFFE00000);
			if (!NT_SUCCESS(status))
				break;

			needChangePagePermission = true;

			SmallPageLevel3RefCnt newItem(pOriginPhyAddr & 0xFFFFFFFFFFE00000, 1);

			regs[0] = NPT_HOOK_TOOL_CPUID_FUNCTION;
			regs[1] = NULL;
			regs[2] = ADD_LEVEL3_REF_ITEM_CPUID_SUBFUNCTION;
			regs[3] = (PTR_TYPE)&newItem;

			SetRegsThenCpuid(&regs[0], &regs[1], &regs[2], &regs[3]);
		}
		else
		{
			//否则，递增引用计数
			++level3Refs[level3RefIdx].refCnt;
		}

		//插入到hook条目
		regs[0] = NPT_HOOK_TOOL_CPUID_FUNCTION;
		regs[1] = NULL;
		regs[2] = ADD_HOOK_ITEM_CPUID_SUBFUNCTION;
		regs[3] = (PTR_TYPE)&record;

		SetRegsThenCpuid(&regs[0], &regs[1], &regs[2], &regs[3]);

	} while (false);

	locker.WriteUnlock();

	if (NT_SUCCESS(status) && needChangePagePermission)
	{
		PageTableLevel123Entry permission = {};
		permission.fields.writeable = true;
		permission.fields.userAccess = true;
		permission.fields.executionDisabled = true;

		ChangePageTablePermission(pOriginPhyAddr & 0xFFFFFFFFFFFF000, permission);
	}

	//失败撤回操作
	if (!NT_SUCCESS(status))
	{
		locker.WriteLock();

		switch (stepCnt)
		{
		case 3:
		{
			if (level3RefIdx == -1)
			{
				ChangeSmallPageToLargePage(pOriginPhyAddr & 0xFFFFFFFFFFE00000);

				level3RefIdx = FindSmallPageLevel3RefCntByPhyAddr(pOriginPhyAddr & 0xFFFFFFFFFFE00000);

				regs[0] = NPT_HOOK_TOOL_CPUID_FUNCTION;
				regs[1] = NULL;
				regs[2] = REMOVE_LEVEL3_REF_ITEM_CPUID_SUBFUNCTION;
				regs[3] = (PTR_TYPE)level3RefIdx;

				SetRegsThenCpuid(&regs[0], &regs[1], &regs[2], &regs[3]);
			}
			else
			{
				--level3Refs[level3RefIdx].refCnt;
			}
			break;
		}
		case 2:
		{
			level3RefIdx = FindSmallPageLevel3RefCntByPhyAddr(swapPagePhyAddr & 0xFFFFFFFFFFE00000);

			--level3Refs[level3RefIdx].refCnt;

			if (!level3Refs[level3RefIdx].refCnt)
			{
				ChangeSmallPageToLargePage(swapPagePhyAddr & 0xFFFFFFFFFFE00000);

				regs[0] = NPT_HOOK_TOOL_CPUID_FUNCTION;
				regs[1] = NULL;
				regs[2] = REMOVE_LEVEL3_REF_ITEM_CPUID_SUBFUNCTION;
				regs[3] = (PTR_TYPE)level3RefIdx;

				SetRegsThenCpuid(&regs[0], &regs[1], &regs[2], &regs[3]);
			}
			break;
		}
		case 1:
		{
			copyMemInfo.pSource = (UINT8*)swapPageRefs[swapPageIdx].pOriginVirtAddr + ((PTR_TYPE)record.pOriginVirtAddr & 0xfff);
			copyMemInfo.pDestination = (UINT8*)swapPageRefs[swapPageIdx].pSwapVirtAddr + ((PTR_TYPE)record.pOriginVirtAddr & 0xfff);
			copyMemInfo.Length = 1;

			regs[0] = NPT_HOOK_TOOL_CPUID_FUNCTION;
			regs[1] = NULL;
			regs[2] = COPY_MEMORY_CPUID_SUBFUNCTION;
			regs[3] = (PTR_TYPE)&copyMemInfo;

			SetRegsThenCpuid(&regs[0], &regs[1], &regs[2], &regs[3]);

			if (allocedNewSwapPage)
			{
				FreeExecutableNonPagedMem(swapPageVirtAddr, HOOK_TAG);

				regs[0] = NPT_HOOK_TOOL_CPUID_FUNCTION;
				regs[1] = NULL;
				regs[2] = REMOVE_SWAPPAGE_REF_CNT_CPUID_SUBFUNCTION;
				regs[3] = (PTR_TYPE)swapPageIdx;

				SetRegsThenCpuid(&regs[0], &regs[1], &regs[2], &regs[3]);
			}
			else
			{
				--swapPageRefs[swapPageIdx].refCnt;
			}
			break;
		}
		case 0:
		default:
			break;
		}

		locker.WriteUnlock();
	}

	return status;
}

#pragma code_seg("PAGE")
NTSTATUS NptHookManager::RemoveHook(PVOID pHookOriginVirtAddr)
{
	NTSTATUS status = STATUS_SUCCESS;

	locker.WriteLock();

	SIZE_TYPE hookIdx = (SIZE_TYPE)-1;
	PTR_TYPE pOriginPhyAddr = INVALID_ADDR;
	PTR_TYPE pOriginPageVirtAddr = NULL;;
	SIZE_TYPE level3RefIdx = (SIZE_TYPE)-1;
	SIZE_TYPE swapPageIdx = (SIZE_TYPE)-1;
	PTR_TYPE swapPagePhyAddr = INVALID_ADDR;
	const HookRecord* pRecord = NULL;
	PTR_TYPE regs[4] = {};
	MemoryCopyInfo copyMemInfo = {};
	bool originPageIsSmallPage = true;

	do
	{
		//查询hook记录是否存在
		hookIdx = FindHookRecordByOriginVirtAddr(pHookOriginVirtAddr);
		if (hookIdx == -1)
		{
			status = STATUS_NOT_FOUND;
			break;
		}

		pRecord = &hookRecords[hookIdx];
		pOriginPageVirtAddr = (PTR_TYPE)pRecord->pOriginVirtAddr & 0xFFFFFFFFFFFFF000;

		regs[0] = NPT_HOOK_TOOL_CPUID_FUNCTION;
		regs[1] = NULL;
		regs[2] = GET_PHYSICAL_ADDRESS_SUBFUNCTION;
		regs[3] = (PTR_TYPE)pRecord->pOriginVirtAddr;

		SetRegsThenCpuid(&regs[0], &regs[1], &regs[2], &regs[3]);
		pOriginPhyAddr = regs[1];

		level3RefIdx = FindSmallPageLevel3RefCntByPhyAddr(pOriginPhyAddr & 0xFFFFFFFFFFE00000);
		if (level3RefIdx == -1)
		{
			--level3Refs[level3RefIdx].refCnt;

			if(!level3Refs[level3RefIdx].refCnt)
			{
				ChangeSmallPageToLargePage(pOriginPhyAddr & 0xFFFFFFFFFFE00000);

				regs[0] = NPT_HOOK_TOOL_CPUID_FUNCTION;
				regs[1] = NULL;
				regs[2] = REMOVE_LEVEL3_REF_ITEM_CPUID_SUBFUNCTION;
				regs[3] = (PTR_TYPE)level3RefIdx;

				SetRegsThenCpuid(&regs[0], &regs[1], &regs[2], &regs[3]);

				originPageIsSmallPage = false;
			}
		}

		swapPageIdx = FindSwapPageRefCntByOriginVirtAddr((PVOID)pOriginPageVirtAddr);
		if (swapPageIdx != -1)
		{
			copyMemInfo.pSource = (UINT8*)swapPageRefs[swapPageIdx].pOriginVirtAddr + ((PTR_TYPE)pRecord->pOriginVirtAddr & 0xfff);
			copyMemInfo.pDestination = (UINT8*)swapPageRefs[swapPageIdx].pSwapVirtAddr + ((PTR_TYPE)pRecord->pOriginVirtAddr & 0xfff);
			copyMemInfo.Length = 1;

			regs[0] = NPT_HOOK_TOOL_CPUID_FUNCTION;
			regs[1] = NULL;
			regs[2] = COPY_MEMORY_CPUID_SUBFUNCTION;
			regs[3] = (PTR_TYPE)&copyMemInfo;

			SetRegsThenCpuid(&regs[0], &regs[1], &regs[2], &regs[3]);

			--swapPageRefs[swapPageIdx].refCnt;

			if (!swapPageRefs[swapPageIdx].refCnt)
			{
				if (originPageIsSmallPage)
					CancelHookOperation(swapPageRefs[swapPageIdx]);

				FreeExecutableNonPagedMem(swapPageRefs[swapPageIdx].pSwapVirtAddr, HOOK_TAG);

				regs[0] = NPT_HOOK_TOOL_CPUID_FUNCTION;
				regs[1] = NULL;
				regs[2] = REMOVE_SWAPPAGE_REF_CNT_CPUID_SUBFUNCTION;
				regs[3] = (PTR_TYPE)swapPageIdx;

				SetRegsThenCpuid(&regs[0], &regs[1], &regs[2], &regs[3]);
			}

			regs[0] = NPT_HOOK_TOOL_CPUID_FUNCTION;
			regs[1] = NULL;
			regs[2] = GET_PHYSICAL_ADDRESS_SUBFUNCTION;
			regs[3] = (PTR_TYPE)swapPageRefs[swapPageIdx].pSwapVirtAddr;

			SetRegsThenCpuid(&regs[0], &regs[1], &regs[2], &regs[3]);

			swapPagePhyAddr = regs[1];

			level3RefIdx = FindSmallPageLevel3RefCntByPhyAddr(swapPagePhyAddr & 0xFFFFFFFFFFE00000);

			--level3Refs[level3RefIdx].refCnt;

			if (!level3Refs[level3RefIdx].refCnt)
			{
				ChangeSmallPageToLargePage(swapPagePhyAddr & 0xFFFFFFFFFFE00000);

				regs[0] = NPT_HOOK_TOOL_CPUID_FUNCTION;
				regs[1] = NULL;
				regs[2] = REMOVE_LEVEL3_REF_ITEM_CPUID_SUBFUNCTION;
				regs[3] = (PTR_TYPE)level3RefIdx;

				SetRegsThenCpuid(&regs[0], &regs[1], &regs[2], &regs[3]);
			}
		}

		//删除hook记录
		regs[0] = NPT_HOOK_TOOL_CPUID_FUNCTION;
		regs[1] = NULL;
		regs[2] = REMOVE_HOOK_ITEM_CPUID_SUBFUNCTION;
		regs[3] = (PTR_TYPE)hookIdx;

		SetRegsThenCpuid(&regs[0], &regs[1], &regs[2], &regs[3]);
	} while (false);

	locker.WriteUnlock();

	return status;
}

#pragma code_seg("PAGE")
NTSTATUS NptHookManager::Init()
{
	UINT32 cpuCmt = KeQueryActiveProcessorCountEx(ALL_PROCESSOR_GROUPS);
	coreNptHookStatus.SetCapacity(cpuCmt);

	for (SIZE_TYPE idx = 0; idx < cpuCmt; ++idx)
		coreNptHookStatus.PushBack(CoreNptHookStatus());

	return STATUS_SUCCESS;
}

#pragma code_seg("PAGE")
void NptHookManager::Deinit()
{
	//挨个删除所有断点
	while (hookRecords.Length())
		RemoveHook(hookRecords[hookRecords.Length() - 1].pOriginVirtAddr);
}
