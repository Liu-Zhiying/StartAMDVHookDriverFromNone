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
SIZE_TYPE NptHookSharedData::FindHookRecordByOriginVirtAddr(PVOID pOriginAddr) const
{
	SIZE_TYPE result = INVALID_INDEX;

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
SIZE_TYPE NptHookSharedData::FindSmallPageLevel3RefCntByPhyAddr(PTR_TYPE phyAddr) const
{
	SIZE_TYPE result = INVALID_INDEX;

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
SIZE_TYPE NptHookSharedData::FindSwapPageRefCntByPhyAddr(PTR_TYPE phyAddr) const
{
	SIZE_TYPE result = INVALID_INDEX;

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
SIZE_TYPE NptHookSharedData::FindSwapPageRefCntByOriginVirtAddr(PVOID pOriginAddr) const
{
	SIZE_TYPE result = INVALID_INDEX;

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

	const NptHookSharedData*  pSharedData = pCoreNptHookStatus[pVirtCpuInfo->otherInfo.cpuIdx].pSharedData;

	if (pSharedData != NULL)
	{
		SIZE_TYPE hookIdx = pSharedData->FindHookRecordByOriginVirtAddr((PVOID)pVirtCpuInfo->guestVmcb.statusFields.rip);

		if (hookIdx != INVALID_INDEX)
		{
			pVirtCpuInfo->guestVmcb.statusFields.rip = (UINT64)pSharedData->hookRecords[hookIdx].pGotoVirtAddr;
			result = true;
		}
	}
	else
	{
		//__debugbreak();
	}

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
			CoreNptHookStatus& hookStatus = pCoreNptHookStatus[pVirtCpuInfo->otherInfo.cpuIdx];

			//获取对应的核心页表管理器
			CoreNptPageTableManager& externalCorePageTableManager = pPageTableManager->GetCoreNptPageTables()[cpuIdx];
			CoreNptPageTableManager& internalCorePageTableManager = internalPageTableManager.GetCoreNptPageTables()[cpuIdx];

			SIZE_TYPE swapPageIdx = INVALID_INDEX;
			PageTableLevel123Entry entry = {};

			PTR_TYPE tempPhyAddr = INVALID_ADDR;

			const NptHookSharedData* pSharedData = hookStatus.pSharedData;

			if (pSharedData != NULL)
			{
				if (hookStatus.pLastActiveHookPageVirtAddr != NULL)
				{
					//根据虚拟地址查询交换页项目
					swapPageIdx = pSharedData->FindSwapPageRefCntByOriginVirtAddr((PVOID)hookStatus.pLastActiveHookPageVirtAddr);

					if (swapPageIdx != INVALID_INDEX)
					{
						//恢复上次hook页面为禁止执行
						entry.fields.writeable = true;
						entry.fields.userAccess = true;
						entry.fields.executionDisabled = true;

						tempPhyAddr = MmGetPhysicalAddress(pSharedData->swapPageRefs[swapPageIdx].pOriginVirtAddr).QuadPart;

						internalCorePageTableManager.ChangePageTablePermession(tempPhyAddr, entry, 1);
					}
					else
					{
						//否则，上次活动hook页虚拟地址置空
						hookStatus.pLastActiveHookPageVirtAddr = NULL;
					}
				}

				//查询发生错误的页面是否为HOOK页面
				swapPageIdx = pSharedData->FindSwapPageRefCntByPhyAddr(pa & 0xFFFFFFFFFF000);

				if (swapPageIdx != INVALID_INDEX)
				{
					//设置hook页面可执行
					entry.fields.writeable = true;
					entry.fields.userAccess = true;
					entry.fields.executionDisabled = false;

					internalCorePageTableManager.ChangePageTablePermession(pa, entry, 1);

					//切换到内部页表
					tempPhyAddr = MmGetPhysicalAddress((PVOID)internalCorePageTableManager.GetNptPageTable()).QuadPart;

					pVirtCpuInfo->guestVmcb.controlFields.nCr3 = tempPhyAddr;

					//更新状态
					hookStatus.pLastActiveHookPageVirtAddr = (PTR_TYPE)pSharedData->swapPageRefs[swapPageIdx].pOriginVirtAddr;
					hookStatus.premissionStatus = CoreNptHookStatus::PremissionStatus::HookPageExecuted;
				}
				else
				{
					//切换到外部页表
					tempPhyAddr = MmGetPhysicalAddress((PVOID)externalCorePageTableManager.GetNptPageTable()).QuadPart;

					pVirtCpuInfo->guestVmcb.controlFields.nCr3 = tempPhyAddr;

					//更新状态
					hookStatus.pLastActiveHookPageVirtAddr = NULL;
					hookStatus.premissionStatus = CoreNptHookStatus::PremissionStatus::HookPageNotExecuted;
				}

				pVirtCpuInfo->guestVmcb.controlFields.tlbControl = 0x3;

				result = true;
			}
			else
			{
				__debugbreak();
			}
		}
	}

	return result;
}

#pragma code_seg()
bool NptHookManager::HandleCpuid(VirtCpuInfo* pVirtCpuInfo, GenericRegisters* pGuestRegisters, PVOID pGuestVmcbPhyAddr, PVOID pHostVmcbPhyAddr)
{
	UNREFERENCED_PARAMETER(pGuestVmcbPhyAddr);
	UNREFERENCED_PARAMETER(pHostVmcbPhyAddr);

	auto switchPageTable = [this](PageTableType type) -> PageTableManager*
	{
		switch (type)
		{
		case ExternalPageTable:
			return pPageTableManager;
		case InternalPageTable:
			return &internalPageTableManager;
		default:
			KeBugCheck(MANUALLY_INITIATED_CRASH);
			break;
		}
	};

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

			PageTableManager* pTargetPageTableManager = switchPageTable(pInfo->type);

			status = pTargetPageTableManager->GetCoreNptPageTables()[pInfo->cpuIdx].UsingSmallPage(pInfo->pLevel3PhyAddr, !pInfo->beLarge);

			pGuestRegisters->rbx = status;

			if (NT_SUCCESS(status) && !pInfo->beLarge)
			{
				status = pTargetPageTableManager->GetCoreNptPageTables()[pInfo->cpuIdx].MapSmallPageByPhyAddr(pInfo->pLevel3PhyAddr, pInfo->pLevel3PhyAddr + 0x200000);
				if (!NT_SUCCESS(status))
				{
					pGuestRegisters->rbx = status;
					pTargetPageTableManager->GetCoreNptPageTables()[pInfo->cpuIdx].UsingSmallPage(pInfo->pLevel3PhyAddr, !pInfo->beLarge);
				}
			}

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

			PageTableManager* pTargetPageTableManager = switchPageTable(pInfo->type);

			status = pTargetPageTableManager->GetCoreNptPageTables()[pInfo->cpuIdx].ChangePageTablePermession(pInfo->physicalAddress, pInfo->permission, pInfo->level);

			pGuestRegisters->rbx = status;

			break;
		}
		case SWAP_SMALL_PAGE_PPN_CPUID_SUBFUNCTION:
		{
			const SwapSmallPagePpnInfo* pInfo = (SwapSmallPagePpnInfo*)pGuestRegisters->rdx;

			PageTableManager* pTargetPageTableManager = switchPageTable(pInfo->type);

			status = pTargetPageTableManager->GetCoreNptPageTables()[pInfo->cpuIdx].SwapSmallPagePpn(pInfo->physicalAddress1, pInfo->physicalAddress2);

			pGuestRegisters->rbx = status;

			break;
		}
		case ADD_HOOK_ITEM_CPUID_SUBFUNCTION:
		{
			sharedData.hookRecords.PushBack(*((const HookRecord*)pGuestRegisters->rdx));
			break;
		}
		case REMOVE_HOOK_ITEM_CPUID_SUBFUNCTION:
		{
			sharedData.hookRecords.Remove((SIZE_TYPE)pGuestRegisters->rdx);
			break;
		}
		case ADD_LEVEL3_REF_ITEM_CPUID_SUBFUNCTION:
		{
			const SmallPageLevel3RefCnt* pInfo = (const SmallPageLevel3RefCnt*)pGuestRegisters->rdx;

			if (!pInfo->refCnt)
				KeBugCheck(MANUALLY_INITIATED_CRASH);

			sharedData.level3Refs.PushBack(*pInfo);
			break;
		}
		case REMOVE_LEVEL3_REF_ITEM_CPUID_SUBFUNCTION:
		{
			if (!sharedData.level3Refs[pGuestRegisters->rdx].refCnt)
			{
				sharedData.level3Refs.Remove((SIZE_TYPE)pGuestRegisters->rdx);
				pGuestRegisters->rbx = true;
			}
			else
			{
				pGuestRegisters->rbx = false;
			}
			break;
		}
		case ADD_SWAPPAGE_REF_CNT_CPUID_SUBFUNCTION:
		{
			const SwapPageRefCnt* pInfo = (const SwapPageRefCnt*)pGuestRegisters->rdx;

			if (!pInfo->refCnt)
				KeBugCheck(MANUALLY_INITIATED_CRASH);

			sharedData.swapPageRefs.PushBack(*pInfo);
			break;
		}
		case REMOVE_SWAPPAGE_REF_CNT_CPUID_SUBFUNCTION:
		{
			if (!sharedData.swapPageRefs[pGuestRegisters->rdx].refCnt)
			{
				sharedData.swapPageRefs.Remove((SIZE_TYPE)pGuestRegisters->rdx);
				pGuestRegisters->rbx = true;
			}
			else
			{
				pGuestRegisters->rbx = false;
			}
			break;
		}
		case ALLOC_NONPAGED_EXECUTEABLE_MEMORY_CPUID_SUBFUNCTION:
		{
			pGuestRegisters->rbx = (PTR_TYPE)AllocExecutableNonPagedMem(pGuestRegisters->rdx, HOOK_TAG);
			break;
		}
		case FREE_NONPAGED_EXECUTEABLE_MEMORY_CPUID_SUBFUNCTION:
		{
			FreeExecutableNonPagedMem((PVOID)pGuestRegisters->rdx, HOOK_TAG);
			break;
		}
		case ALLOC_NONPAGED_MEMORY_CPUID_SUBFUNCTION:
		{
			pGuestRegisters->rbx = (PTR_TYPE)AllocNonPagedMem(pGuestRegisters->rdx, HOOK_TAG);
			break;
		}
		case FREE_NONPAGED_MEMORY_CPUID_SUBFUNCTION:
		{
			FreeNonPagedMem((PVOID)pGuestRegisters->rdx, HOOK_TAG);
			break;
		}
		case OPERATE_REF_COUNT_CPUID_SUBFUNCTION:
		{
			OperateRefCountInfo* pInfo = (OperateRefCountInfo*)pGuestRegisters->rdx;

			PTR_TYPE* pOperationObject = NULL;

			switch (pInfo->objectType)
			{
			case RefCountOperationObjectType::SwapPageRefCntObject:
			{
				pOperationObject = &sharedData.swapPageRefs[pInfo->idx].refCnt;
				break;
			}
			case RefCountOperationObjectType::Level3RefObject:
			{
				pOperationObject = &sharedData.level3Refs[pInfo->idx].refCnt;
				break;
			}
			default:
				break;
			}

			if (pOperationObject != NULL)
			{
				switch (pInfo->operationType)
				{
				case RefCountOperationType::IncrementCount:
				{
					++(*pOperationObject);
					break;
				}
				case RefCountOperationType::DecrementCount:
				{
					--(*pOperationObject);
					break;
				}
				default:
					break;
				}
			}

			break;
		}
		case COPY_HOOKRECORD_CPUID_SUBFUNCTION:
		{
			HookRecord* pDestnation = (HookRecord*)pGuestRegisters->rbx;
			*pDestnation = sharedData.hookRecords[pGuestRegisters->rdx];
			break;
		}
		case COPY_SWAPPAGE_REF_CNT_CPUID_SUBFUNCTION:
		{
			SwapPageRefCnt* pDestnation = (SwapPageRefCnt*)pGuestRegisters->rbx;
			*pDestnation = sharedData.swapPageRefs[pGuestRegisters->rdx];
			break;
		}
		case COPY_LEVEL3_REF_ITEM_CPUID_SUBFUNCTION:
		{
			SmallPageLevel3RefCnt* pDestnation = (SmallPageLevel3RefCnt*)pGuestRegisters->rbx;
			*pDestnation = sharedData.level3Refs[pGuestRegisters->rdx];
			break;
		}
		case COPY_SHARED_DATA_CPUID_SUBFUNCTION:
		{
			NptHookSharedData* pNewCopy = (NptHookSharedData*)AllocNonPagedMem(sizeof(NptHookSharedData), HOOK_TAG);
			if (pNewCopy == NULL)
			{
				pGuestRegisters->rbx = NULL;
				break;
			}
			CallConstructor(pNewCopy, sharedData);
			pGuestRegisters->rbx = (PTR_TYPE)pNewCopy;
			break;
		}
		case DESTROY_SHARED_DATA_COPY_CPUID_SUBFUNCTION:
		{
			CallDestroyer((NptHookSharedData*)pGuestRegisters->rdx);
			FreeNonPagedMem((NptHookSharedData*)pGuestRegisters->rdx, HOOK_TAG);
			break;
		}
		case RESTORE_CR3_CPUID_SUBFUNCTION:
		{
			pVirtCpuInfo->guestVmcb.controlFields.nCr3 = MmGetPhysicalAddress((PVOID)pPageTableManager->GetCoreNptPageTables()[pGuestRegisters->rdx].GetNptPageTable()).QuadPart;
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
NTSTATUS NptHookManager::ChangeLargePageToSmallPage(PTR_TYPE pOriginLevel3PhyAddr, PageTableType type)
{
	NTSTATUS result = STATUS_SUCCESS;
	SIZE_TYPE cpuCnt = KeQueryActiveProcessorCountEx(ALL_PROCESSOR_GROUPS);

	PTR_TYPE regs[4] = {};
	ChangePageSizeInfo info = {};

	info.beLarge = false;
	info.pLevel3PhyAddr = pOriginLevel3PhyAddr;
	info.type = type;

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
			result = (NTSTATUS)regs[1];
			break;
		}
	}

	return result;
}

#pragma code_seg("PAGE")
NTSTATUS NptHookManager::ChangeSmallPageToLargePage(PTR_TYPE pOriginLevel3PhyAddr, PageTableType type)
{
	NTSTATUS result = STATUS_SUCCESS;
	SIZE_TYPE cpuCnt = KeQueryActiveProcessorCountEx(ALL_PROCESSOR_GROUPS);

	PTR_TYPE regs[4] = {};
	ChangePageSizeInfo info = {};

	info.beLarge = true;
	info.pLevel3PhyAddr = pOriginLevel3PhyAddr;
	info.type = type;

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
			result = (NTSTATUS)regs[1];
			break;
		}
	}

	return result;
}

#pragma code_seg("PAGE")
NTSTATUS NptHookManager::ChangePageTablePermission(PTR_TYPE physicalAddress, PageTableLevel123Entry permission, PageTableType type, UINT32 level)
{
	NTSTATUS status = STATUS_SUCCESS;
	SIZE_TYPE cpuCnt = KeQueryActiveProcessorCountEx(ALL_PROCESSOR_GROUPS);

	PTR_TYPE regs[4] = {};
	ChangePageTablePermissionInfo info = {};

	info.physicalAddress = physicalAddress;
	info.permission = permission;
	info.level = level;
	info.type = type;

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

#pragma code_seg("PAGE")
NTSTATUS NptHookManager::SwapSmallPagePpn(PTR_TYPE physicalAddrees1, PTR_TYPE physicalAddress2, PageTableType type)
{
	NTSTATUS status = STATUS_SUCCESS;
	SIZE_TYPE cpuCnt = KeQueryActiveProcessorCountEx(ALL_PROCESSOR_GROUPS);

	PTR_TYPE regs[4] = {};

	PROCESSOR_NUMBER processorNum = {};
	GROUP_AFFINITY affinity = {}, oldAffinity = {};

	SwapSmallPagePpnInfo info = {};

	info.physicalAddress1 = physicalAddrees1;
	info.physicalAddress2 = physicalAddress2;
	info.type = type;

	for (ULONG idx = 0; idx < cpuCnt; ++idx)
	{
		KeGetProcessorNumberFromIndex(idx, &processorNum);
		affinity = {};
		affinity.Group = processorNum.Group;
		affinity.Mask = 1ULL << processorNum.Number;
		KeSetSystemGroupAffinityThread(&affinity, &oldAffinity);

		regs[0] = NPT_HOOK_TOOL_CPUID_FUNCTION;
		regs[1] = 0;
		regs[2] = SWAP_SMALL_PAGE_PPN_CPUID_SUBFUNCTION;
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
NTSTATUS NptHookManager::CancelHookOperation(const SwapPageRefCnt& swapPageInfo)
{
	NTSTATUS status = STATUS_SUCCESS;
	SIZE_TYPE cpuCnt = KeQueryActiveProcessorCountEx(ALL_PROCESSOR_GROUPS);

	PTR_TYPE regs[4] = {};

	PROCESSOR_NUMBER processorNum = {};
	GROUP_AFFINITY affinity = {}, oldAffinity = {};

	PageTableLevel123Entry permission = {};
	permission.fields.writeable = true;
	permission.fields.userAccess = true;

	ChangePageTablePermissionInfo info = {};

	SwapSmallPagePpnInfo info2 = {};

	info.permission = permission;
	info.level = 1;

	regs[0] = NPT_HOOK_TOOL_CPUID_FUNCTION;
	regs[1] = NULL;
	regs[2] = GET_PHYSICAL_ADDRESS_SUBFUNCTION;
	regs[3] = (PTR_TYPE)swapPageInfo.pOriginVirtAddr;

	SetRegsThenCpuid(&regs[0], &regs[1], &regs[2], &regs[3]);

	info.physicalAddress = regs[1];
	info2.physicalAddress1 = regs[1];
	info.type = PageTableType::ExternalPageTable;

	regs[0] = NPT_HOOK_TOOL_CPUID_FUNCTION;
	regs[1] = NULL;
	regs[2] = GET_PHYSICAL_ADDRESS_SUBFUNCTION;
	regs[3] = (PTR_TYPE)swapPageInfo.pSwapVirtAddr;

	SetRegsThenCpuid(&regs[0], &regs[1], &regs[2], &regs[3]);

	info2.physicalAddress2 = regs[1];
	info2.type = PageTableType::InternalPageTable;

	for (ULONG idx = 0; idx < cpuCnt; ++idx)
	{
		KeGetProcessorNumberFromIndex(idx, &processorNum);
		affinity = {};
		affinity.Group = processorNum.Group;
		affinity.Mask = 1ULL << processorNum.Number;
		KeSetSystemGroupAffinityThread(&affinity, &oldAffinity);

		do
		{
			//还原物理页面交换
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
			//内部NPT页表恢复执行禁止
			permission.fields.executionDisabled = true;

			regs[0] = NPT_HOOK_TOOL_CPUID_FUNCTION;
			regs[1] = 0;
			regs[2] = CHANGE_PAGE_TABLE_PERMISSION_CPUID_SUBFUNCTION;
			regs[3] = (PTR_TYPE)&info;

			info.type = PageTableType::InternalPageTable;
			info.cpuIdx = idx;

			SetRegsThenCpuid(&regs[0], &regs[1], &regs[2], &regs[3]);

			if (!NT_SUCCESS(regs[1]))
			{
				status = (NTSTATUS)regs[1];
				break;
			}
			//外部NPT页表恢复可执行
			permission.fields.executionDisabled = false;

			regs[0] = NPT_HOOK_TOOL_CPUID_FUNCTION;
			regs[1] = 0;
			regs[2] = CHANGE_PAGE_TABLE_PERMISSION_CPUID_SUBFUNCTION;
			regs[3] = (PTR_TYPE)&info;

			info.type = PageTableType::ExternalPageTable;
			info.cpuIdx = idx;

			SetRegsThenCpuid(&regs[0], &regs[1], &regs[2], &regs[3]);

			if (!NT_SUCCESS(regs[1]))
			{
				status = (NTSTATUS)regs[1];
				break;
			}
			//NCR3切换到外部NPT页表
			regs[0] = NPT_HOOK_TOOL_CPUID_FUNCTION;
			regs[1] = NULL;
			regs[2] = RESTORE_CR3_CPUID_SUBFUNCTION;
			regs[3] = idx;

			SetRegsThenCpuid(&regs[0], &regs[1], &regs[2], &regs[3]);

		} while (false);

		KeRevertToUserGroupAffinityThread(&oldAffinity);

		if (!NT_SUCCESS(status))
			break;
	}

	return status;
}

#pragma code_seg("PAGE")
void NptHookManager::SyncSharedData()
{
	PTR_TYPE  regs[4] = {};

	SIZE_TYPE cpuCnt = KeQueryActiveProcessorCountEx(ALL_PROCESSOR_GROUPS);

	PROCESSOR_NUMBER processorNum = {};
	GROUP_AFFINITY affinity = {}, oldAffinity = {};

	//拷贝共享数据
	regs[0] = NPT_HOOK_TOOL_CPUID_FUNCTION;
	regs[1] = NULL;
	regs[2] = COPY_SHARED_DATA_CPUID_SUBFUNCTION;
	regs[3] = NULL;
	
	SetRegsThenCpuid(&regs[0], &regs[1], &regs[2], &regs[3]);

	//拷贝失败咋蓝屏
	if (regs[1] == NULL)
		KeBugCheck(MEMORY_MANAGEMENT);

	//同步数据
	for (ULONG idx = 0; idx < cpuCnt; ++idx)
	{
		KeGetProcessorNumberFromIndex(idx, &processorNum);
		affinity = {};
		affinity.Group = processorNum.Group;
		affinity.Mask = 1ULL << processorNum.Number;
		KeSetSystemGroupAffinityThread(&affinity, &oldAffinity);

		pCoreNptHookStatus[idx].pSharedData = (NptHookSharedData*)regs[1];

		KeRevertToUserGroupAffinityThread(&oldAffinity);
	}

	//释放旧数据
	if (pSharedDataCopy != NULL)
	{
		regs[0] = NPT_HOOK_TOOL_CPUID_FUNCTION;
		regs[1] = NULL;
		regs[2] = DESTROY_SHARED_DATA_COPY_CPUID_SUBFUNCTION;
		regs[3] = (PTR_TYPE)pSharedDataCopy;

		SetRegsThenCpuid(&regs[0], &regs[1], &regs[2], &regs[3]);
	}

	//写入当前拷贝的指针
	pSharedDataCopy = (NptHookSharedData*)regs[1];
}

#pragma code_seg("PAGE")
NTSTATUS NptHookManager::AddHook(const HookRecord& record)
{
	NTSTATUS status = STATUS_SUCCESS;
	PTR_TYPE pOriginPhyAddr = NULL;
	PTR_TYPE pOriginPageVirtAddr = (PTR_TYPE)record.pOriginVirtAddr & 0xfffffffffffff000;
	SIZE_TYPE level3RefIdx = INVALID_INDEX;
	SIZE_TYPE swapPageIdx = INVALID_INDEX;
	SIZE_TYPE hookIdx = INVALID_INDEX;
	UINT8* swapPageVirtAddr = NULL;
	PTR_TYPE swapPagePhyAddr = INVALID_ADDR;
	bool allocedNewSwapPage = false;
	bool needChangePagePermission = false;
	PTR_TYPE regs[4] = {};
	MemoryCopyInfo copyMemInfo = {};
	OperateRefCountInfo operateRefInfo = {};
	SwapPageRefCnt swapPageRefCnt = {};
	PageTableLevel123Entry permission = {};
	int stepCnt = 0;
	
	do
	{
		hookIdx = sharedData.FindHookRecordByOriginVirtAddr(record.pOriginVirtAddr);

		if (hookIdx != INVALID_INDEX)
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

		swapPageIdx = sharedData.FindSwapPageRefCntByOriginVirtAddr((PVOID)pOriginPageVirtAddr);

		if (swapPageIdx == INVALID_INDEX)
		{
			regs[0] = NPT_HOOK_TOOL_CPUID_FUNCTION;
			regs[1] = NULL;
			regs[2] = ALLOC_NONPAGED_EXECUTEABLE_MEMORY_CPUID_SUBFUNCTION;
			regs[3] = PAGE_SIZE;

			SetRegsThenCpuid(&regs[0], &regs[1], &regs[2], &regs[3]);

			swapPageVirtAddr = (UINT8*)regs[1];

			if (swapPageVirtAddr == NULL)
			{
				status = STATUS_INSUFFICIENT_RESOURCES;
				break;
			}

			//拷贝数据
			copyMemInfo.pSource = (PVOID)pOriginPageVirtAddr;
			copyMemInfo.pDestination = swapPageVirtAddr;
			copyMemInfo.Length = PAGE_SIZE;

			regs[0] = NPT_HOOK_TOOL_CPUID_FUNCTION;
			regs[1] = NULL;
			regs[2] = COPY_MEMORY_CPUID_SUBFUNCTION;
			regs[3] = (PTR_TYPE)&copyMemInfo;

			SetRegsThenCpuid(&regs[0], &regs[1], &regs[2], &regs[3]);
			//写入断点
			UINT8 hookData = NptHookCode;

			copyMemInfo.pSource = &hookData;
			copyMemInfo.pDestination = (UINT8*)swapPageVirtAddr + ((PTR_TYPE)record.pOriginVirtAddr & 0xfff);
			copyMemInfo.Length = 1;

			regs[0] = NPT_HOOK_TOOL_CPUID_FUNCTION;
			regs[1] = NULL;
			regs[2] = COPY_MEMORY_CPUID_SUBFUNCTION;
			regs[3] = (PTR_TYPE)&copyMemInfo;

			SetRegsThenCpuid(&regs[0], &regs[1], &regs[2], &regs[3]);
			//标记新分配了交换页
			allocedNewSwapPage = true;

			//插入交换页对条目
			SwapPageRefCnt newItem = {};

			newItem.pOriginVirtAddr = (PVOID)pOriginPageVirtAddr;
			newItem.pSwapVirtAddr= swapPageVirtAddr;
			newItem.refCnt = 1;

			regs[0] = NPT_HOOK_TOOL_CPUID_FUNCTION;
			regs[1] = NULL;
			regs[2] = ADD_SWAPPAGE_REF_CNT_CPUID_SUBFUNCTION;
			regs[3] = (PTR_TYPE)&newItem;

			SetRegsThenCpuid(&regs[0], &regs[1], &regs[2], &regs[3]);

			//拷贝数据待用
			swapPageRefCnt = newItem;
		}
		else
		{
			//获取交换页对条目
			regs[0] = NPT_HOOK_TOOL_CPUID_FUNCTION;
			regs[1] = (PTR_TYPE)&swapPageRefCnt;
			regs[2] = COPY_SWAPPAGE_REF_CNT_CPUID_SUBFUNCTION;
			regs[3] = swapPageIdx;

			//增加引用计数
			operateRefInfo.idx = swapPageIdx;
			operateRefInfo.objectType = RefCountOperationObjectType::SwapPageRefCntObject;
			operateRefInfo.operationType = RefCountOperationType::IncrementCount;

			regs[0] = NPT_HOOK_TOOL_CPUID_FUNCTION;
			regs[1] = NULL;
			regs[2] = OPERATE_REF_COUNT_CPUID_SUBFUNCTION;
			regs[3] = (PTR_TYPE)&operateRefInfo;

			SetRegsThenCpuid(&regs[0], &regs[1], &regs[2], &regs[3]);

			//写入断点
			UINT8 hookData = NptHookCode;
			
			copyMemInfo.pSource = &hookData;
			copyMemInfo.pDestination = (UINT8*)swapPageRefCnt.pSwapVirtAddr + ((PTR_TYPE)record.pOriginVirtAddr & 0xfff);
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

		level3RefIdx = sharedData.FindSmallPageLevel3RefCntByPhyAddr(swapPagePhyAddr & 0xFFFFFFFFFFE00000);

		if (level3RefIdx == INVALID_INDEX)
		{
			//如果没有查询到为小页的记录，就设置为小页，并新增记录
			status = ChangeLargePageToSmallPage(swapPagePhyAddr & 0xFFFFFFFFFFE00000, PageTableType::ExternalPageTable);
			if (!NT_SUCCESS(status))
				break;

			status = ChangeLargePageToSmallPage(swapPagePhyAddr & 0xFFFFFFFFFFE00000, PageTableType::InternalPageTable);
			if (!NT_SUCCESS(status))
				break;

			permission.fields.writeable = true;
			permission.fields.userAccess = true;
			permission.fields.executionDisabled = false;

			status = ChangePageTablePermission(swapPagePhyAddr & 0xFFFFFFFFFFE00000, permission, PageTableType::InternalPageTable, 2);
			if (!NT_SUCCESS(status))
				break;

			SmallPageLevel3RefCnt newItem = {};

			newItem.level3PhyAddr = swapPagePhyAddr & 0xFFFFFFFFFFE00000;
			newItem.refCnt = 1;

			regs[0] = NPT_HOOK_TOOL_CPUID_FUNCTION;
			regs[1] = NULL;
			regs[2] = ADD_LEVEL3_REF_ITEM_CPUID_SUBFUNCTION;
			regs[3] = (PTR_TYPE)&newItem;

			SetRegsThenCpuid(&regs[0], &regs[1], &regs[2], &regs[3]);
		}
		else
		{
			//否则，递增引用计数
			operateRefInfo.idx = level3RefIdx;
			operateRefInfo.objectType = RefCountOperationObjectType::Level3RefObject;
			operateRefInfo.operationType = RefCountOperationType::IncrementCount;

			regs[0] = NPT_HOOK_TOOL_CPUID_FUNCTION;
			regs[1] = NULL;
			regs[2] = OPERATE_REF_COUNT_CPUID_SUBFUNCTION;
			regs[3] = (PTR_TYPE)&operateRefInfo;

			SetRegsThenCpuid(&regs[0], &regs[1], &regs[2], &regs[3]);
		}

		stepCnt = 3;

		//设置原始页对应的页表为小页
		//先查询是否有设置为小页的记录

		level3RefIdx = sharedData.FindSmallPageLevel3RefCntByPhyAddr(pOriginPhyAddr & 0xFFFFFFFFFFE00000);

		if (level3RefIdx == INVALID_INDEX)
		{
			//如果没有查询到为小页的记录，就设置为小页，设置权限，并新增记录
			status = ChangeLargePageToSmallPage(pOriginPhyAddr & 0xFFFFFFFFFFE00000, PageTableType::ExternalPageTable);
			if (!NT_SUCCESS(status))
				break;

			status = ChangeLargePageToSmallPage(pOriginPhyAddr & 0xFFFFFFFFFFE00000, PageTableType::InternalPageTable);
			if (!NT_SUCCESS(status))
				break;

			permission.fields.writeable = true;
			permission.fields.userAccess = true;
			permission.fields.executionDisabled = false;

			status = ChangePageTablePermission(pOriginPhyAddr & 0xFFFFFFFFFFE00000, permission, PageTableType::InternalPageTable, 2);
			if (!NT_SUCCESS(status))
				break;

			needChangePagePermission = true;

			SmallPageLevel3RefCnt newItem = {};

			newItem.level3PhyAddr = pOriginPhyAddr & 0xFFFFFFFFFFE00000;
			newItem.refCnt = 1;

			regs[0] = NPT_HOOK_TOOL_CPUID_FUNCTION;
			regs[1] = NULL;
			regs[2] = ADD_LEVEL3_REF_ITEM_CPUID_SUBFUNCTION;
			regs[3] = (PTR_TYPE)&newItem;

			SetRegsThenCpuid(&regs[0], &regs[1], &regs[2], &regs[3]);
		}
		else
		{
			//否则，递增引用计数
			operateRefInfo.idx = level3RefIdx;
			operateRefInfo.objectType = RefCountOperationObjectType::Level3RefObject;
			operateRefInfo.operationType = RefCountOperationType::IncrementCount;

			regs[0] = NPT_HOOK_TOOL_CPUID_FUNCTION;
			regs[1] = NULL;
			regs[2] = OPERATE_REF_COUNT_CPUID_SUBFUNCTION;
			regs[3] = (PTR_TYPE)&operateRefInfo;

			SetRegsThenCpuid(&regs[0], &regs[1], &regs[2], &regs[3]);
		}

		//插入到hook条目
		regs[0] = NPT_HOOK_TOOL_CPUID_FUNCTION;
		regs[1] = NULL;
		regs[2] = ADD_HOOK_ITEM_CPUID_SUBFUNCTION;
		regs[3] = (PTR_TYPE)&record;

		SetRegsThenCpuid(&regs[0], &regs[1], &regs[2], &regs[3]);

		//同步共享数据到每个核心
		SyncSharedData();

	} while (false);

	//对新hook执行权限修改
	if (NT_SUCCESS(status) && needChangePagePermission)
	{
		PTR_TYPE tempPhyAddr1 = MmGetPhysicalAddress((PVOID)swapPageRefCnt.pOriginVirtAddr).QuadPart;
		PTR_TYPE tempPhyAddr2 = MmGetPhysicalAddress(swapPageRefCnt.pSwapVirtAddr).QuadPart;

		SwapSmallPagePpn(tempPhyAddr1, tempPhyAddr2, PageTableType::InternalPageTable);

		permission.fields.writeable = true;
		permission.fields.userAccess = true;
		permission.fields.executionDisabled = true;

		ChangePageTablePermission(pOriginPhyAddr & 0xFFFFFFFFFFFF000, permission, PageTableType::ExternalPageTable, 1);
	}

	//失败撤回操作
	if (!NT_SUCCESS(status))
	{
		switch (stepCnt)
		{
		case 3:
		{
			if (level3RefIdx == INVALID_INDEX)
			{
				ChangeSmallPageToLargePage(pOriginPhyAddr & 0xFFFFFFFFFFE00000, PageTableType::ExternalPageTable);
				ChangeSmallPageToLargePage(pOriginPhyAddr & 0xFFFFFFFFFFE00000, PageTableType::InternalPageTable);

				permission.fields.writeable = true;
				permission.fields.userAccess = true;
				permission.fields.executionDisabled = true;

				ChangePageTablePermission(pOriginPhyAddr & 0xFFFFFFFFFFE00000, permission, PageTableType::InternalPageTable, 2);

				level3RefIdx = sharedData.FindSmallPageLevel3RefCntByPhyAddr(pOriginPhyAddr & 0xFFFFFFFFFFE00000);

				regs[0] = NPT_HOOK_TOOL_CPUID_FUNCTION;
				regs[1] = NULL;
				regs[2] = REMOVE_LEVEL3_REF_ITEM_CPUID_SUBFUNCTION;
				regs[3] = (PTR_TYPE)level3RefIdx;

				SetRegsThenCpuid(&regs[0], &regs[1], &regs[2], &regs[3]);
			}
			else
			{
				//递减小页引用计数
				operateRefInfo.idx = level3RefIdx;
				operateRefInfo.objectType = RefCountOperationObjectType::Level3RefObject;
				operateRefInfo.operationType = RefCountOperationType::DecrementCount;

				regs[0] = NPT_HOOK_TOOL_CPUID_FUNCTION;
				regs[1] = NULL;
				regs[2] = OPERATE_REF_COUNT_CPUID_SUBFUNCTION;
				regs[3] = (PTR_TYPE)&operateRefInfo;

				SetRegsThenCpuid(&regs[0], &regs[1], &regs[2], &regs[3]);
			}
			break;
		}
		case 2:
		{
			level3RefIdx = sharedData.FindSmallPageLevel3RefCntByPhyAddr(swapPagePhyAddr & 0xFFFFFFFFFFE00000);

			//递减小页引用计数
			operateRefInfo.idx = level3RefIdx;
			operateRefInfo.objectType = RefCountOperationObjectType::Level3RefObject;
			operateRefInfo.operationType = RefCountOperationType::DecrementCount;

			regs[0] = NPT_HOOK_TOOL_CPUID_FUNCTION;
			regs[1] = NULL;
			regs[2] = OPERATE_REF_COUNT_CPUID_SUBFUNCTION;
			regs[3] = (PTR_TYPE)&operateRefInfo;

			SetRegsThenCpuid(&regs[0], &regs[1], &regs[2], &regs[3]);

			//尝试删除小页和清理
			regs[0] = NPT_HOOK_TOOL_CPUID_FUNCTION;
			regs[1] = NULL;
			regs[2] = REMOVE_LEVEL3_REF_ITEM_CPUID_SUBFUNCTION;
			regs[3] = level3RefIdx;

			SetRegsThenCpuid(&regs[0], &regs[1], &regs[2], &regs[3]);

			if (regs[1])
			{
				ChangeSmallPageToLargePage(swapPagePhyAddr & 0xFFFFFFFFFFE00000, PageTableType::ExternalPageTable);
				ChangeSmallPageToLargePage(swapPagePhyAddr & 0xFFFFFFFFFFE00000, PageTableType::InternalPageTable);

				permission.fields.writeable = true;
				permission.fields.userAccess = true;
				permission.fields.executionDisabled = true;

				ChangePageTablePermission(swapPagePhyAddr & 0xFFFFFFFFFFE00000, permission, PageTableType::InternalPageTable, 2);
			}

			break;
		}
		case 1:
		{
			copyMemInfo.pSource = (UINT8*)swapPageRefCnt.pOriginVirtAddr + ((PTR_TYPE)record.pOriginVirtAddr & 0xfff);
			copyMemInfo.pDestination = (UINT8*)swapPageRefCnt.pSwapVirtAddr + ((PTR_TYPE)record.pOriginVirtAddr & 0xfff);
			copyMemInfo.Length = 1;

			regs[0] = NPT_HOOK_TOOL_CPUID_FUNCTION;
			regs[1] = NULL;
			regs[2] = COPY_MEMORY_CPUID_SUBFUNCTION;
			regs[3] = (PTR_TYPE)&copyMemInfo;

			SetRegsThenCpuid(&regs[0], &regs[1], &regs[2], &regs[3]);

			if (allocedNewSwapPage)
			{
				//释放内存
				regs[0] = NPT_HOOK_TOOL_CPUID_FUNCTION;
				regs[1] = NULL;
				regs[2] = FREE_NONPAGED_EXECUTEABLE_MEMORY_CPUID_SUBFUNCTION;
				regs[3] = (PTR_TYPE)swapPageVirtAddr;

				SetRegsThenCpuid(&regs[0], &regs[1], &regs[2], &regs[3]);

				//递减交换页引用计数
				operateRefInfo.idx = swapPageIdx;
				operateRefInfo.objectType = RefCountOperationObjectType::SwapPageRefCntObject;
				operateRefInfo.operationType = RefCountOperationType::DecrementCount;

				regs[0] = NPT_HOOK_TOOL_CPUID_FUNCTION;
				regs[1] = NULL;
				regs[2] = OPERATE_REF_COUNT_CPUID_SUBFUNCTION;
				regs[3] = (PTR_TYPE)&operateRefInfo;

				SetRegsThenCpuid(&regs[0], &regs[1], &regs[2], &regs[3]);

				//删除交换页引用计数
				regs[0] = NPT_HOOK_TOOL_CPUID_FUNCTION;
				regs[1] = NULL;
				regs[2] = REMOVE_SWAPPAGE_REF_CNT_CPUID_SUBFUNCTION;
				regs[3] = (PTR_TYPE)swapPageIdx;

				SetRegsThenCpuid(&regs[0], &regs[1], &regs[2], &regs[3]);
			}
			else
			{
				//递减交换页引用计数
				operateRefInfo.idx = swapPageIdx;
				operateRefInfo.objectType = RefCountOperationObjectType::SwapPageRefCntObject;
				operateRefInfo.operationType = RefCountOperationType::DecrementCount;

				regs[0] = NPT_HOOK_TOOL_CPUID_FUNCTION;
				regs[1] = NULL;
				regs[2] = OPERATE_REF_COUNT_CPUID_SUBFUNCTION;
				regs[3] = (PTR_TYPE)&operateRefInfo;

				SetRegsThenCpuid(&regs[0], &regs[1], &regs[2], &regs[3]);
			}
			break;
		}
		case 0:
		default:
			break;
		}
	}

	return status;
}

#pragma code_seg("PAGE")
NTSTATUS NptHookManager::RemoveHook(PVOID pHookOriginVirtAddr)
{
	NTSTATUS status = STATUS_SUCCESS;

	SIZE_TYPE hookIdx = INVALID_INDEX;
	PTR_TYPE pOriginPhyAddr = INVALID_ADDR;
	PTR_TYPE pOriginPageVirtAddr = NULL;;
	SIZE_TYPE level3RefIdx = INVALID_INDEX;
	SIZE_TYPE swapPageIdx = INVALID_INDEX;
	PTR_TYPE swapPagePhyAddr = INVALID_ADDR;
	HookRecord record = {};
	PTR_TYPE regs[4] = {};
	MemoryCopyInfo copyMemInfo = {};
	OperateRefCountInfo operateRefInfo = {};
	SwapPageRefCnt swapPageRefCnt = {};
	PageTableLevel123Entry permission = {};

	bool originPageToLargePage = false;
	bool swapPageToLargePage = false;
	bool restoreHookSwap = false;

	do
	{
		//查询hook记录是否存在
		hookIdx = sharedData.FindHookRecordByOriginVirtAddr(pHookOriginVirtAddr);
		if (hookIdx == INVALID_INDEX)
		{
			status = STATUS_NOT_FOUND;
			break;
		}

		//拷贝hook记录数据
		regs[0] = NPT_HOOK_TOOL_CPUID_FUNCTION;
		regs[1] = (PTR_TYPE)&record;
		regs[2] = COPY_HOOKRECORD_CPUID_SUBFUNCTION;
		regs[3] = hookIdx;

		SetRegsThenCpuid(&regs[0], &regs[1], &regs[2], &regs[3]);

		//计算hook原始页面的起始地址
		pOriginPageVirtAddr = (PTR_TYPE)record.pOriginVirtAddr & 0xFFFFFFFFFFFFF000;

		//获取hook原始虚拟地址的物理地址
		regs[0] = NPT_HOOK_TOOL_CPUID_FUNCTION;
		regs[1] = NULL;
		regs[2] = GET_PHYSICAL_ADDRESS_SUBFUNCTION;
		regs[3] = (PTR_TYPE)record.pOriginVirtAddr;

		SetRegsThenCpuid(&regs[0], &regs[1], &regs[2], &regs[3]);
		pOriginPhyAddr = regs[1];

		//根据原始页面的物理地址查询小页引用计数
		level3RefIdx = sharedData.FindSmallPageLevel3RefCntByPhyAddr(pOriginPhyAddr & 0xFFFFFFFFFFE00000);
		if (level3RefIdx != INVALID_INDEX)
		{
			//递减小页引用计数
			operateRefInfo.idx = level3RefIdx;
			operateRefInfo.objectType = RefCountOperationObjectType::Level3RefObject;
			operateRefInfo.operationType = RefCountOperationType::DecrementCount;

			regs[0] = NPT_HOOK_TOOL_CPUID_FUNCTION;
			regs[1] = NULL;
			regs[2] = OPERATE_REF_COUNT_CPUID_SUBFUNCTION;
			regs[3] = (PTR_TYPE)&operateRefInfo;

			SetRegsThenCpuid(&regs[0], &regs[1], &regs[2], &regs[3]);

			//尝试删除小页和清理
			regs[0] = NPT_HOOK_TOOL_CPUID_FUNCTION;
			regs[1] = NULL;
			regs[2] = REMOVE_LEVEL3_REF_ITEM_CPUID_SUBFUNCTION;
			regs[3] = level3RefIdx;

			SetRegsThenCpuid(&regs[0], &regs[1], &regs[2], &regs[3]);

			if (regs[1])
				originPageToLargePage = true;
				
		}

		//根据hook原始页面大的起始地址查询交换页引用计数
		swapPageIdx = sharedData.FindSwapPageRefCntByOriginVirtAddr((PVOID)pOriginPageVirtAddr);
		if (swapPageIdx != INVALID_INDEX)
		{
			//获取交换页的物理地址
			regs[0] = NPT_HOOK_TOOL_CPUID_FUNCTION;
			regs[1] = (PTR_TYPE)&swapPageRefCnt;
			regs[2] = COPY_SWAPPAGE_REF_CNT_CPUID_SUBFUNCTION;
			regs[3] = swapPageIdx;

			SetRegsThenCpuid(&regs[0], &regs[1], &regs[2], &regs[3]);

			regs[0] = NPT_HOOK_TOOL_CPUID_FUNCTION;
			regs[1] = NULL;
			regs[2] = GET_PHYSICAL_ADDRESS_SUBFUNCTION;
			regs[3] = (PTR_TYPE)swapPageRefCnt.pSwapVirtAddr;

			SetRegsThenCpuid(&regs[0], &regs[1], &regs[2], &regs[3]);

			swapPagePhyAddr = regs[1];

			//还原hook内存
			copyMemInfo.pSource = (UINT8*)swapPageRefCnt.pOriginVirtAddr + ((PTR_TYPE)record.pOriginVirtAddr & 0xfff);
			copyMemInfo.pDestination = (UINT8*)swapPageRefCnt.pSwapVirtAddr + ((PTR_TYPE)record.pOriginVirtAddr & 0xfff);
			copyMemInfo.Length = 1;

			regs[0] = NPT_HOOK_TOOL_CPUID_FUNCTION;
			regs[1] = NULL;
			regs[2] = COPY_MEMORY_CPUID_SUBFUNCTION;
			regs[3] = (PTR_TYPE)&copyMemInfo;

			SetRegsThenCpuid(&regs[0], &regs[1], &regs[2], &regs[3]);

			//递减交换页引用计数
			operateRefInfo.idx = swapPageIdx;
			operateRefInfo.objectType = RefCountOperationObjectType::SwapPageRefCntObject;
			operateRefInfo.operationType = RefCountOperationType::DecrementCount;

			regs[0] = NPT_HOOK_TOOL_CPUID_FUNCTION;
			regs[1] = NULL;
			regs[2] = OPERATE_REF_COUNT_CPUID_SUBFUNCTION;
			regs[3] = (PTR_TYPE)&operateRefInfo;

			SetRegsThenCpuid(&regs[0], &regs[1], &regs[2], &regs[3]);

			//尝试清理交换页引用并清理
			regs[0] = NPT_HOOK_TOOL_CPUID_FUNCTION;
			regs[1] = NULL;
			regs[2] = REMOVE_SWAPPAGE_REF_CNT_CPUID_SUBFUNCTION;
			regs[3] = (PTR_TYPE)swapPageIdx;

			SetRegsThenCpuid(&regs[0], &regs[1], &regs[2], &regs[3]);

			if (regs[1])
			{
				restoreHookSwap = true;

				regs[0] = NPT_HOOK_TOOL_CPUID_FUNCTION;
				regs[1] = NULL;
				regs[2] = FREE_NONPAGED_EXECUTEABLE_MEMORY_CPUID_SUBFUNCTION;
				regs[3] = (PTR_TYPE)swapPageRefCnt.pSwapVirtAddr;

				SetRegsThenCpuid(&regs[0], &regs[1], &regs[2], &regs[3]);
			}

			level3RefIdx = sharedData.FindSmallPageLevel3RefCntByPhyAddr(swapPagePhyAddr & 0xFFFFFFFFFFE00000);

			//递减小页引用计数
			operateRefInfo.idx = level3RefIdx;
			operateRefInfo.objectType = RefCountOperationObjectType::Level3RefObject;
			operateRefInfo.operationType = RefCountOperationType::DecrementCount;

			regs[0] = NPT_HOOK_TOOL_CPUID_FUNCTION;
			regs[1] = NULL;
			regs[2] = OPERATE_REF_COUNT_CPUID_SUBFUNCTION;
			regs[3] = (PTR_TYPE)&operateRefInfo;

			SetRegsThenCpuid(&regs[0], &regs[1], &regs[2], &regs[3]);

			//尝试删除小页和清理
			regs[0] = NPT_HOOK_TOOL_CPUID_FUNCTION;
			regs[1] = NULL;
			regs[2] = REMOVE_LEVEL3_REF_ITEM_CPUID_SUBFUNCTION;
			regs[3] = level3RefIdx;

			SetRegsThenCpuid(&regs[0], &regs[1], &regs[2], &regs[3]);

			if (regs[1])
				swapPageToLargePage = true;
		}

		//删除hook记录
		regs[0] = NPT_HOOK_TOOL_CPUID_FUNCTION;
		regs[1] = NULL;
		regs[2] = REMOVE_HOOK_ITEM_CPUID_SUBFUNCTION;
		regs[3] = (PTR_TYPE)hookIdx;

		SetRegsThenCpuid(&regs[0], &regs[1], &regs[2], &regs[3]);

		if (restoreHookSwap)
			CancelHookOperation(swapPageRefCnt);

		SyncSharedData();

		if (originPageToLargePage)
		{
			ChangeSmallPageToLargePage(pOriginPhyAddr & 0xFFFFFFFFFFE00000, PageTableType::ExternalPageTable);
			ChangeSmallPageToLargePage(pOriginPhyAddr & 0xFFFFFFFFFFE00000, PageTableType::InternalPageTable);

			permission.fields.writeable = true;
			permission.fields.userAccess = true;
			permission.fields.executionDisabled = true;

			ChangePageTablePermission(pOriginPhyAddr & 0xFFFFFFFFFFE00000, permission, PageTableType::InternalPageTable, 2);
		}

		if (swapPageToLargePage)
		{
			ChangeSmallPageToLargePage(swapPagePhyAddr & 0xFFFFFFFFFFE00000, PageTableType::ExternalPageTable);
			ChangeSmallPageToLargePage(swapPagePhyAddr & 0xFFFFFFFFFFE00000, PageTableType::InternalPageTable);

			permission.fields.writeable = true;
			permission.fields.userAccess = true;
			permission.fields.executionDisabled = true;

			ChangePageTablePermission(swapPagePhyAddr & 0xFFFFFFFFFFE00000, permission, PageTableType::InternalPageTable, 2);
		}
	} while (false);

	return status;
}

#pragma code_seg("PAGE")
NTSTATUS NptHookManager::Init()
{
	UINT32 cpuCnt = KeQueryActiveProcessorCountEx(ALL_PROCESSOR_GROUPS);
	pCoreNptHookStatus = (CoreNptHookStatus*)AllocNonPagedMem(sizeof(CoreNptHookStatus) * cpuCnt, PT_TAG);

	if (pCoreNptHookStatus == NULL)
		return STATUS_MEMORY_NOT_ALLOCATED;

	for (SIZE_TYPE idx = 0; idx < cpuCnt; ++idx)
		CallConstructor(pCoreNptHookStatus + idx);

	//构建内置页表
	NTSTATUS status = internalPageTableManager.Init();

	if (!NT_SUCCESS(status))
		return status;

	//设置内置页表默认权限为禁止执行
	PageTableLevel123Entry permission = {};
	permission.fields.userAccess = true;
	permission.fields.writeable = true;
	permission.fields.executionDisabled = true;

	for (SIZE_TYPE idx = 0; idx < internalPageTableManager.GetCoreNptPageTablesCnt(); ++idx)
	{
		CoreNptPageTableManager& pCoreNptPageTableManager = internalPageTableManager.GetCoreNptPageTables()[idx];

		pCoreNptPageTableManager.ChangeAllEndLevelPageTablePermession(permission);;
	}

	internalPageTableManager.SetDefaultPermission(permission);

	return STATUS_SUCCESS;
}

#pragma code_seg("PAGE")
void NptHookManager::Deinit()
{
	SIZE_TYPE cpuCnt = KeQueryActiveProcessorCountEx(ALL_PROCESSOR_GROUPS);

	PROCESSOR_NUMBER processorNum = {};
	GROUP_AFFINITY affinity = {}, oldAffinity = {};

	PTR_TYPE regs[4] = {};

	//释放NPT HOOK 状态内存
	for (SIZE_TYPE idx = 0; idx < cpuCnt; ++idx)
		CallDestroyer(pCoreNptHookStatus + idx);

	regs[0] = NPT_HOOK_TOOL_CPUID_FUNCTION;
	regs[1] = NULL;
	regs[2] = FREE_NONPAGED_MEMORY_CPUID_SUBFUNCTION;
	regs[3] = (PTR_TYPE)pCoreNptHookStatus;

	SetRegsThenCpuid(&regs[0], &regs[1], &regs[2], &regs[3]);

	//还原hook
	for (SIZE_TYPE idx = 0; idx < sharedData.hookRecords.Length(); ++idx)
		RemoveHook(sharedData.hookRecords[0].pOriginVirtAddr);

	//还原CR3
	for (ULONG idx = 0; idx < cpuCnt; ++idx)
	{
		KeGetProcessorNumberFromIndex(idx, &processorNum);
		affinity = {};
		affinity.Group = processorNum.Group;
		affinity.Mask = 1ULL << processorNum.Number;
		KeSetSystemGroupAffinityThread(&affinity, &oldAffinity);

		regs[0] = NPT_HOOK_TOOL_CPUID_FUNCTION;
		regs[1] = NULL;
		regs[2] = RESTORE_CR3_CPUID_SUBFUNCTION;
		regs[3] = idx;

		SetRegsThenCpuid(&regs[0], &regs[1], &regs[2], &regs[3]);

		KeRevertToUserGroupAffinityThread(&oldAffinity);
	}

	//析构内置NPT页表
	internalPageTableManager.Deinit();	
}

#pragma code_seg)
bool SimulateSceHookManager::HandleInvalidOpcode(VirtCpuInfo* pVirtCpuInfo, GenericRegisters* pGuestRegisters, PVOID pGuestVmcbPhyAddr, PVOID pHostVmcbPhyAddr)
{
	//syscall
	//0x0f 0x05
	//sysret
	//0x0f 0x07

	if (pCallback == NULL)
		KeBugCheck(MANUALLY_INITIATED_CRASH);

	bool result = false;

	UINT8* pByte = (UINT8*)pVirtCpuInfo->guestVmcb.statusFields.rip;

	if (pByte[0] == 0x0f)
	{
		switch (pByte[1])
		{
		case 0x05:
		{
			//调用回调通知
			GenericRegisters guestRegistersCopy = *pGuestRegisters;

			guestRegistersCopy.rip = pVirtCpuInfo->guestVmcb.statusFields.rip;
			guestRegistersCopy.rsp = pVirtCpuInfo->guestVmcb.statusFields.rsp;
			guestRegistersCopy.rax = pVirtCpuInfo->guestVmcb.statusFields.rax;
			guestRegistersCopy.rflags = pVirtCpuInfo->guestVmcb.statusFields.rflags;

			pCallback(&guestRegistersCopy, InstructionType::Syscall);

			//模拟syscall

			PTR_TYPE tempRip = NULL;

			PTR_TYPE starMsrValue = pVirtCpuInfo->guestVmcb.statusFields.star;
			pGuestRegisters->rcx = pVirtCpuInfo->guestVmcb.controlFields.nRip;									//RCX.q = next_RIP
			pGuestRegisters->r11 = pVirtCpuInfo->guestVmcb.statusFields.rflags;									// R11.q = RFLAGS

			UINT16 syscallCs = ((starMsrValue >> 32) & 0xffff);

			SegmentAttribute csAttribute = GetSegmentAttribute(pVirtCpuInfo->guestVmcb.statusFields.cs.selector, pVirtCpuInfo->guestVmcb.statusFields.gdtr.base);
			SegmentAttribute ssAttribute = GetSegmentAttribute(pVirtCpuInfo->guestVmcb.statusFields.ss.selector, pVirtCpuInfo->guestVmcb.statusFields.gdtr.base);

			//判断是32位用户程序进入还是64位用户程序进入，选择不同的位置执行
			if (csAttribute.Fields.LongMode)
				tempRip = pVirtCpuInfo->guestVmcb.statusFields.lstar;
			else
				tempRip = pVirtCpuInfo->guestVmcb.statusFields.cstar;

			csAttribute.Fields.LongMode = 1;
			csAttribute.Fields.Dpl = 0;

			ssAttribute.Fields.LongMode = 1;
			ssAttribute.Fields.Dpl = 0;

			pVirtCpuInfo->guestVmcb.statusFields.cs.selector = syscallCs & 0xfffc;
			pVirtCpuInfo->guestVmcb.statusFields.cs.base = 0;
			pVirtCpuInfo->guestVmcb.statusFields.cs.limit = 0xFFFFFFFF;
			pVirtCpuInfo->guestVmcb.statusFields.cs.attrib = csAttribute.AsUInt16;

			pVirtCpuInfo->guestVmcb.statusFields.ss.selector = syscallCs + 8;
			pVirtCpuInfo->guestVmcb.statusFields.ss.base = 0;
			pVirtCpuInfo->guestVmcb.statusFields.ss.limit = 0xFFFFFFFF;
			pVirtCpuInfo->guestVmcb.statusFields.ss.attrib = ssAttribute.AsUInt16;

			PTR_TYPE sfmaskMsrValue = pVirtCpuInfo->guestVmcb.statusFields.sfmask;
			pVirtCpuInfo->guestVmcb.statusFields.rflags &= ~sfmaskMsrValue;																		//RFLAGS AND ~MSR_SFMASK 
			pVirtCpuInfo->guestVmcb.statusFields.rflags &= ~(1 << EFLAGS_RF_OFFSET);															//RFLAGS.RF = 0

			//CPL = 0
			pVirtCpuInfo->guestVmcb.statusFields.cs.selector &= ~0x3;

			//设置RIP
			pVirtCpuInfo->guestVmcb.statusFields.rip = tempRip;

			result = true;
			break;
		}
		case 0x07:
		{
			//调用回调通知
			GenericRegisters guestRegistersCopy = *pGuestRegisters;

			guestRegistersCopy.rip = pVirtCpuInfo->guestVmcb.statusFields.rip;
			guestRegistersCopy.rsp = pVirtCpuInfo->guestVmcb.statusFields.rsp;
			guestRegistersCopy.rax = pVirtCpuInfo->guestVmcb.statusFields.rax;
			guestRegistersCopy.rflags = pVirtCpuInfo->guestVmcb.statusFields.rflags;

			pCallback(&guestRegistersCopy, InstructionType::Sysret);

			//模拟sysret

			PTR_TYPE tempRip = NULL;

			PTR_TYPE starMsrValue = pVirtCpuInfo->guestVmcb.statusFields.star;

			pVirtCpuInfo->guestVmcb.statusFields.cs.base = 0;
			pVirtCpuInfo->guestVmcb.statusFields.cs.limit = 0xFFFFFFFF;

			UINT16 sysretCs = (starMsrValue >> 48) & 0xffff;

			if (IoIs32bitProcess(NULL))
			{
				tempRip = (UINT32)pGuestRegisters->rcx;
			}
			else
			{
				//cs.selector += 16
				sysretCs += 0x10;
				tempRip = pGuestRegisters->rcx;
			}

			SegmentAttribute csAttribute = GetSegmentAttribute(sysretCs, pVirtCpuInfo->guestVmcb.statusFields.gdtr.base);

			pVirtCpuInfo->guestVmcb.statusFields.cs.selector = sysretCs | 0x3;
			pVirtCpuInfo->guestVmcb.statusFields.cs.attrib = csAttribute.AsUInt16;

			//CPL = 3
			pVirtCpuInfo->guestVmcb.statusFields.cs.selector &= 0x3;

			//RFLAGS.q = r11
			pVirtCpuInfo->guestVmcb.statusFields.rflags = pGuestRegisters->r11;

			result = true;
			break;
		}
		default:
			break;
		}
	}

	return result;
}
