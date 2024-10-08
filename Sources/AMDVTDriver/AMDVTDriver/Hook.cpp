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

	if (coreNptHookStatus.Length() <= pVirtCpuInfo->otherInfo.cpuIdx)
		return result;

	const NptHookSharedData*  pSharedData = coreNptHookStatus[pVirtCpuInfo->otherInfo.cpuIdx].pSharedData;

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
			CoreNptHookStatus& hookStatus = coreNptHookStatus[pVirtCpuInfo->otherInfo.cpuIdx];

			//获取对应的核心页表管理器
			CoreNptPageTableManager& corePageTableManager = pPageTableManager->GetCoreNptPageTables()[cpuIdx];

			SIZE_TYPE swapPageIdx = INVALID_INDEX;
			PageTableLevel123Entry entry = {};

			PTR_TYPE tempPhyAddr1 = {}, tempPhyAddr2 = {};

			SwapPageRefCnt tempSwapPageInfo = {};

			const NptHookSharedData* pSharedData = hookStatus.pSharedData;

			if (pSharedData != NULL)
			{
				if (hookStatus.pLastActiveHookPageVirtAddr != NULL)
				{
					//根据虚拟地址查询交换页项目
					swapPageIdx = pSharedData->FindSwapPageRefCntByOriginVirtAddr((PVOID)hookStatus.pLastActiveHookPageVirtAddr);

					if (swapPageIdx != INVALID_INDEX)
					{
						//如果交换页存在，还原当前hook页面的交换（就是再次交换）
						const SwapPageRefCnt& swapPageRef = pSharedData->swapPageRefs[swapPageIdx];
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
				swapPageIdx = pSharedData->FindSwapPageRefCntByPhyAddr(pa & 0xFFFFFFFFFF000);

				if (swapPageIdx != INVALID_INDEX)
				{
					const SwapPageRefCnt& swapPageRef = pSharedData->swapPageRefs[swapPageIdx];

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
					hookStatus.pLastActiveHookPageVirtAddr = (PTR_TYPE)pSharedData->swapPageRefs[swapPageIdx].pOriginVirtAddr;
					hookStatus.premissionStatus = CoreNptHookStatus::PremissionStatus::HookPageExecuted;
				}
				else
				{
					//设置HOOK页面可读可写不可执行，其他页面均可读可写可执行
					entry.fields.writeable = true;
					entry.fields.userAccess = true;

					corePageTableManager.ChangeAllPageTablePermession(entry);

					entry.fields.executionDisabled = true;
					for (SIZE_TYPE idx = 0; idx < pSharedData->swapPageRefs.Length(); ++idx)
						corePageTableManager.ChangePageTablePermession(MmGetPhysicalAddress(pSharedData->swapPageRefs[idx].pOriginVirtAddr).QuadPart, entry, 1);

					//更新状态
					hookStatus.pLastActiveHookPageVirtAddr = NULL;
					hookStatus.premissionStatus = CoreNptHookStatus::PremissionStatus::HookPageNotExecuted;
				}

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

bool NptHookManager::HandleCpuid(VirtCpuInfo* pVirtCpuInfo, GenericRegisters* pGuestRegisters, PVOID pGuestVmcbPhyAddr, PVOID pHostVmcbPhyAddr)
{
	UNREFERENCED_PARAMETER(pGuestVmcbPhyAddr);
	UNREFERENCED_PARAMETER(pHostVmcbPhyAddr);

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

			break;
		}
		case SWAP_SMALL_PAGE_PPN_CPUID_SUBFUNCTION:
		{
			const SwapSmallPagePpnInfo* pInfo = (SwapSmallPagePpnInfo*)pGuestRegisters->rdx;

			status = pPageTableManager->GetCoreNptPageTables()[pInfo->cpuIdx].SwapSmallPagePpn(pInfo->physicalAddress1, pInfo->physicalAddress2);

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
	SIZE_TYPE cpuCnt = KeQueryActiveProcessorCountEx(ALL_PROCESSOR_GROUPS);

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
	SIZE_TYPE cpuCnt = KeQueryActiveProcessorCountEx(ALL_PROCESSOR_GROUPS);

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
	SIZE_TYPE cpuCnt = KeQueryActiveProcessorCountEx(ALL_PROCESSOR_GROUPS);

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
	SIZE_TYPE cpuCnt = KeQueryActiveProcessorCountEx(ALL_PROCESSOR_GROUPS);

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

		coreNptHookStatus[idx].pSharedData = (NptHookSharedData*)regs[1];

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
			status = ChangeLargePageToSmallPage(swapPagePhyAddr & 0xFFFFFFFFFFE00000);
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
			status = ChangeLargePageToSmallPage(pOriginPhyAddr & 0xFFFFFFFFFFE00000);
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
		PageTableLevel123Entry permission = {};
		permission.fields.writeable = true;
		permission.fields.userAccess = true;
		permission.fields.executionDisabled = true;

		ChangePageTablePermission(pOriginPhyAddr & 0xFFFFFFFFFFFF000, permission);
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
				ChangeSmallPageToLargePage(pOriginPhyAddr & 0xFFFFFFFFFFE00000);

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
				ChangeSmallPageToLargePage(swapPagePhyAddr & 0xFFFFFFFFFFE00000);

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
			ChangeSmallPageToLargePage(pOriginPhyAddr & 0xFFFFFFFFFFE00000);

		if (swapPageToLargePage)
			ChangeSmallPageToLargePage(swapPagePhyAddr & 0xFFFFFFFFFFE00000);
	} while (false);

	return status;
}

#pragma code_seg("PAGE")
NTSTATUS NptHookManager::Init()
{
	UINT32 cpuCnt = KeQueryActiveProcessorCountEx(ALL_PROCESSOR_GROUPS);
	coreNptHookStatus.SetCapacity(cpuCnt);

	for (SIZE_TYPE idx = 0; idx < cpuCnt; ++idx)
		coreNptHookStatus.PushBack(CoreNptHookStatus());

	return STATUS_SUCCESS;
}

#pragma code_seg("PAGE")
void NptHookManager::Deinit()
{
	for (SIZE_TYPE idx = 0; idx < sharedData.hookRecords.Length(); ++idx)
		RemoveHook(sharedData.hookRecords[0].pOriginVirtAddr);
}
