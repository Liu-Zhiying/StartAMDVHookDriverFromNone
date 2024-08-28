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

	SIZE_TYPE hookIdx = FindHookRecordByOriginVirtAddr((PVOID)pVirtCpuInfo->guestVmcb.statusFields.rip);

	if (hookIdx != -1)
	{
		pVirtCpuInfo->guestVmcb.statusFields.rip = (UINT64)hookRecords[hookIdx].pGotoVirtAddr;
		return true;
	}

	return false;
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

	if (exitInfo.fields.present)
	{
		if (exitInfo.fields.execute)
		{
			KIRQL oldIrql = {};

			KeAcquireSpinLock(&operationLock, &oldIrql);

			//获取CPU IDX
			UINT32 cpuIdx = pVirtCpuInfo->otherInfo.cpuIdx;

			//获取核心NPT HOOK状态
			CoreNptHookStatus& hookStatus = coreNptHookStatus[pVirtCpuInfo->otherInfo.cpuIdx];

			//获取对应的核心页表管理器
			CoreNptPageTableManager& corePageTableManager = pPageTableManager->GetCoreNptPageTables()[cpuIdx];

			SIZE_TYPE swapPageIdx = (SIZE_TYPE)-1;
			PageTableLevel123Entry entry = {};

			if (hookStatus.pLastActiveHookPageVirtAddr != NULL)
			{
				//根据虚拟地址查询交换页项目
				swapPageIdx = FindSwapPageRefCntByOriginVirtAddr((PVOID)hookStatus.pLastActiveHookPageVirtAddr);

				if (swapPageIdx != -1)
				{
					//如果交换页存在，还原当前hook页面的交换（就是再次交换）
					const SwapPageRefCnt& swapPageRef = swapPageRefs[swapPageIdx];
					corePageTableManager.SwapSmallPageForPhyAddr(MmGetPhysicalAddress(swapPageRef.pOriginVirtAddr).QuadPart, MmGetPhysicalAddress(swapPageRef.pSwapVirtAddr).QuadPart);
				}
				else
				{
					//否则，上次活动hook页虚拟地址置空
					hookStatus.pLastActiveHookPageVirtAddr = NULL;
				}
			}

			//查询发生错误的页面是否为HOOK页面
			swapPageIdx = FindSwapPageRefCntByPhyAddr(pa & 0xFFFFFFFFF000);

			if (swapPageIdx != (SIZE_TYPE)-1)
			{
				const SwapPageRefCnt& swapPageRef = swapPageRefs[swapPageIdx];
				
				//交换新hook页面
				corePageTableManager.SwapSmallPageForPhyAddr(MmGetPhysicalAddress(swapPageRef.pOriginVirtAddr).QuadPart, MmGetPhysicalAddress(swapPageRef.pSwapVirtAddr).QuadPart);

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

			result = true;

			KeReleaseSpinLock(&operationLock, oldIrql);
		}
	}
	else
	{
		result = pPageTableManager->HandleNpf(pVirtCpuInfo, pGuestRegisters, pGuestVmcbPhyAddr, pHostVmcbPhyAddr);
	}

	return result;
}

#pragma code_seg()
NTSTATUS NptHookManager::AddHook(const HookRecord& record)
{
	NTSTATUS status = STATUS_SUCCESS;
	KIRQL oldIrql = {};

	KeAcquireSpinLock(&operationLock, &oldIrql);

	ULONG cpuIdx = KeGetCurrentProcessorIndex();
	SIZE_TYPE cpuCnt = pPageTableManager->GetCoreNptPageTablesCnt();
	CoreNptPageTableManager* pCpuPageTables = pPageTableManager->GetCoreNptPageTables();
	PTR_TYPE pOriginPhyAddr = MmGetPhysicalAddress(record.pOriginVirtAddr).QuadPart;
	PTR_TYPE pOriginAlignedPhyAddr = pOriginPhyAddr & 0xFFFFFFFFF000;
	PTR_TYPE pOriginLevel3PhyAddr = pOriginPhyAddr & 0xFFFFFFE00000;
	PVOID pOriginAlignedVirtAddr = (PVOID)(((PTR_TYPE)record.pOriginVirtAddr) & 0xFFFFFFFFF000);
	SIZE_TYPE level3RefIdx = (SIZE_TYPE)-1;
	UINT8* pSwapPage = NULL;
	SIZE_TYPE swapPageIdx = (SIZE_TYPE)-1;
	int stepCnt = 0;

	do
	{
		if (FindHookRecordByOriginVirtAddr(record.pOriginVirtAddr) != -1)
		{
			status = STATUS_UNSUCCESSFUL;
			break;
		}
		
		stepCnt = 1;

		level3RefIdx = FindSmallPageLevel3RefCntByPhyAddr(pOriginLevel3PhyAddr);
		if (level3RefIdx == -1)
		{
			for (SIZE_TYPE idx = 0; idx < cpuCnt; ++idx)
			{
				status = pCpuPageTables[idx].UsingSmallPageForPhyAddr(pOriginLevel3PhyAddr, true);
				if (!NT_SUCCESS(status))
					break;

				status = pCpuPageTables[idx].MapSmallPageForPhyAddr(pOriginLevel3PhyAddr, pOriginLevel3PhyAddr + 0x200000);
				if (!NT_SUCCESS(status))
					break;
			}

			if (!NT_SUCCESS(status))
				break;

			//插入level3引用条目
			level3Refs.PushBack(SmallPageLevel3RefCnt(pOriginLevel3PhyAddr, 1));
		}
		else
		{
			++level3Refs[level3RefIdx].refCnt;
		}
		
		stepCnt = 2;

		swapPageIdx = FindSwapPageRefCntByOriginVirtAddr(pOriginAlignedVirtAddr);
		if (swapPageIdx == -1)
		{
			PVOID newSwapPage = AllocNonPagedMem(PAGE_SIZE, HOOK_TAG);
			if (newSwapPage == NULL)
			{
				status = STATUS_INSUFFICIENT_RESOURCES;
				break;
			}

			RtlCopyMemory(newSwapPage, record.pOriginVirtAddr, PAGE_SIZE);

			pSwapPage = (UINT8*)newSwapPage;

			//插入交换页对条目
			swapPageRefs.PushBack(SwapPageRefCnt(pOriginAlignedVirtAddr, pSwapPage, 1));

			//页面属性修改
			for (SIZE_TYPE idx = 0; idx < cpuCnt; ++idx)
			{
				CoreNptHookStatus& hookStatus = coreNptHookStatus[idx];
				CoreNptPageTableManager& corePageTableManager = pCpuPageTables[idx];

				if (hookStatus.premissionStatus == CoreNptHookStatus::PremissionStatus::HookPageNotExecuted || hookStatus.pLastActiveHookPageVirtAddr != (PTR_TYPE)pOriginAlignedVirtAddr)
				{
					PageTableLevel123Entry entry = {};
					entry.fields.writeable = true;
					entry.fields.userAccess = true;
					entry.fields.executionDisabled = true;
					corePageTableManager.ChangePageTablePermession(MmGetPhysicalAddress(pOriginAlignedVirtAddr).QuadPart, entry, 1);
				}
			}
		}
		else
		{
			++swapPageRefs[swapPageIdx].refCnt;

			//获取NPT页面的最终地址用于判断页面是否交换
			PTR_TYPE tempAddr, tempLevel;
			pCpuPageTables[cpuIdx].GetNptFinalAddrForPhyAddr(pOriginAlignedPhyAddr, tempAddr, tempLevel);

			//根据交换情况设置交换页读写的虚拟地址
			if (tempAddr == pOriginAlignedPhyAddr)
				pSwapPage = (UINT8*)swapPageRefs[swapPageIdx].pSwapVirtAddr;
			else
				pSwapPage = (UINT8*)swapPageRefs[swapPageIdx].pOriginVirtAddr;
		}

		//写入int3断点
		PTR_TYPE modifyIdx = ((PTR_TYPE)record.pOriginVirtAddr) & 0xFFF;
		pSwapPage[modifyIdx] = 0xcc;

		//插入到hook条目
		hookRecords.PushBack(record);

	} while (false);

	if (!NT_SUCCESS(status))
	{
		switch (stepCnt)
		{
		case 2:
			if (swapPageIdx == -1)
			{
				//回滚level3引用更新
				if (level3RefIdx == -1)
				{
					SIZE_TYPE tempIdx = FindSmallPageLevel3RefCntByPhyAddr(pOriginLevel3PhyAddr);
					if (tempIdx != -1)
						level3Refs.Remove(tempIdx);
				}
				else
				{
					--level3Refs[level3RefIdx].refCnt;
				}
			}
		case 1:
			if (level3RefIdx == -1)
			{
				//回滚页表更新
				for (SIZE_TYPE idx = 0; idx < cpuCnt; ++idx)
					pCpuPageTables[idx].UsingSmallPageForPhyAddr(pOriginLevel3PhyAddr, false);
			}
		case 0:
		default:
			break;
		}
	}

	KeReleaseSpinLock(&operationLock, oldIrql);

	return status;
}

#pragma code_seg()
NTSTATUS NptHookManager::RemoveHook(PVOID pHookOriginVirtAddr)
{
	NTSTATUS status = STATUS_SUCCESS;
	KIRQL oldIrql = {};

	KeAcquireSpinLock(&operationLock, &oldIrql);

	do
	{
		//查询hook记录是否存在
		SIZE_TYPE hookIdx = FindHookRecordByOriginVirtAddr(pHookOriginVirtAddr);
		if (hookIdx == -1)
		{
			status = STATUS_NOT_FOUND;
			break;
		}

		//初始化数据
		HookRecord record = hookRecords[hookIdx];
		ULONG cpuIdx = KeGetCurrentProcessorIndex();
		SIZE_TYPE cpuCnt = pPageTableManager->GetCoreNptPageTablesCnt();
		CoreNptPageTableManager* pCpuPageTables = pPageTableManager->GetCoreNptPageTables();
		PTR_TYPE pOriginPhyAddr = MmGetPhysicalAddress(record.pOriginVirtAddr).QuadPart;
		PTR_TYPE pOriginAlignedPhyAddr = pOriginPhyAddr & 0xFFFFFFFFF000;
		PTR_TYPE pOriginLevel3PhyAddr = pOriginPhyAddr & 0xFFFFFFE00000;
		PVOID pOriginAlignedVirtAddr = (PVOID)(((PTR_TYPE)record.pOriginVirtAddr) & 0xFFFFFFFFF000);

		//查询交换页引用
		SIZE_TYPE swapPageIdx = FindSwapPageRefCntByOriginVirtAddr(pOriginAlignedVirtAddr);
		if (swapPageIdx != -1)
		{
			//应勇计数递减
			--swapPageRefs[swapPageIdx].refCnt;

			//如果引用技术为0，回收交换页
			//否则，还原修改的字节
			if (!swapPageRefs[swapPageIdx].refCnt)
			{
				//回收交换页
				FreeNonPagedMem(swapPageRefs[swapPageIdx].pSwapVirtAddr, HOOK_TAG);
				swapPageRefs.Remove(swapPageIdx);
			}
			else
			{
				//获取NPT页面的最终地址用于判断页面是否交换
				PTR_TYPE tempAddr, tempLevel;
				pCpuPageTables[cpuIdx].GetNptFinalAddrForPhyAddr(pOriginAlignedPhyAddr, tempAddr, tempLevel);

				PTR_TYPE modifyIdx = ((PTR_TYPE)record.pOriginVirtAddr) & 0xFFF;

				//还原字节修改
				if (tempAddr == pOriginAlignedPhyAddr)
					((UINT8*)swapPageRefs[swapPageIdx].pSwapVirtAddr)[modifyIdx] = ((UINT8*)swapPageRefs[swapPageIdx].pOriginVirtAddr)[modifyIdx];
				else
					((UINT8*)swapPageRefs[swapPageIdx].pOriginVirtAddr)[modifyIdx] = ((UINT8*)swapPageRefs[swapPageIdx].pSwapVirtAddr)[modifyIdx];
			}
		}

		//查询level3小页计数
		SIZE_TYPE level3RefIdx = FindSmallPageLevel3RefCntByPhyAddr(pOriginLevel3PhyAddr);
		if (level3RefIdx != -1)
		{
			//引用计数递减
			--level3Refs[level3RefIdx].refCnt;
			//如果小页引用计数为0，还原为大页
			if (!level3Refs[level3RefIdx].refCnt)
			{
				//修改Level3回大页
				for (SIZE_TYPE idx = 0; idx < cpuCnt; ++idx)
					pCpuPageTables[idx].UsingSmallPageForPhyAddr(pOriginLevel3PhyAddr, false);
				level3Refs.Remove(level3RefIdx);
			}
		}

		//页面属性修改
		for (SIZE_TYPE idx = 0; idx < cpuCnt; ++idx)
		{
			CoreNptHookStatus& hookStatus = coreNptHookStatus[idx];
			CoreNptPageTableManager& corePageTableManager = pCpuPageTables[idx];
			PageTableLevel123Entry entry = {};
			entry.fields.writeable = true;
			entry.fields.userAccess = true;

			if (hookStatus.premissionStatus == CoreNptHookStatus::PremissionStatus::HookPageExecuted)
				entry.fields.executionDisabled = true;
				
			corePageTableManager.ChangePageTablePermession(MmGetPhysicalAddress(pOriginAlignedVirtAddr).QuadPart, entry, 2);
		}

		//删除hook记录
		hookRecords.Remove(hookIdx);
	} while (false);

	KeReleaseSpinLock(&operationLock, oldIrql);

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
