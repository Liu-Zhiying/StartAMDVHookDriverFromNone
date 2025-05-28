#include "Hook.h"
#include <intrin.h>

extern "C" PTR_TYPE LStarHookCallback;
extern "C" PTR_TYPE OldLStarEntry;
extern "C" PTR_TYPE LStarHookCallbackParam1;
extern "C" PTR_TYPE LStarHookCallbackParam2;
extern "C" PTR_TYPE LStarHookCallbackParam3;
extern "C" void LStarHookEntry();
extern "C" void _mystac();
extern "C" void _myclac();

#pragma code_seg("PAGE")
void SetLStrHookEntryParameters(PTR_TYPE oldEntry, PTR_TYPE pCallback, PTR_TYPE param1, PTR_TYPE param2, PTR_TYPE param3)
{
	PAGED_CODE();
	//���ò���
	LStarHookCallback = pCallback;
	OldLStarEntry = oldEntry;
	LStarHookCallbackParam1 = param1;
	LStarHookCallbackParam2 = param2;
	LStarHookCallbackParam3 = param3;
}

//��ȡLStarHookEntry����������ĵ�ַ��hookʱ��MSR_LSTAR��ʵ�ʵ�ַ
#pragma code_seg("PAGE")
PTR_TYPE GetLStarHookEntry()
{
	PAGED_CODE();
	return (PTR_TYPE)LStarHookEntry;
}

#pragma code_seg()
SIZE_TYPE NptHookData::FindHookRecordByOriginVirtAddr(PTR_TYPE pOriginAddr) const
{
	SIZE_TYPE result = INVALID_INDEX;

	for (SIZE_TYPE idx = 0; idx < hookRecords.Length(); ++idx)
	{
		if (hookRecords[idx].pOriginVirtAddr == (PVOID)pOriginAddr)
		{
			result = idx;
			break;
		}
	}

	return result;
}

#pragma code_seg()
SIZE_TYPE NptHookData::FindSmallPageLevel2RefCntByPhyAddr(PTR_TYPE phyAddr) const
{
	SIZE_TYPE result = INVALID_INDEX;

	for (SIZE_TYPE idx = 0; idx < smallPageRecord.Length(); ++idx)
	{
		if (smallPageRecord[idx].level3PhyAddr == phyAddr)
		{
			result = idx;
			break;
		}
	}

	return result;
}

#pragma code_seg()
SIZE_TYPE NptHookData::FindSwapPageRefCntByOriginPhyAddr(PTR_TYPE phyAddr) const
{
	SIZE_TYPE result = INVALID_INDEX;

	for (SIZE_TYPE idx = 0; idx < swapPageRecord.Length(); ++idx)
	{
		if (swapPageRecord[idx].pOriginPhyAddr == phyAddr)
		{
			result = idx;
			break;
		}
	}

	return result;
}

#pragma code_seg()
SIZE_TYPE NptHookData::FindSwapPageRefCntByOriginVirtAddr(PTR_TYPE pOriginAddr) const
{
	SIZE_TYPE result = INVALID_INDEX;

	for (SIZE_TYPE idx = 0; idx < swapPageRecord.Length(); ++idx)
	{
		if (swapPageRecord[idx].pOriginVirtAddr == (PVOID)pOriginAddr)
		{
			result = idx;
			break;
		}
	}

	return result;
}

SIZE_TYPE NptHookData::FindSwapPageRefCntBySwapVirtAddr(PTR_TYPE pSwapAddr) const
{
	SIZE_TYPE result = INVALID_INDEX;

	for (SIZE_TYPE idx = 0; idx < swapPageRecord.Length(); ++idx)
	{
		if (swapPageRecord[idx].pSwapVirtAddr == (PVOID)pSwapAddr)
		{
			result = idx;
			break;
		}
	}

	return result;
}

#pragma code_seg("PAGE")
void NptHookManager::SetupSVMManager(SVMManager& svmManager)
{
	PAGED_CODE();

	//���ó�ʼNPTҳ��
	svmManager.SetNCr3Provider(&pageTableManager1);
	//����NFP
	svmManager.SetNpfInterceptPlugin(this);
	//����BP
	svmManager.SetBreakpointPlugin(this);
}

#pragma code_seg()
bool NptHookManager::HandleBreakpoint(VirtCpuInfo* pVirtCpuInfo, GenericRegisters* pGuestRegisters, PVOID pGuestVmcbPhyAddr, PVOID pHostVmcbPhyAddr)
{
	UNREFERENCED_PARAMETER(pGuestRegisters);
	UNREFERENCED_PARAMETER(pGuestVmcbPhyAddr);
	UNREFERENCED_PARAMETER(pHostVmcbPhyAddr);

	bool result = false;

	const NptHookData& data = hookData[pVirtCpuInfo->otherInfo.cpuIdx];

	//���ƥ�䵽hook��ֱ����ת
	SIZE_TYPE hookIdx = data.FindHookRecordByOriginVirtAddr(pGuestRegisters->rip);

	if (hookIdx != INVALID_INDEX)
	{
		pGuestRegisters->rip = (UINT64)data.hookRecords[hookIdx].pGotoVirtAddr;
		result = true;
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

	//�����ϲ�����ȱҳ
	if (!exitInfo.fields.present)
	{
		result = pageTableManager1.HandleNpf(pVirtCpuInfo, pGuestRegisters, pGuestVmcbPhyAddr, pHostVmcbPhyAddr) &&
			pageTableManager2.HandleNpf(pVirtCpuInfo, pGuestRegisters, pGuestVmcbPhyAddr, pHostVmcbPhyAddr);
	}
	else
	{
		if (exitInfo.fields.execute)
		{
			//ͨ���޸�ִ��Ȩ��ʵ��hook��Ĭ��hookҳ���ִֹ�У����ִ����hookҳ����Ϊִ�е�hookҳ������ִ�У�����ҳ������ִ�У�ִ�г�hookҳ��֮���ٻָ�Ĭ��

			//Ĭ��״̬ʹ���ⲿҳ����Ȩ�������hookʱ�Ѿ��������
			//hookҳ��ִ��ʱʹ���ڲ�ҳ���ڲ�ҳ��Ĭ�Ͻ�ִֹ�У������޸�ִ�е�hook����ִ��
			//����ϴ�ִ�е���hookҳ�棬�ָ��ڲ�ҳ���ӦҳΪ��ִֹ��

			//��ȡCPU IDX
			UINT32 cpuIdx = pVirtCpuInfo->otherInfo.cpuIdx;

			//��ȡ����NPT HOOK״̬
			NptHookStatus& hookStatus = hookData[cpuIdx].hookStatus;

			//��ȡ��Ӧ�ĺ���ҳ�������
			CoreNptPageTableManager& externalCorePageTableManager = pageTableManager1.GetCoreNptPageTables()[cpuIdx];
			CoreNptPageTableManager& internalCorePageTableManager = pageTableManager2.GetCoreNptPageTables()[cpuIdx];

			SIZE_TYPE swapPageIdx = INVALID_INDEX;
			PageTableLevel123Entry entry = {};

			PTR_TYPE tempPhyAddr = INVALID_ADDR;

			NptHookData& data = hookData[cpuIdx];

			if (hookStatus.pLastActiveHookPageVirtAddr != NULL)
			{
				//���������ַ��ѯ����ҳ��Ŀ
				swapPageIdx = data.FindSwapPageRefCntByOriginVirtAddr(hookStatus.pLastActiveHookPageVirtAddr);

				if (swapPageIdx != INVALID_INDEX)
				{
					//�ָ��ϴ�hookҳ��Ϊ��ִֹ��
					entry.fields.writeable = true;
					entry.fields.userAccess = true;
					entry.fields.executionDisabled = true;

					tempPhyAddr = data.swapPageRecord[swapPageIdx].pOriginPhyAddr;

					internalCorePageTableManager.ChangePageTableEntryPermession(tempPhyAddr, entry, 1);
				}
			}

			//��ѯ���������ҳ���Ƿ�ΪHOOKҳ��
			swapPageIdx = data.FindSwapPageRefCntByOriginPhyAddr(pa & 0xFFFFFFFFFF000);

			if (swapPageIdx != INVALID_INDEX)
			{
				//����hookҳ���ִ��
				entry.fields.writeable = true;
				entry.fields.userAccess = true;
				entry.fields.executionDisabled = false;

				internalCorePageTableManager.ChangePageTableEntryPermession(pa, entry, 1);

				//�л����ڲ�ҳ��
				tempPhyAddr = internalCorePageTableManager.GetNptPageTablePa();

				pVirtCpuInfo->guestVmcb.controlFields.nCr3 = tempPhyAddr;

				//����״̬
				hookStatus.pLastActiveHookPageVirtAddr = (PTR_TYPE)data.swapPageRecord[swapPageIdx].pOriginVirtAddr;
				hookStatus.premissionStatus = NptHookStatus::PremissionStatus::HookPageExecuted;
			}
			else
			{
				//�л����ⲿҳ��
				tempPhyAddr = externalCorePageTableManager.GetNptPageTablePa();

				pVirtCpuInfo->guestVmcb.controlFields.nCr3 = tempPhyAddr;

				//����״̬
				hookStatus.pLastActiveHookPageVirtAddr = NULL;
				hookStatus.premissionStatus = NptHookStatus::PremissionStatus::HookPageNotExecuted;
			}

			result = true;
		}
	}

	return result;
}

#pragma code_seg()
NTSTATUS NptHookManager::AddHookInSignleCore(const NptHookRecord& record, UINT32 idx)
{
	NTSTATUS status = STATUS_SUCCESS;
	PTR_TYPE pOriginPhyAddr = MmGetPhysicalAddress(record.pOriginVirtAddr).QuadPart;
	PTR_TYPE pOriginPageVirtAddr = (PTR_TYPE)record.pOriginVirtAddr & 0xfffffffffffff000;
	SIZE_TYPE smallPagIdx = INVALID_INDEX;
	SIZE_TYPE swapPageIdx = INVALID_INDEX;
	SIZE_TYPE hookIdx = INVALID_INDEX;
	UINT8* swapPageVirtAddr = NULL;
	PTR_TYPE swapPagePhyAddr = INVALID_ADDR;
	bool needChangePagePermission = false;

	CoreNptPageTableManager& corePageTableManager1 = pageTableManager1.GetCoreNptPageTables()[idx];
	CoreNptPageTableManager& corePageTableManager2 = pageTableManager2.GetCoreNptPageTables()[idx];

	auto changeToSmallPage = [](CoreNptPageTableManager& pageTableManager, PTR_TYPE pa) -> NTSTATUS
		{
			NTSTATUS status = STATUS_SUCCESS;

			do
			{
				status = pageTableManager.UsingSmallPage(pa, true);

				if (!NT_SUCCESS(status)) break;

				status = pageTableManager.MapSmallPageByPhyAddr(pa, pa + 0x200000);

				if (!NT_SUCCESS(status))
				{
					pageTableManager.UsingSmallPage(pa, false);
					break;
				}
			} while (false);

			return status;
		};

	do
	{
		//���hook��Ŀ�Ƿ����
		hookIdx = hookData[idx].FindHookRecordByOriginVirtAddr((PTR_TYPE)record.pOriginVirtAddr);

		if (hookIdx != INVALID_INDEX)
		{
			status = STATUS_INSUFFICIENT_RESOURCES;
			break;
		}

		hookData[idx].hookRecords.PushBack(record);

		swapPageIdx = hookData[idx].FindSwapPageRefCntByOriginVirtAddr(pOriginPageVirtAddr);

		if (swapPageIdx == INVALID_INDEX)
		{
			swapPageVirtAddr = (UINT8*)AllocExecutableNonPagedMem(PAGE_SIZE, HOOK_TAG);

			if (swapPageVirtAddr == NULL)
			{
				status = STATUS_UNSUCCESSFUL;
				break;
			}

			//��������
			RtlCopyMemory(swapPageVirtAddr, (PVOID)pOriginPageVirtAddr, PAGE_SIZE);
			//д��ϵ�
			swapPageVirtAddr[(PTR_TYPE)record.pOriginVirtAddr & 0xfff] = NptHookCode;

			//���뽻��ҳ����Ŀ
			SwapPageRecord newItem = {};

			newItem.pOriginVirtAddr = (PVOID)pOriginPageVirtAddr;
			newItem.pOriginPhyAddr = MmGetPhysicalAddress(newItem.pOriginVirtAddr).QuadPart;
			newItem.pSwapVirtAddr = swapPageVirtAddr;
			newItem.pSwapPhyAddr = MmGetPhysicalAddress(newItem.pSwapVirtAddr).QuadPart;
			newItem.refCnt = 1;

			swapPagePhyAddr = newItem.pSwapPhyAddr;

			hookData[idx].swapPageRecord.PushBack(newItem);
		}
		else
		{
			SwapPageRecord swapPageRefCnt = {};

			//��ȡ����ҳ����Ŀ
			swapPageRefCnt = hookData[idx].swapPageRecord[swapPageIdx];

			//д��ϵ�
			swapPageVirtAddr = (UINT8*)swapPageRefCnt.pSwapVirtAddr;
			swapPageVirtAddr[(PTR_TYPE)record.pOriginVirtAddr & 0xfff] = NptHookCode;

			//��������
			++hookData[idx].swapPageRecord[swapPageIdx].refCnt;
		}

		//��ȡ����ҳ�������ַ
		swapPagePhyAddr = MmGetPhysicalAddress((PVOID)swapPageVirtAddr).QuadPart;

		//���ý���ҳ��Ӧ��ҳ��ΪСҳ
		//�Ȳ�ѯ�Ƿ�������ΪСҳ�ļ�¼
		smallPagIdx = hookData[idx].FindSmallPageLevel2RefCntByPhyAddr(swapPagePhyAddr & 0xFFFFFFFFFFE00000);

		if (smallPagIdx == INVALID_INDEX)
		{
			//���û�в�ѯ��ΪСҳ�ļ�¼��������ΪСҳ����������¼
			status = changeToSmallPage(corePageTableManager1, swapPagePhyAddr & 0xFFFFFFFFFFE00000);

			if (!NT_SUCCESS(status))
				break;

			status = changeToSmallPage(corePageTableManager2, swapPagePhyAddr & 0xFFFFFFFFFFE00000);

			if (!NT_SUCCESS(status))
				break;

			SmallPageRecord newItem = {};

			newItem.level3PhyAddr = swapPagePhyAddr & 0xFFFFFFFFFFE00000;
			newItem.refCnt = 1;

			hookData[idx].smallPageRecord.PushBack(newItem);
		}
		else
		{
			++hookData[idx].smallPageRecord[smallPagIdx].refCnt;
		}

		//����ԭʼҳ��Ӧ��ҳ��ΪСҳ
		//�Ȳ�ѯ�Ƿ�������ΪСҳ�ļ�¼

		smallPagIdx = hookData[idx].FindSmallPageLevel2RefCntByPhyAddr(pOriginPhyAddr & 0xFFFFFFFFFFE00000);

		if (smallPagIdx == INVALID_INDEX)
		{
			//���û�в�ѯ��ΪСҳ�ļ�¼��������ΪСҳ����������¼
			status = changeToSmallPage(corePageTableManager1, pOriginPhyAddr & 0xFFFFFFFFFFE00000);

			if (!NT_SUCCESS(status))
				break;

			status = changeToSmallPage(corePageTableManager2, pOriginPhyAddr & 0xFFFFFFFFFFE00000);

			if (!NT_SUCCESS(status))
				break;

			needChangePagePermission = true;

			SmallPageRecord newItem = {};

			newItem.level3PhyAddr = pOriginPhyAddr & 0xFFFFFFFFFFE00000;

			hookData[idx].smallPageRecord.PushBack(newItem);
		}
		else
		{
			++hookData[idx].smallPageRecord[smallPagIdx].refCnt;
		}

	} while (false);

	if (NT_SUCCESS(status) && needChangePagePermission)
	{
		PageTableLevel123Entry permission = {};

		//����ҳ����
		corePageTableManager2.SwapSmallPagePpn(pOriginPhyAddr, swapPagePhyAddr, 1);

		permission.fields.writeable = true;
		permission.fields.userAccess = true;
		permission.fields.executionDisabled = true;

		corePageTableManager1.ChangePageTableEntryPermession(pOriginPhyAddr, permission, 1);
	}

	return status;
}

#pragma code_seg()
NTSTATUS NptHookManager::RemoveHookInSignleCore(PVOID pHookOriginVirtAddr, UINT32 idx)
{
	NTSTATUS status = STATUS_SUCCESS;
	PTR_TYPE pOriginPhyAddr = MmGetPhysicalAddress(pHookOriginVirtAddr).QuadPart;
	PTR_TYPE pOriginPageVirtAddr = (PTR_TYPE)pHookOriginVirtAddr & 0xfffffffffffff000;
	SIZE_TYPE smallPagIdx = INVALID_INDEX;
	SIZE_TYPE swapPageIdx = INVALID_INDEX;
	SIZE_TYPE hookIdx = INVALID_INDEX;
	UINT8* swapPageVirtAddr = NULL;
	PTR_TYPE swapPagePhyAddr = INVALID_ADDR;
	PageTableLevel123Entry permission = {};

	CoreNptPageTableManager& corePageTableManager1 = pageTableManager1.GetCoreNptPageTables()[idx];
	CoreNptPageTableManager& corePageTableManager2 = pageTableManager2.GetCoreNptPageTables()[idx];

	do
	{
		//���hook��Ŀ�Ƿ����
		hookIdx = hookData[idx].FindHookRecordByOriginVirtAddr((PTR_TYPE)pHookOriginVirtAddr);

		if (hookIdx == INVALID_INDEX)
		{
			status = STATUS_INSUFFICIENT_RESOURCES;
			break;
		}

		swapPageIdx = hookData[idx].FindSwapPageRefCntByOriginVirtAddr(pOriginPageVirtAddr);

		if (swapPageIdx != INVALID_INDEX)
		{
			SwapPageRecord& record = hookData[idx].swapPageRecord[swapPageIdx];

			swapPageVirtAddr = (UINT8*)record.pSwapVirtAddr;

			//��ԭHOOK
			swapPageVirtAddr[(PTR_TYPE)record.pOriginVirtAddr & 0xfff] = *((UINT8*)record.pOriginVirtAddr);

			if (!(--record.refCnt))
			{
				corePageTableManager2.SwapSmallPagePpn(record.pOriginPhyAddr, record.pSwapPhyAddr, 1);

				//�ͷ��ڴ�
				FreeExecutableNonPagedMem(hookData[idx].swapPageRecord[swapPageIdx].pSwapVirtAddr, HOOK_TAG);

				//ɾ����¼��
				hookData[idx].swapPageRecord.Remove(swapPageIdx);
			}
		}

		//��ȡ����ҳ�������ַ
		swapPagePhyAddr = MmGetPhysicalAddress((PVOID)swapPageVirtAddr).QuadPart;

		//�ݼ��������������Ϊ0�ָ���ҳ�������¼
		smallPagIdx = hookData[idx].FindSmallPageLevel2RefCntByPhyAddr(swapPagePhyAddr & 0xFFFFFFFFFFE00000);

		if (smallPagIdx != INVALID_INDEX)
		{
			SmallPageRecord& record = hookData[idx].smallPageRecord[smallPagIdx];
			if (!(--record.refCnt))
			{
				corePageTableManager1.UsingSmallPage(swapPagePhyAddr & 0xFFFFFFFFFFE00000, false);

				PTR_TYPE entryPermission = pageTableManager2.GetDefaultPermission(2);

				((PageTableLevel123*)&entryPermission)->entries->fields.executionDisabled = true;

				pageTableManager2.SetDefaultPermission(entryPermission, 2);

				corePageTableManager2.UsingSmallPage(swapPagePhyAddr & 0xFFFFFFFFFFE00000, false);

				((PageTableLevel123*)&entryPermission)->entries->fields.executionDisabled = false;

				pageTableManager2.SetDefaultPermission(entryPermission, 2);

				hookData[idx].smallPageRecord.Remove(smallPagIdx);
			}
		}

		//�ݼ��������������Ϊ0�ָ���ҳ�������¼
		smallPagIdx = hookData[idx].FindSmallPageLevel2RefCntByPhyAddr(pOriginPhyAddr & 0xFFFFFFFFFFE00000);

		if (smallPagIdx != INVALID_INDEX)
		{
			SmallPageRecord& record = hookData[idx].smallPageRecord[smallPagIdx];
			if (!(--record.refCnt))
			{
				corePageTableManager1.UsingSmallPage(pOriginPhyAddr & 0xFFFFFFFFFFE00000, false);

				PTR_TYPE entryPermission = pageTableManager2.GetDefaultPermission(2);

				((PageTableLevel123*)&entryPermission)->entries->fields.executionDisabled = true;

				pageTableManager2.SetDefaultPermission(entryPermission, 2);

				corePageTableManager2.UsingSmallPage(pOriginPhyAddr & 0xFFFFFFFFFFE00000, false);

				((PageTableLevel123*)&entryPermission)->entries->fields.executionDisabled = false;

				pageTableManager2.SetDefaultPermission(entryPermission, 2);

				hookData[idx].smallPageRecord.Remove(smallPagIdx);
			}
		}

		hookData[idx].hookRecords.Remove(hookIdx);

	} while (false);

	return status;
}

#pragma code_seg("PAGE")
NTSTATUS NptHookManager::AddHook(const NptHookRecord& record)
{
	PAGED_CODE();

	auto processor = [&record, this](UINT32 cpuIdx) -> NTSTATUS {
		return AddHookInSignleCore(record, cpuIdx);
		};

	auto rollbacker = [&record, this](UINT32 cpuIdx) -> NTSTATUS {
		return RemoveHookInSignleCore(record.pOriginVirtAddr, cpuIdx);
		};

	NTSTATUS status = RunOnEachCore(0, KeQueryMaximumProcessorCountEx(ALL_PROCESSOR_GROUPS), processor);

	if (NT_SUCCESS(status)) return status;

	return RunOnEachCore(0, KeQueryMaximumProcessorCountEx(ALL_PROCESSOR_GROUPS), rollbacker);
}

#pragma code_seg("PAGE")
NTSTATUS NptHookManager::RemoveHook(PVOID pHookOriginVirtAddr)
{
	PAGED_CODE();

	auto processor = [pHookOriginVirtAddr, this](UINT32 cpuIdx) -> NTSTATUS {
		return RemoveHookInSignleCore(pHookOriginVirtAddr, cpuIdx);
		};

	return RunOnEachCore(0, KeQueryMaximumProcessorCountEx(ALL_PROCESSOR_GROUPS), processor);
}

#pragma code_seg("PAGE")
NTSTATUS NptHookManager::Init()
{
	PAGED_CODE();

	cpuCnt = KeQueryActiveProcessorCountEx(ALL_PROCESSOR_GROUPS);

	//hookData.SetCapacity(cpuCnt);
	for (SIZE_T cnt = 0; cnt < cpuCnt; ++cnt)
		hookData.EmplaceBack(static_cast<NptHookData&&>(NptHookData()));

	//��������ҳ��
	NTSTATUS status = pageTableManager1.Init();

	if (!NT_SUCCESS(status))
		return status;

	status = pageTableManager2.Init();

	if (!NT_SUCCESS(status))
		return status;

	//�ڲ�ҳ����ϲ�ҳ��������ִ�е�
	//��ײ�ҳ������ִ��
	//�������л�ĳҳ�浽��2ִ��ʱ������Ϊ�ϲ�ҳ������ִ�ж�����
	PageTableLevel123Entry permission = {};
	permission.fields.userAccess = true;
	permission.fields.writeable = true;
	permission.fields.executionDisabled = true;

	//��ײ�ҳ������ִ��
	for (SIZE_TYPE idx = 0; idx < pageTableManager2.GetCoreNptPageTablesCnt(); ++idx)
	{
		CoreNptPageTableManager& pCoreNptPageTableManager = pageTableManager2.GetCoreNptPageTables()[idx];

		pCoreNptPageTableManager.ChangeAllEndLevelPageTablePermession(permission);;
	}

	//�����µ�Ĭ��Ȩ��Ϊ����ִ�У���Ϊ���������޸Ļ���������ײ�ҳ����޸�
	pageTableManager2.SetDefaultPermission(permission.data, 1);

	return STATUS_SUCCESS;
}

#pragma code_seg("PAGE")
void NptHookManager::Deinit()
{
	PAGED_CODE();

	for (SIZE_T idx1 = 0; idx1 < hookData.Length(); ++idx1)
	{
		//�ͷ�NPT HOOK �ڴ�
		for (SIZE_TYPE idx2 = 0; idx2 < hookData[idx1].swapPageRecord.Length(); ++idx2)
			FreeExecutableNonPagedMem(hookData[idx1].swapPageRecord[idx2].pSwapVirtAddr, HOOK_TAG);
	}

	hookData.Clear();

	//��������NPTҳ��
	pageTableManager1.Deinit();

	pageTableManager2.Deinit();

	//��ճ�Ա
	cpuCnt = 0;
}

#pragma code_seg()
PVOID FunctionCallerManager::AllocFunctionCallerForHook(PVOID pFunction)
{
	constexpr unsigned char jmpOpCodeTemplate[] = { 0xff, 0x25, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff };
	constexpr SIZE_TYPE jmpAddressOffset = 6;

	static bool isXedInited = false;

	//���xedδ��ʼ������ʼ��xed
	if (!isXedInited) {
		xed_tables_init();
	}

	//����ɺ����ĵ�һ��ָ��ĳ���
	xed_decoded_inst_t xedd;
	xed_state_t dstate = {};

	dstate.mmode = XED_MACHINE_MODE_LONG_64;

	xed_decoded_inst_zero_set_mode(&xedd, &dstate);

	xed_error_enum_t result = xed_ild_decode(&xedd, (unsigned char*)pFunction, XED_MAX_INSTRUCTION_BYTES);

	if (result != XED_ERROR_NONE)
		return NULL;

	unsigned int length = xed_decoded_inst_get_length(&xedd);

	//��������hook�е��þɺ�����ָ���
	PVOID pFunctionCaller = AllocExecutableNonPagedMem(length + sizeof jmpOpCodeTemplate, HOOK_TAG);

	if (pFunctionCaller == NULL)
		return NULL;

	RtlCopyMemory(pFunctionCaller, pFunction, length);
	RtlCopyMemory((PCHAR)pFunctionCaller + length, jmpOpCodeTemplate, sizeof jmpOpCodeTemplate);

	PTR_TYPE* pJmpAddress = (PTR_TYPE*)((PCHAR)pFunctionCaller + length + jmpAddressOffset);

	*pJmpAddress = ((PTR_TYPE)pFunction + length);

	return pFunctionCaller;
}

#pragma code_seg()
void FunctionCallerManager::FreeFunctionCallerForHook(PVOID pFunctionCaller)
{
	FreeExecutableNonPagedMem(pFunctionCaller, HOOK_TAG);
}

#pragma code_seg()
SIZE_TYPE FunctionCallerManager::FindFunctionCallerItemBySourceFunction(PVOID pSourceFunction)
{
	SIZE_TYPE callerCnt = functionCallerItems.Length();

	for (SIZE_TYPE idx = 0; idx < callerCnt; ++idx)
	{
		if (pSourceFunction == functionCallerItems[idx].pSourceFunction)
			return idx;
	}

	return INVALID_INDEX;
}

#pragma code_seg()
void FunctionCallerManager::Deinit()
{
	SIZE_TYPE callerCnt = functionCallerItems.Length();

	for (SIZE_TYPE idx = 0; idx < callerCnt; ++idx)
		FreeFunctionCallerForHook(functionCallerItems[idx].pFunctionCaller);

	functionCallerItems.Clear();
}

#pragma code_seg()
PVOID FunctionCallerManager::GetFunctionCaller(PVOID pSourceFunction)
{
	PVOID result = NULL;

	//������û���Ѿ������Caller�ڴ��
	SIZE_TYPE idx = FindFunctionCallerItemBySourceFunction(pSourceFunction);

	//���򷵻أ����򴴽��ٷ���
	if (idx != INVALID_INDEX)
	{
		result = functionCallerItems[idx].pFunctionCaller;
	}
	else
	{
		PVOID pNewFunctionCaller = AllocFunctionCallerForHook(pSourceFunction);

		if (pNewFunctionCaller != NULL)
		{
			FunctionCallerItem newItem = {};
			newItem.pFunctionCaller = pNewFunctionCaller;
			newItem.pSourceFunction = pSourceFunction;

			functionCallerItems.PushBack(newItem);

			result = pNewFunctionCaller;
		}
	}

	return result;
}

#pragma code_seg()
void FunctionCallerManager::RemoveFunctionCaller(PVOID pSourceFunction)
{
	//������û���Ѿ������Caller�ڴ�飬����ɾ����¼���ͷ��ڴ��
	SIZE_TYPE idx = FindFunctionCallerItemBySourceFunction(pSourceFunction);

	if (idx != INVALID_INDEX)
	{
		FreeFunctionCallerForHook(functionCallerItems[idx].pFunctionCaller);
		functionCallerItems.Remove(idx);
	}
}
