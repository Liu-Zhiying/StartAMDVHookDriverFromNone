//�������ܵĲ���ʾ��
#include "main.h"

#pragma code_seg()
void TestLStarHookCallback()
{
	static bool showMessage = false;
	if (!showMessage)
	{
		showMessage = true;
		KdPrint(("Msr Hook OK!\n"));
	}
}

PVOID pHookMem = NULL;

#pragma code_seg()
PVOID NTAPI ExAllocatePool2Handler(POOL_FLAGS Flags, SIZE_T NumberOfBytes, ULONG Tag)
{
	static bool showMessage = false;
	if (!showMessage)
	{
		showMessage = true;
		KdPrint(("ExAllocatePool2 hook OK!\n"));
	}

	typedef PVOID(*P_ExAllocatePool2)(POOL_FLAGS Flags, SIZE_T NumberOfBytes, ULONG Tag);
	PVOID result = ((P_ExAllocatePool2)pHookMem)(Flags, NumberOfBytes, Tag);
	return result;
}

#pragma code_seg("PAGE")
void GlobalManager::SetMsrHookParameters()
{
	PAGED_CODE();

	//����Ҫhook��msr
	//Hook IA32_MSR_LSTAR
	UINT32 msrNums[1] = { IA32_MSR_LSTAR };
	msrHookManager.SetHookMsrs(msrNums);

	//��SVMManager��
	svmManager.SetCpuIdInterceptPlugin(&msrHookManager);
	svmManager.SetMsrInterceptPlugin(&msrHookManager);
}

#pragma code_seg("PAGE")
void GlobalManager::SetNptHook()
{
	PAGED_CODE();
	//����NPT HOOK�ⲿҳ��
	nptHookManager.SetPageTableManager(&ptManager);
	//����CPUID
	svmManager.SetCpuIdInterceptPlugin(&nptHookManager);
	//����NFP
	svmManager.SetNpfInterceptPlugin(&nptHookManager);
	//����BP
	svmManager.SetBreakpointPlugin(&nptHookManager);
}

#pragma code_seg("PAGE")
void GlobalManager::SetNpt()
{
	PAGED_CODE();
	//����NPTҳ��
	KdPrint(("GlobalManager::Init(): Enable NPT\n"));
	svmManager.SetNCr3Provider(&ptManager);
}

#pragma code_seg("PAGE")
void GlobalManager::HookApi()
{
	PAGED_CODE();

	//��ȡExAllocatePool2�������ַ
	UNICODE_STRING apiName = {};
	RtlInitUnicodeString(&apiName, L"ExAllocatePool2");
	PVOID apiVirtAddr = MmGetSystemRoutineAddress(&apiName);

	KdPrint(("GlobalManager::HookApi(): ExAllocatePool2 virtual address: %llx\n", apiVirtAddr));

	if (apiVirtAddr == NULL)
	{
		KdPrint(("GlobalManager::HookApi(): ExAllocatePool2 address not found!\n"));
		return;
	}

	//��ȡExAllocatePool2��������ַ
	PTR_TYPE apiPhyAddr = MmGetPhysicalAddress(apiVirtAddr).QuadPart;

	KdPrint(("GlobalManager::HookApi(): ExAllocatePool2 physical address: %llx\n", apiPhyAddr));

	//����hookʱ����ִ��ԭ�����Ĵ��룬ע�⣬�����hook����ֻ��Windows 11 24h2��Ч
	//0x48, 0x89, 0x5c, 0x24, 0x10 
	//mov qword ptr [rsp+10h], rbx ����ָ����ExAllocatePool2��Windows 11 24h2�ĵ�һ��ָ��
	//0xff, 0x25, 0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF
	//jmp 0xffffffffffffffff ����� 0xffffffffffffffff Ҫ�滻Ϊ ExAllocatePool2 �ĵڶ���ָ��������ַ

	//���ϵͳ�汾��ͬ�������ʵ������޸�

	UINT8 hookCode[] = { 0x48, 0x89, 0x5c, 0x24, 0x10, 0xff, 0x25, 0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF };

	*((PVOID*)(hookCode + 0xb)) = ((UINT8*)apiVirtAddr) + 0x5;

	pHookMem = ExAllocatePool2(POOL_FLAG_NON_PAGED_EXECUTE, sizeof(hookCode), 0x22);
	if (pHookMem == NULL)
	{
		KdPrint(("GlobalManager::HookApi(): Allocate hook memory failed!\n"));
		return;
	}
	//�ѻ�����д���ִ���ڴ�
	RtlCopyMemory(pHookMem, hookCode, sizeof(hookCode));

	//ִ��hook
	NptHookRecord record = {};
	record.pOriginVirtAddr = apiVirtAddr;
	record.pGotoVirtAddr = ExAllocatePool2Handler;

	nptHookManager.AddHook(record);
}

#pragma code_seg("PAGE")
void GlobalManager::EnableMsrHook()
{
	PAGED_CODE();

	//HOOK MSR_LSTAR
	EnableLStrHook<1>(&msrHookManager, TestLStarHookCallback);
}

#pragma code_seg("PAGE")
NTSTATUS GlobalManager::Init()
{
	PAGED_CODE();

	NTSTATUS status = STATUS_SUCCESS;
	do
	{
#if defined(TEST_NPT_HOOK)

		SetNptHook();

		status = nptHookManager.Init();
		if (!NT_SUCCESS(status))
			break;

		status = ptManager.Init();
		if (!NT_SUCCESS(status))
			break;

		SetNpt();

		status = svmManager.Init();
		if (!NT_SUCCESS(status))
			break;

		HookApi();

#elif defined(TEST_MSR_HOOK)

		SetMsrHookParameters();

		status = msrHookManager.Init();
		if (!NT_SUCCESS(status))
			break;

		status = svmManager.Init();
		if (!NT_SUCCESS(status))
			break;

		EnableMsrHook();
#else
#error "Please define TEST_NPT_HOOK or TEST_MSR_HOOK to test a driver function."
#endif

	} while (false);

	if (!NT_SUCCESS(status))
		Deinit();

	return status;
}
#pragma code_seg("PAGE")
void GlobalManager::Deinit()
{
	PAGED_CODE();

#if defined(TEST_NPT_HOOK)
	nptHookManager.Deinit();
	svmManager.Deinit();
	ptManager.Deinit();
#elif defined(TEST_MSR_HOOK)
	msrHookManager.Deinit();
	svmManager.Deinit();
#endif // TEST_NPT_HOOK
}
#pragma code_seg("PAGE")
GlobalManager::~GlobalManager()
{
	PAGED_CODE();

	GlobalManager::Deinit();
#ifdef TEST_NPT_HOOK
	if (pHookMem != NULL)
		ExFreePoolWithTag(pHookMem, 0x22);
#endif // TEST_NPT_HOOK
}