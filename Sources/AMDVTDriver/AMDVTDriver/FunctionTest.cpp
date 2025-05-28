//�������ܵĲ���ʾ��
#include "main.h"

#pragma code_seg()
void TestLStarHookCallback(GenericRegisters* pRegisters, PVOID param1, PVOID param2, PVOID param3)
{
	UNREFERENCED_PARAMETER(pRegisters);
	UNREFERENCED_PARAMETER(param1);
	UNREFERENCED_PARAMETER(param2);
	UNREFERENCED_PARAMETER(param3);

	static bool showMessage = false;
	if (!showMessage)
	{
		showMessage = true;
		KdPrint(("Msr Hook OK!\n"));
		KdPrint(("rax = %llu, user rsp = %p, param1 = %llu, param2 = %llu, param3 = %llu\n", pRegisters->rax, (PVOID)pRegisters->extraInfo1, (INT64)param1, (INT64)param2, (INT64)param3));
	}
}

typedef PVOID(*P_ExAllocatePool2)(POOL_FLAGS Flags, SIZE_T NumberOfBytes, ULONG Tag);
typedef PVOID(*P_ExAllocatePoolWithTag)(POOL_TYPE Flags, SIZE_T NumberOfBytes, ULONG Tag);

#pragma data_seg()
P_ExAllocatePoolWithTag pFunctionCaller1 = NULL;
#pragma data_seg()
P_ExAllocatePool2 pFunctionCaller2 = NULL;

#pragma code_seg()
PVOID NTAPI ExAllocatePoolWithTagHandler(POOL_TYPE PoolType, SIZE_T NumberOfBytes, ULONG Tag)
{
	PVOID result = pFunctionCaller1(PoolType, NumberOfBytes, Tag);

	return result;
}

#pragma code_seg()
PVOID NTAPI ExAllocatePool2Handler(POOL_FLAGS Flags, SIZE_T NumberOfBytes, ULONG Tag)
{	
	PVOID result = pFunctionCaller2(Flags, NumberOfBytes, Tag);

	return result;
}

#if defined(TEST_MSR_HOOK)
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
	svmManager.SetMsrBackupRestorePlugin(&msrHookManager);
}
#endif

#if defined(TEST_NPT_HOOK)
#pragma code_seg("PAGE")
void GlobalManager::HookApi()
{
	PAGED_CODE();

	//��ȡExAllocatePoolWithTag�������ַ
	UNICODE_STRING apiName = {};
	RtlInitUnicodeString(&apiName, L"ExAllocatePoolWithTag");
	PVOID apiVirtAddr1 = MmGetSystemRoutineAddress(&apiName);

	if (apiVirtAddr1 == NULL)
		KdPrint(("GlobalManager::HookApi(): ExAllocatePoolWithTag address not found!\n"));
	else
		KdPrint(("GlobalManager::HookApi(): ExAllocatePoolWithTag virtual address: %llx\n", (INT64)apiVirtAddr1));
	
	//��ȡExAllocatePool2�������ַ
	RtlInitUnicodeString(&apiName, L"ExAllocatePool2");
	PVOID apiVirtAddr2 = MmGetSystemRoutineAddress(&apiName);

	if (apiVirtAddr2 == NULL)
		KdPrint(("GlobalManager::HookApi(): ExAllocatePool2 address not found!\n"));
	else
		KdPrint(("GlobalManager::HookApi(): ExAllocatePool2 virtual address: %llx\n", (INT64)apiVirtAddr2));

	//ִ��hook
	NptHookRecord record = {};

	//���ڽ���SVM֮ǰ����ж��SVM֮���޸�HOOK
	//��SVM����ʱ�޸�HOOK �зǳ������ ����DPC ��ʱ

	if (apiVirtAddr1 != NULL)
	{
		pFunctionCaller1 = (P_ExAllocatePoolWithTag)functionCallerManager.GetFunctionCaller(apiVirtAddr1);

		record.pOriginVirtAddr = apiVirtAddr1;
		record.pGotoVirtAddr = ExAllocatePoolWithTagHandler;

		nptHookManager.AddHook(record);

		KdPrint(("Hook ExAllocatePoolWithTag OK!\n"));
	}

	if (apiVirtAddr2 != NULL)
	{
		pFunctionCaller2 = (P_ExAllocatePool2)functionCallerManager.GetFunctionCaller(apiVirtAddr2);

		record.pOriginVirtAddr = apiVirtAddr2;
		record.pGotoVirtAddr = ExAllocatePool2Handler;

		nptHookManager.AddHook(record);

		KdPrint(("Hook ExAllocatePool2 OK!\n"));
	}
	
#if defined(TEST_NPT_HOOK_REMOVE)
	nptHookManager.RemoveHook(apiVirtAddr1);
	nptHookManager.RemoveHook(apiVirtAddr2);
#endif
}
#endif
 
#if defined(TEST_MSR_HOOK)
#pragma code_seg("PAGE")
void GlobalManager::EnableMsrHook()
{
	PAGED_CODE();

	//HOOK MSR_LSTAR
	EnableLStrHook<1>(&msrHookManager, TestLStarHookCallback,(PVOID)1, (PVOID)2, (PVOID)3);
}
#endif

#pragma code_seg("PAGE")
NTSTATUS GlobalManager::Init()
{
	PAGED_CODE();

	NTSTATUS status = STATUS_SUCCESS;
	do
	{
#if defined(TEST_NPT_HOOK)

		status = nptHookManager.Init();
		if (!NT_SUCCESS(status))
			break;

		status = functionCallerManager.Init();
		if (!NT_SUCCESS(status))
			break;

		nptHookManager.SetupSVMManager(svmManager);

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

	svmManager.Deinit();
	nptHookManager.Deinit();
	functionCallerManager.Deinit();
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
}