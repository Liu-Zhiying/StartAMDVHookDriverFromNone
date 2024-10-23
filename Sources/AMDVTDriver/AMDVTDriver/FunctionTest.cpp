//驱动功能的测试示例
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
		KdPrint(("rax = %llu, user rsp = %p, param1 = %llu, param2 = %llu, param3 = %llu\n", pRegisters->rax, (PVOID)pRegisters->extraInfo1, param1, param2, param3));
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

	//设置要hook的msr
	//Hook IA32_MSR_LSTAR
	UINT32 msrNums[1] = { IA32_MSR_LSTAR };
	msrHookManager.SetHookMsrs(msrNums);

	//和SVMManager绑定
	svmManager.SetCpuIdInterceptPlugin(&msrHookManager);
	svmManager.SetMsrInterceptPlugin(&msrHookManager);
	svmManager.SetMsrHookPlugin(&msrHookManager);
}

#pragma code_seg("PAGE")
void GlobalManager::SetNptHook()
{
	PAGED_CODE();
	//设置NPT HOOK外部页表
	nptHookManager.SetPageTableManager(&ptManager);
	//拦截CPUID
	svmManager.SetCpuIdInterceptPlugin(&nptHookManager);
	//拦截NFP
	svmManager.SetNpfInterceptPlugin(&nptHookManager);
	//拦截BP
	svmManager.SetBreakpointPlugin(&nptHookManager);
}

#pragma code_seg("PAGE")
void GlobalManager::SetNpt()
{
	PAGED_CODE();
	//传递NPT页表
	KdPrint(("GlobalManager::Init(): Enable NPT\n"));
	svmManager.SetNCr3Provider(&ptManager);
}

#pragma code_seg("PAGE")
void GlobalManager::HookApi()
{
	PAGED_CODE();

	//获取ExAllocatePool2的虚拟地址
	UNICODE_STRING apiName = {};
	RtlInitUnicodeString(&apiName, L"ExAllocatePool2");
	PVOID apiVirtAddr = MmGetSystemRoutineAddress(&apiName);

	KdPrint(("GlobalManager::HookApi(): ExAllocatePool2 virtual address: %llx\n", apiVirtAddr));

	if (apiVirtAddr == NULL)
	{
		KdPrint(("GlobalManager::HookApi(): ExAllocatePool2 address not found!\n"));
		return;
	}

	//构造hook时返回执行原函数的代码，注意，这里的hook代码只对Windows 11 24h2有效
	//0x48, 0x89, 0x5c, 0x24, 0x10 
	//mov qword ptr [rsp+10h], rbx 这条指令是ExAllocatePool2在Windows 11 24h2的第一条指令
	//0xff, 0x25, 0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF
	//jmp 0xffffffffffffffff 这里的 0xffffffffffffffff 要替换为 ExAllocatePool2 的第二条指令的虚拟地址

	//如果系统版本不同，请根据实际情况修改

	UINT8 hookCode[] = { 0x48, 0x89, 0x5c, 0x24, 0x10, 0xff, 0x25, 0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF };

	*((PVOID*)(hookCode + 0xb)) = ((UINT8*)apiVirtAddr) + 0x5;

	pHookMem = ExAllocatePool2(POOL_FLAG_NON_PAGED_EXECUTE, sizeof(hookCode), 0x22);
	if (pHookMem == NULL)
	{
		KdPrint(("GlobalManager::HookApi(): Allocate hook memory failed!\n"));
		return;
	}
	//把机器码写入可执行内存
	RtlCopyMemory(pHookMem, hookCode, sizeof(hookCode));

	//执行hook
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
	EnableLStrHook<1>(&msrHookManager, TestLStarHookCallback,(PVOID)1, (PVOID)2, (PVOID)3);
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