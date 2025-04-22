#include <ntddk.h>
#include <wdm.h>
#include "AMDVDriverSDK.h"

typedef PVOID(NTAPI* pExAllocatePool2Handler)(POOL_FLAGS Flags, SIZE_T NumberOfBytes, ULONG Tag);
typedef PVOID(NTAPI* pExAllocatePoolWithTagHandler)(POOL_TYPE PoolType, SIZE_T NumberOfBytes, ULONG Tag);

#pragma data_seg()
pExAllocatePool2Handler pFunctionCaller1 = NULL;
#pragma data_seg()
pExAllocatePoolWithTagHandler pFunctionCaller2 = NULL;

#pragma data_seg()
pExAllocatePool2Handler pSourceFunction1 = NULL;
#pragma data_seg()
pExAllocatePoolWithTagHandler pSourceFunction2 = NULL;

#pragma code_seg()
void SyscallCallback(GenericRegisters& guestRegisters, StackDump& stackDump, UINT32 pid, PVOID param)
{
	UNREFERENCED_PARAMETER(guestRegisters);
	UNREFERENCED_PARAMETER(stackDump);
	UNREFERENCED_PARAMETER(param);

	KdPrint(("Syscall interrepted PID = %d\n", pid));

	const SIZE_T lineSize = 16;

	KdPrint(("Stack dump:\n"));

	for (SIZE_T idx1 = 0; idx1 < sizeof stackDump / lineSize; ++idx1)
		KdPrint(("%2x %2x %2x %2x %2x %2x %2x %2x %2x %2x %2x %2x %2x %2x %2x %2x", 
				stackDump[idx1 * lineSize],
				stackDump[idx1 * lineSize + 1],
				stackDump[idx1 * lineSize + 2],
				stackDump[idx1 * lineSize + 3],
				stackDump[idx1 * lineSize + 4],
				stackDump[idx1 * lineSize + 5],
				stackDump[idx1 * lineSize + 6],
				stackDump[idx1 * lineSize + 7], 
				stackDump[idx1 * lineSize + 8], 
				stackDump[idx1 * lineSize + 9], 
				stackDump[idx1 * lineSize + 10], 
				stackDump[idx1 * lineSize + 11],
				stackDump[idx1 * lineSize + 12],
				stackDump[idx1 * lineSize + 13],
				stackDump[idx1 * lineSize + 14],
				stackDump[idx1 * lineSize + 15]));
}

#pragma code_seg("PAGE")
void DriverUnload(PDRIVER_OBJECT pDriverObject)
{
	PAGED_CODE();
	UNREFERENCED_PARAMETER(pDriverObject);

	AMDVDriverInterface::DelNptHook(pSourceFunction1);
	AMDVDriverInterface::DelNptHook(pSourceFunction2);

	if (pFunctionCaller2 != NULL)
		AMDVDriverInterface::DelFunctionCaller(pSourceFunction2);
	if (pFunctionCaller1 != NULL)
		AMDVDriverInterface::DelFunctionCaller(pSourceFunction1);

	SetLStartCallbackParam param = {};

	AMDVDriverInterface::SetSyscallHookCallback(NULL);

	return;
}

#pragma code_seg()
PVOID NTAPI ExAllocatePool2Handler(POOL_FLAGS Flags, SIZE_T NumberOfBytes, ULONG Tag)
{
	return pFunctionCaller1(Flags, NumberOfBytes, Tag);
}

#pragma code_seg()
PVOID NTAPI ExAllocatePoolWithTagHandler(POOL_TYPE PoolType, SIZE_T NumberOfBytes, ULONG Tag)
{
	return pFunctionCaller2(PoolType, NumberOfBytes, Tag);
}

#pragma code_seg("INIT")
extern "C" NTSTATUS DriverEntry(PDRIVER_OBJECT pDriverObject, PUNICODE_STRING pRegisterPath)
{
	UNREFERENCED_PARAMETER(pDriverObject);
	UNREFERENCED_PARAMETER(pRegisterPath);

	pDriverObject->DriverUnload = DriverUnload;

	if (!AMDVDriverInterface::IsInSVM())
	{
		KdPrint(("AMDVDriver is not present!"));
		return STATUS_UNSUCCESSFUL;
	}

	//获取ExAllocatePoolWithTag的虚拟地址
	UNICODE_STRING apiName = {};
	RtlInitUnicodeString(&apiName, L"ExAllocatePoolWithTag");
	pSourceFunction2 = (pExAllocatePoolWithTagHandler)MmGetSystemRoutineAddress(&apiName);

	if (pSourceFunction2 == NULL)
		KdPrint(("GlobalManager::HookApi(): ExAllocatePoolWithTag address not found!\n"));
	else
		KdPrint(("GlobalManager::HookApi(): ExAllocatePoolWithTag virtual address: %llx\n", (INT64)pSourceFunction2));

	//获取ExAllocatePool2的虚拟地址
	RtlInitUnicodeString(&apiName, L"ExAllocatePool2");
	pSourceFunction1 = (pExAllocatePool2Handler)MmGetSystemRoutineAddress(&apiName);

	if (pSourceFunction1 == NULL)
		KdPrint(("GlobalManager::HookApi(): ExAllocatePool2 address not found!\n"));
	else
		KdPrint(("GlobalManager::HookApi(): ExAllocatePool2 virtual address: %llx\n", (INT64)pSourceFunction1));

	//执行hook
	NptHookRecord record = {};

	//请在进入SVM之前或者卸载SVM之后修改HOOK
	//在SVM运行时修改HOOK 有非常大概率 出现DPC 超时

	if (pSourceFunction2 != NULL)
	{
		pFunctionCaller2 = (pExAllocatePoolWithTagHandler)AMDVDriverInterface::AddFunctionCaller(pSourceFunction2);

		if (pFunctionCaller2 == NULL)
		{
			KdPrint(("get ExAllocatePoolWithTag function caller failed!\n"));
		}
		else
		{
			KdPrint(("get ExAllocatePoolWithTag function caller success!\n"));

			record.pOriginVirtAddr = pSourceFunction2;
			record.pGotoVirtAddr = ExAllocatePoolWithTagHandler;

			if (AMDVDriverInterface::AddNptHook(record))
				KdPrint(("Hook ExAllocatePoolWithTag OK!\n"));
			else
				KdPrint(("Hook ExAllocatePoolWithTag Failed!\n"));
		}
	}

	if (pSourceFunction1 != NULL)
	{
		pFunctionCaller1 = (pExAllocatePool2Handler)AMDVDriverInterface::AddFunctionCaller(pSourceFunction1);

		if (pFunctionCaller1 == NULL)
		{
			KdPrint(("get ExAllocatePool2 function caller failed!\n"));
		}
		else
		{
			KdPrint(("get ExAllocatePool2 function caller success!\n"));

			pFunctionCaller1 = (pExAllocatePool2Handler)AMDVDriverInterface::AddFunctionCaller(pSourceFunction1);
			record.pOriginVirtAddr = pSourceFunction1;
			record.pGotoVirtAddr = ExAllocatePool2Handler;

			if (AMDVDriverInterface::AddNptHook(record))
				KdPrint(("Hook ExAllocatePool2 OK!\n"));
			else
				KdPrint(("Hook ExAllocatePool2 Failed!\n"));
		}
	}

	SetLStartCallbackParam param = {};

	param.callback = SyscallCallback;

	if (AMDVDriverInterface::SetSyscallHookCallback(&param))
		KdPrint(("Hook syscall OK!\n"));
	else
		KdPrint(("Hook syscall Failed!\n"));

	return STATUS_SUCCESS;
}