#include <ntddk.h>
#include <wdm.h>
#include <stdio.h>
#include <intrin.h>
#include "SVM.h"
#include "Hook.h"
#include "PageTable.h"

void TestLStarHookCallback()
{
	static bool showMessage = false;
	if (!showMessage)
	{
		KdPrint(("Msr Hook OK!\n"));
		showMessage = true;
	}
}

void NptHookTest()
{
	KdPrint(("Npt Hook OK!\n"));
}

class GlobalManager : public IManager
{
	PageTableManager ptManager;
	SVMManager svmManager;
	MsrHookManager<1> msrHookManager;
	NptHookManager nptHookManager;
	PVOID pHookMem = NULL;
public:

	#pragma code_seg("PAGE")
	void SetMsrHookParameters()
	{
		PAGED_CODE();

		//设置要hook的msr
		//Hook IA32_MSR_LSTAR
		UINT32 msrNums[1] = { IA32_MSR_LSTAR };
		msrHookManager.SetHookMsrs(msrNums);

		//和SVMManager绑定
		svmManager.SetCpuIdInterceptPlugin(&msrHookManager);
		svmManager.SetMsrInterceptPlugin(&msrHookManager);
	}

	#pragma code_seg("PAGE")
	void SetNptHook()
	{
		PAGED_CODE();
		nptHookManager.SetPageTableManager(&ptManager);
		svmManager.SetNpfInterceptPlugin(&nptHookManager);
		svmManager.SetBreakpointPlugin(&nptHookManager);
	}

	#pragma code_seg("PAGE")
	void SetNpt()
	{
		PAGED_CODE();
		//传递NPT页表
		KdPrint(("GlobalManager::Init(): Enable NPT\n"));
		svmManager.SetNCr3Provider(&ptManager);
		//svmManager.SetNpfInterceptPlugin(&ptManager);
	}

	#pragma code_seg("PAGE")
	void HookApi()
	{
		PAGED_CODE();
		/*
		//测试页表处理性能
		KdPrint(("GlobalManager::Init(): Test LStar hook\n"));
		PageTableLevel123Entry entry = {};

		entry.fields.writeable = true;
		entry.fields.userAccess = true;

		LARGE_INTEGER frequency = {};

		KeQueryPerformanceCounter(&frequency);

		ULONGLONG timeBeg = KeQueryPerformanceCounter(NULL).QuadPart;

		ptManager.GetCoreNptPageTables()[0].ChangeAllPageTablePermession(entry);

		ULONGLONG timeEnd = KeQueryPerformanceCounter(NULL).QuadPart;

		KdPrint(("time elapsed = %lld\n", (timeEnd - timeBeg) / (frequency.QuadPart / 1000)));
		*/
		/*
		UINT8 hookCode[] = { 0x48,0xb8,0x88,0x77,0x66,0x55,0x44,0x33,0x22,0x11,0xff,0xf0,0x48,0x89,0x5c,0x24,0x08,0x48,0xb8,0x88,0x77,0x66,0x55,0x44,0x33,0x22,0x11,0xff,0xe0,0xc3 };
		UNICODE_STRING apiName = {};
		RtlInitUnicodeString(&apiName, L"ExAllocatePool2");
		PVOID apiVirtAddr = MmGetSystemRoutineAddress(&apiName);

		KdPrint(("GlobalManager::Init(): ExAllocatePool2 virtual address: %llx\n", apiVirtAddr));

		if (apiVirtAddr == NULL)
		{
			KdPrint(("GlobalManager::Init(): ExAllocatePool2 address not found!\n"));
			return;
		}

		PTR_TYPE apiPhyAddr = MmGetPhysicalAddress(apiVirtAddr).QuadPart;

		KdPrint(("GlobalManager::Init(): ExAllocatePool2 physical address: %llx\n", apiPhyAddr));

		pHookMem = ExAllocatePool2(POOL_FLAG_NON_PAGED_EXECUTE, sizeof(hookCode), 0x22);
		if (pHookMem == NULL)
		{
			KdPrint(("GlobalManager::Init(): Allocate hook memory failed!\n"));
			return;
		}

		RtlCopyMemory(hookCode, pHookMem, sizeof(hookCode));
		PVOID* pTemp = (PVOID*)pHookMem + 0x2;
		*pTemp = NptHookTest;

		pTemp = (PVOID*)pHookMem + 0x14;
		*pTemp = (PUINT8)apiVirtAddr + 0x5;

		HookRecord record = {};
		record.pOriginVirtAddr = apiVirtAddr;
		record.pGotoVirtAddr = pHookMem;

		nptHookManager.AddHook(record);
		*/
	}

	#pragma code_seg("PAGE")
	void EnableMsrHook()
	{
		PAGED_CODE();

		//hook lstar
		EnableLStrHook<1>(&msrHookManager, TestLStarHookCallback);
	}

	#pragma code_seg("PAGE")
	virtual NTSTATUS Init() override
	{
		PAGED_CODE();

		NTSTATUS status = STATUS_SUCCESS;
		do
		{

			SetMsrHookParameters();

			status = msrHookManager.Init();
			if (!NT_SUCCESS(status))
				break;

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

			EnableMsrHook();

			HookApi();

		} while (false);

		if (!NT_SUCCESS(status))
			Deinit();

		return status;
	}
	#pragma code_seg("PAGE")
	virtual void Deinit() override
	{
		PAGED_CODE();

		msrHookManager.Deinit();
		svmManager.Deinit();
		ptManager.Deinit();
	}
	#pragma code_seg("PAGE")
	virtual ~GlobalManager()
	{
		PAGED_CODE();

		GlobalManager::Deinit();

		if (pHookMem != NULL)
			ExFreePoolWithTag(pHookMem, 0x22);
	}
};

#pragma code_seg("PAGE")
NTSTATUS DriverIOHandler(IN PDEVICE_OBJECT,
	IN PIRP Irp)
{
	PAGED_CODE();
	Irp->IoStatus.Status = STATUS_SUCCESS;
	Irp->IoStatus.Information = 0;
	IoCompleteRequest(Irp, IO_NO_INCREMENT);
	return STATUS_SUCCESS;
}

#pragma code_seg("PAGE")
void UnloadDriver(IN PDRIVER_OBJECT drvObj)
{
	PAGED_CODE();
	PDEVICE_OBJECT devObj = drvObj->DeviceObject;
	if (devObj != NULL)
	{
		UNICODE_STRING symLinkName;
		RtlInitUnicodeString(&symLinkName, L"\\DosDevices\\AMDVTDriver");
		GlobalManager* pGlobalManager = (GlobalManager*)drvObj->DeviceObject->DeviceExtension;
		//如果你在DriverEntry里面调用IoCreateSymbolicLink的话加上这句
		//因为你在DriverEntry里面使用的常量跟着DriverEntry一起卸载了
		IoDeleteSymbolicLink(&symLinkName);
		IoDeleteDevice(devObj);
		CallDestroyer(pGlobalManager);
	}
	KdPrint(("AMD-V driver has exited\n"));
}

#pragma code_seg("INIT")
extern "C" NTSTATUS DriverEntry(IN PDRIVER_OBJECT pDriverObject,
	IN PUNICODE_STRING)
{
	////过ObRegisterCallbacks驱动签名检测
	//PVOID thisDrvSection = pDriverObject->DriverSection;
	//*((PUINT32)((PUCHAR)thisDrvSection + 0x68)) |= 0x20;

	pDriverObject->MajorFunction[IRP_MJ_CLOSE] =
		pDriverObject->MajorFunction[IRP_MJ_CREATE] =
		pDriverObject->MajorFunction[IRP_MJ_READ] =
		pDriverObject->MajorFunction[IRP_MJ_WRITE] = DriverIOHandler;
	pDriverObject->DriverUnload = UnloadDriver;

	UINT32 initStep = 0;
	NTSTATUS status = STATUS_SUCCESS;
	PDEVICE_OBJECT fdo = NULL;
	GlobalManager* pGlobalManager = NULL;
	UNICODE_STRING devName;
	UNICODE_STRING symLinkName;
	RtlInitUnicodeString(&devName, L"\\Device\\AMDVTDriver");
	RtlInitUnicodeString(&symLinkName, L"\\DosDevices\\AMDVTDriver");
	do
	{
		KdPrint(("DriverEntry(): Starting AMD-V Driver\n"));

		status = IoCreateDevice(pDriverObject, sizeof(GlobalManager), &devName, FILE_DEVICE_UNKNOWN,
			0, TRUE, &fdo);
		if (!NT_SUCCESS(status))
			break;
		initStep = 1;

		pGlobalManager = ((GlobalManager*)fdo->DeviceExtension);
		CallConstructor(pGlobalManager);
		
		status = IoCreateSymbolicLink(&symLinkName, &devName);
		if (!NT_SUCCESS(status))
			break;
		initStep = 2;

		status = pGlobalManager->Init();
		if (!NT_SUCCESS(status))
			break;
		initStep = 3;

		fdo->Flags |= DO_BUFFERED_IO;
		KdPrint(("DriverEntry(): AMD-V Driver Start successfully.\n"));
	} while (0);

	if (!NT_SUCCESS(status))
	{
		CHAR errorInfo[100] = {};
		sprintf(errorInfo, "DriverEntry(): AMD-V Driver Init Err, Step: %d, Code: %x\n", initStep, status);
		KdPrint((errorInfo));
		switch (initStep)
		{
		case 3:
			CallDestroyer(pGlobalManager);
		case 2:
			IoDeleteSymbolicLink(&symLinkName);
		case 1:
			IoDeleteDevice(fdo);
		default:
			break;
		}
	}

	return status;
}