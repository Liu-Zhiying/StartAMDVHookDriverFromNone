#include <ntddk.h>
#include <wdm.h>
#include <stdio.h>
#include "SVM.h"
#include "Hook.h"
#include "PageTable.h"

#pragma code_seg()
UINT8 teststack[KERNEL_STACK_SIZE];

class GlobalManager : public IManager
{
	PageTableManager ptManager;
	SVMManager svmManager;
	MsrHookManager<1> msrHookManager;
	IManager* subManagers[3] = { &msrHookManager, &ptManager, &svmManager };
public:

	#pragma code_seg("PAGE")
	void SetMsrHookParameters()
	{
		PAGED_CODE();

		//设置要hook的msr
		UINT32 msrNums[1] = { 0xC0000082 };
		msrHookManager.SetHookMsrs(msrNums);

		//和SVMManager绑定
		svmManager.SetCpuIdInterceptPlugin(&msrHookManager);
		svmManager.SetMsrInterceptPlugin(&msrHookManager);
	}

	#pragma code_seg("PAGE")
	virtual NTSTATUS Init() override
	{
		PAGED_CODE();
		SetMsrHookParameters();
		NTSTATUS status = STATUS_SUCCESS;
		do
		{
			SIZE_T idx = 0;
			for (idx = 0; idx < GetArrayElementCnt(subManagers); ++idx)
			{
				status = subManagers[idx]->Init();
				if (!NT_SUCCESS(status))
					break;
			}
			if (!NT_SUCCESS(status))
				Deinit();
		} while (false);
		return status;
	}
	#pragma code_seg("PAGE")
	virtual void Deinit() override
	{
		PAGED_CODE();
		SIZE_T idx = 0;
		for (idx = GetArrayElementCnt(subManagers); idx; --idx)
			subManagers[idx - 1]->Deinit();
	}
	#pragma code_seg("PAGE")
	virtual ~GlobalManager()
	{
		PAGED_CODE();
		GlobalManager::Deinit();
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