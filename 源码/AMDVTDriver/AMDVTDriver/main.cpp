#include <ntddk.h>
#include <wdm.h>
#include <stdio.h>
#include "CheckAMDV.h"
#include "PageTable.h"

#pragma warning(disable : 4100)

typedef struct _DRV_GDATA
{
	UNICODE_STRING symLinkName;
	PT_G_INFO gPtInfo;
} DRV_GDATA;

#pragma code_seg()
NTSTATUS DriverIOHandler(IN PDEVICE_OBJECT,
	IN PIRP Irp)
{
	Irp->IoStatus.Status = STATUS_SUCCESS;
	Irp->IoStatus.Information = 0;
	IoCompleteRequest(Irp, IO_NO_INCREMENT);
	return STATUS_SUCCESS;
}

#pragma code_seg()
void UnloadDriver(IN PDRIVER_OBJECT drvObj)
{
	PDEVICE_OBJECT devObj = drvObj->DeviceObject;
	if (devObj != NULL)
	{
		//如果你在DriverEntry里面调用IoCreateSymbolicLink的话加上这句
		//因为你在DriverEntry里面使用的常量跟着DriverEntry一起卸载了
		RtlInitUnicodeString(&((DRV_GDATA*)devObj->DeviceExtension)->symLinkName, L"\\DosDevices\\LzyWFPDriverTest");
		IoDeleteSymbolicLink(&((DRV_GDATA*)devObj->DeviceExtension)->symLinkName);
		IoDeleteDevice(devObj);
	}
	KdPrint(("AMD-V driver has exited\n"));
}

#pragma code_seg("INIT")
extern "C" NTSTATUS DriverEntry(IN PDRIVER_OBJECT pDriverObject,
	IN PUNICODE_STRING)
{

	//过ObRegisterCallbacks驱动签名检测
	PVOID thisDrvSection = pDriverObject->DriverSection;
	*((PUINT32)((PUCHAR)thisDrvSection + 0x68)) |= 0x20;

	pDriverObject->MajorFunction[IRP_MJ_CLOSE] =
		pDriverObject->MajorFunction[IRP_MJ_CREATE] =
		pDriverObject->MajorFunction[IRP_MJ_READ] =
		pDriverObject->MajorFunction[IRP_MJ_WRITE] = DriverIOHandler;
	pDriverObject->DriverUnload = UnloadDriver;

	NTSTATUS status = STATUS_SUCCESS;
	PDEVICE_OBJECT fdo = NULL;
	DRV_GDATA* pGData = NULL;
	UNICODE_STRING devName;
	UINT32 initStep = 0;
	RtlInitUnicodeString(&devName, L"\\Device\\AMDVTDriver");
	do
	{
		KdPrint(("Starting AMD-V Driver\n"));

		char szCpuString[13];
		CPUString(szCpuString);
		if (strcmp(szCpuString, "AuthenticAMD"))
		{
			KdPrint(("Can not AMD-V Driver，The Machine does not using AMD CPU，CPU string is: %s\n", szCpuString));
			status = STATUS_FAILED_DRIVER_ENTRY;
			break;
		}

		if (QuerySVMStatus() != (SVM_ENABLED | SVM_READY | SVM_SUPPORTED))
		{
			KdPrint(("Can not AMD-V Driver，Do not support SVM or SVM is not enabled\n"));
			status = STATUS_FAILED_DRIVER_ENTRY;
			break;
		}

		status = IoCreateDevice(pDriverObject, sizeof(DRV_GDATA), &devName, FILE_DEVICE_UNKNOWN,
			0, FALSE, &fdo);
		if (!NT_SUCCESS(status))
			break;
		initStep = 1;

		pGData = ((DRV_GDATA*)fdo->DeviceExtension);

		RtlInitUnicodeString(&pGData->symLinkName, L"\\DosDevices\\LzyWFPDriverTest");
		status = IoCreateSymbolicLink(&pGData->symLinkName, &devName);
		if (!NT_SUCCESS(status))
			break;
		initStep = 2;

		//现在调用没啥卵用，仅测试
		//这个函数的主要目的是为接下来拷贝Windows页表（这个说法可能有点不准确
		//但是VT驱动需要根据Windows页表单独搞一个新页表）做准备
		GetPageTableBaseVirtualAddress(&pGData->gPtInfo.pPxe, &pGData->gPtInfo.pageSize);

		//测试代码
		InitGlobalNewPageTableInfo(&pGData->gPtInfo);
		PVOID pNewBlock = NULL;
		if (AllocPageTableInfoBlock(&pGData->gPtInfo, &pNewBlock) == STATUS_SUCCESS)
			AttachPageTableInfoBlockToList(&pGData->gPtInfo, pNewBlock);
		if (AllocPageTableInfoBlock(&pGData->gPtInfo, &pNewBlock) == STATUS_SUCCESS)
			AttachPageTableInfoBlockToList(&pGData->gPtInfo, pNewBlock);
		if (AllocPageTableInfoBlock(&pGData->gPtInfo, &pNewBlock) == STATUS_SUCCESS)
			AttachPageTableInfoBlockToList(&pGData->gPtInfo, pNewBlock);
		if (AllocPageTableInfoBlock(&pGData->gPtInfo, &pNewBlock) == STATUS_SUCCESS)
			AttachPageTableInfoBlockToList(&pGData->gPtInfo, pNewBlock);
		DestroyPageTableInfoBlockList(&pGData->gPtInfo);
		//拷贝页表


		fdo->Flags |= DO_BUFFERED_IO;
		KdPrint(("AMD-V Driver Start successfully.\n"));
	} while (0);

	if (!NT_SUCCESS(status))
	{
		CHAR errorInfo[80] = {};
		sprintf(errorInfo, "AMD-V Driver Init Err, Step: %d, Code: %x\n", initStep, status);
		KdPrint((errorInfo));
		switch (initStep)
		{
		case 1:
			IoDeleteDevice(fdo);
			break;
		case 0:
			return status;
		default:
			break;
		}
	}

	return status;
}