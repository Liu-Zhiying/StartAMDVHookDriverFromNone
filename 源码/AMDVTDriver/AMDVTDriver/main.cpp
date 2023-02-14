#include <ntddk.h>
#include <wdm.h>
#include <stdio.h>
#include "CheckAMDV.h"
#include "PageTable.h"

#pragma warning(disable : 4100)

typedef struct _DRV_RECORD
{
	UNICODE_STRING symLinkName;
	UINT32 initStatus;
} DRV_RECORD;

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
		RtlInitUnicodeString(&((DRV_RECORD*)devObj->DeviceExtension)->symLinkName, L"\\DosDevices\\LzyWFPDriverTest");
		IoDeleteSymbolicLink(&((DRV_RECORD*)devObj->DeviceExtension)->symLinkName);
		IoDeleteDevice(devObj);
	}
	KdPrint(("AMD-V driver has exited\n"));
}

#pragma code_seg("INIT")
extern "C" NTSTATUS DriverEntry(IN PDRIVER_OBJECT pDriverObject,
	IN PUNICODE_STRING)
{
	KdPrint(("AMD-V Driver Starting\n"));
	char szCpuString[13];
	CPUString(szCpuString);
	if (strcmp(szCpuString, "AuthenticAMD"))
	{
		KdPrint(("Can not AMD-V Driver，The Machine does not using AMD CPU，CPU string is: %s\n", szCpuString));
		return STATUS_FAILED_DRIVER_ENTRY;
	}
	if (QuerySVMStatus() != (SVM_ENABLED | SVM_READY | SVM_SUPPORTED))
	{
		KdPrint(("Can not AMD-V Driver，Do not support SVM or SVM is not enabled\n"));
		return STATUS_FAILED_DRIVER_ENTRY;
	}

	//现在调用没啥卵用，仅测试
	//这个函数的主要目的是为接下来拷贝Windows页表（这个说法可能有点不准确，但是VT驱动需要根据Windows页表单独搞一个新页表）做准备
	PTR_TYPE tmp1 = 0, tmp2 = 0;
	GetPageTableBaseVirtualAddress(&tmp1, &tmp2);

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
	UNICODE_STRING devName;
	RtlInitUnicodeString(&devName, L"\\Device\\AMDVTDriver");
	do
	{
		KdPrint(("Init AMD-V Driver Data\n"));

		status = IoCreateDevice(
			pDriverObject,
			//分配内存大小
			sizeof(DRV_RECORD),
			&devName,
			FILE_DEVICE_UNKNOWN,
			0,
			FALSE,
			&fdo);
		if (!NT_SUCCESS(status))
			break;

		RtlInitUnicodeString(&((DRV_RECORD*)fdo->DeviceExtension)->symLinkName, L"\\DosDevices\\LzyWFPDriverTest");

		status = IoCreateSymbolicLink(&((DRV_RECORD*)fdo->DeviceExtension)->symLinkName, &devName);
		if (!NT_SUCCESS(status))
			break;

		((DRV_RECORD*)fdo->DeviceExtension)->initStatus = 1;
	} while (0);

	if (!NT_SUCCESS(status))
	{
		CHAR errorInfo[80] = {};
		sprintf(errorInfo, "Init err, Code: %x\n", status);
		KdPrint((errorInfo));

		if (fdo != NULL)
		{
			IoDeleteSymbolicLink(&((DRV_RECORD*)fdo->DeviceExtension)->symLinkName);
			IoDeleteDevice(fdo);
		}
	}

	if (fdo != NULL)
	{
		KdPrint(("\n"));
		fdo->Flags |= DO_BUFFERED_IO;
	}

	KdPrint(("AMD-V Driver Start successfully.\n"));

	return status;
}