#include "SVM.h"
#include "VMCB.h"
#include <intrin.h>

//AMD SVM û��ר�ŵ�VMMCALLָ�ֻ��ʹ���Զ���CPUID
//AMD �ֲ��ϸ����⻯Ԥ����CPUID ID Ϊ 0x40000000~0x400000ff
const UINT32 GUEST_CALL_VMM_CPUID_FUNCTION = 0x400000ff;
const UINT32 SVM_TAG = MAKE_TAG('s', 'v', 'm', ' ');

//GDT����ο�https://wiki.osdev.org/Global_Descriptor_Table#System_Segment_Descriptor
//�ճ�https://github.com/tandasat/SimpleSvm
typedef struct _SEGMENT_DESCRIPTOR
{
	union
	{
		UINT64 AsUInt64;
		struct
		{
			UINT16 LimitLow;        // [0:15]
			UINT16 BaseLow;         // [16:31]
			UINT32 BaseMiddle : 8;  // [32:39]
			UINT32 Type : 4;        // [40:43]
			UINT32 System : 1;      // [44]
			UINT32 Dpl : 2;         // [45:46]
			UINT32 Present : 1;     // [47]
			UINT32 LimitHigh : 4;   // [48:51]
			UINT32 Avl : 1;         // [52]
			UINT32 LongMode : 1;    // [53]
			UINT32 DefaultBit : 1;  // [54]
			UINT32 Granularity : 1; // [55]
			UINT32 BaseHigh : 8;    // [56:63]	
		} Fields;
	};
	//��һ���������Լ����ӣ����ಿ�ֺ�git��Ŀһ��
	//��һ�����Ƿ���ڿ�Type��Ա��X64ǿ��ƽ̹�Σ����ڴ���κ����ݶ���һ���ֲ�����
	//�����Ŷ�(gate segment)��ϵͳ��(system segment)������Щ��Ա�����Ҷ�����в�ͬ������ο�CPU�ֲ�
	//��������Ҫ��ȡϵͳ��(TSS LDT)�Ļ�ַ
	struct
	{
		UINT32 BaseHigh4Byte;
		UINT32 Reserved;
	} OptionalField;
} SEGMENT_DESCRIPTOR, * PSEGMENT_DESCRIPTOR;

//��ѡ������attribute
//�ճ�https://github.com/tandasat/SimpleSvm
typedef struct _SEGMENT_ATTRIBUTE
{
	union
	{
		UINT16 AsUInt16;
		struct
		{
			UINT16 Type : 4;        // [0:3]
			UINT16 System : 1;      // [4]
			UINT16 Dpl : 2;         // [5:6]
			UINT16 Present : 1;     // [7]
			UINT16 Avl : 1;         // [8]
			UINT16 LongMode : 1;    // [9]
			UINT16 DefaultBit : 1;  // [10]
			UINT16 Granularity : 1; // [11]
			UINT16 Reserved1 : 4;   // [12:15]
		} Fields;
	};
} SEGMENT_ATTRIBUTE, * PSEGMENT_ATTRIBUTE;

//һϵ�л�ຯ��
//Դ������SVM_asm.asm����
//��Ҫ���ǼĴ�����ȡ����
extern "C" void _mysgdt(UINT64* pBase, UINT16* pLImit);
extern "C" void _mysidt(UINT64* pBase, UINT16* pLImit);
extern "C" void _mysldt(UINT16* pSelector);
extern "C" void _mystr(UINT16* pSelector);
extern "C" UINT16 _cs_selector();
extern "C" UINT16 _ds_selector();
extern "C" UINT16 _es_selector();
extern "C" UINT16 _fs_selector();
extern "C" UINT16 _gs_selector();
extern "C" UINT16 _ss_selector();
//���ڱ��ݺͻ�ԭ�Ĵ���������
extern "C" void _save_or_load_regs(GenericRegisters* pRegisters);
//ִ��vmrun��ز���
extern "C" void _run_svm_vmrun(VirtCpuInfo* pInfo, PVOID pGuestVmcbPhyAddr, PVOID pHostVmcbPhyAddr, PVOID pStack);

//���������ȫ�ճ�https://github.com/tandasat/SimpleSvm
//ԭ����������SvGetSegmentAccessRight
//��ȡ�μĴ���Attribute
#pragma code_seg("PAGE")
UINT16 _GetSegmentAttribute(_In_ UINT16 SegmentSelector, _In_ ULONG_PTR GdtBase)
{
	PAGED_CODE();
	PSEGMENT_DESCRIPTOR descriptor = NULL;
	SEGMENT_ATTRIBUTE attribute = {};

	//���ڶ�ѡ���ӵĽṹ�ο�https://wiki.osdev.org/Segment_Selector
	//��3bit�Ǳ�־�����ﲻ�ܻ�ַ��LDT����������������ƾ��Ǽ����ַ��GDT
	descriptor = reinterpret_cast<PSEGMENT_DESCRIPTOR>(
		GdtBase + (SegmentSelector & ~0x7));

	attribute.Fields.Type = descriptor->Fields.Type;
	attribute.Fields.System = descriptor->Fields.System;
	attribute.Fields.Dpl = descriptor->Fields.Dpl;
	attribute.Fields.Present = descriptor->Fields.Present;
	attribute.Fields.Avl = descriptor->Fields.Avl;
	attribute.Fields.LongMode = descriptor->Fields.LongMode;
	attribute.Fields.DefaultBit = descriptor->Fields.DefaultBit;
	attribute.Fields.Granularity = descriptor->Fields.Granularity;
	attribute.Fields.Reserved1 = 0;

	return attribute.AsUInt16;
}

//��ȡ�μĴ���Base
#pragma code_seg("PAGE")
UINT64 _GetSegmentBaseAddress(_In_ UINT16 SegmentSelector, _In_ ULONG_PTR GdtBase)
{
	PAGED_CODE();
	PSEGMENT_DESCRIPTOR descriptor;
	UINT64 baseAddress = 0;

	descriptor = reinterpret_cast<PSEGMENT_DESCRIPTOR>(
		GdtBase + (SegmentSelector & ~0x7));

	baseAddress |= descriptor->Fields.BaseLow;
	baseAddress |= ((UINT64)descriptor->Fields.BaseMiddle) << 16;
	baseAddress |= ((UINT64)descriptor->Fields.BaseHigh) << 24;
	baseAddress |= ((UINT64)descriptor->OptionalField.BaseHigh4Byte) << 32;

	return baseAddress;
}

//��ȡ�μĴ���Limit
#pragma code_seg("PAGE")
UINT32 _GetSegmentLimit(_In_ UINT16 SegmentSelector, _In_ ULONG_PTR GdtBase)
{
	PAGED_CODE();
	PSEGMENT_DESCRIPTOR descriptor;
	UINT32 limit = 0;

	descriptor = reinterpret_cast<PSEGMENT_DESCRIPTOR>(
		GdtBase + (SegmentSelector & ~0x7));

	limit |= descriptor->Fields.LimitLow;
	limit |= ((UINT64)descriptor->Fields.LimitHigh) << 16;

	return limit;
}

//#VMEXIT��������
#pragma code_seg()
extern "C" void VmExitHandler(VirtCpuInfo* pVirtCpuInfo, GenericRegisters* pGuestRegisters, PVOID pGuestVmcbPhyAddr, PVOID pHostVmcbPhyAddr)
{
	UNREFERENCED_PARAMETER(pHostVmcbPhyAddr);
	UNREFERENCED_PARAMETER(pGuestVmcbPhyAddr);

	//����ռĴ������������ִ�л����˳������
	pGuestRegisters->extraInfo1 = 0;
	pGuestRegisters->extraInfo2 = 0;

	switch ((VmExitReasons)pVirtCpuInfo->guestVmcb.controlFields.exitCode)
	{
	case VMEXIT_REASON_CPUID:
	{
		int cpuidResult[4] = {};

		if (pVirtCpuInfo->otherInfo.pMsrInterceptPlugin != NULL &&
			pVirtCpuInfo->otherInfo.pCpuIdInterceptPlugin->HandleCpuid(pVirtCpuInfo, pGuestRegisters,
																	  pGuestVmcbPhyAddr, pHostVmcbPhyAddr))
			return;

		if (((int)pVirtCpuInfo->guestVmcb.statusFields.rax) == GUEST_CALL_VMM_CPUID_FUNCTION)
		{
			switch (pGuestRegisters->rcx)
			{
			case 0:
			{
				//�����˳����⻯֮���ָ��Ĵ�����ջ�Ĵ���
				pGuestRegisters->extraInfo1 = pVirtCpuInfo->guestVmcb.controlFields.nRip;
				pGuestRegisters->extraInfo2 = pVirtCpuInfo->guestVmcb.statusFields.rsp;

				//����RFlags
				pGuestRegisters->rflags = pVirtCpuInfo->guestVmcb.statusFields.rflags;

				//���˳�VMMʱ��GIF�������˳���ϵͳ����ղ����жϼ������ڽ���Hostģʽ��ʱ��GIF�ǹر�״̬
				__svm_stgi();
				__svm_vmsave((SIZE_T)pGuestVmcbPhyAddr);

				//�˳����⻯������ִ��guest
				UINT64 eferVal = __readmsr(IA32_MSR_EFER);
				__writemsr(IA32_MSR_EFER, eferVal & ~(1ULL << EFER_SVME_OFFSET));
				__writeeflags((UINT32)pVirtCpuInfo->guestVmcb.statusFields.rflags);

				break;
			}
			}
		}
		else
		{
			//KdPrint(("CPUID Parameter: function = %x, subleaf = %x\n", (int)pVirtCpuInfo->guestVmcb.statusFields.rax, (int)pGuestRegisters->rcx));

			__cpuidex(cpuidResult, (int)pVirtCpuInfo->guestVmcb.statusFields.rax, (int)pGuestRegisters->rcx);

			if (((int)pVirtCpuInfo->guestVmcb.statusFields.rax) == CPUID_FN_SVM_FEATURE)
				cpuidResult[2] &= ~(1UL << CPUID_FN_80000001_ECX_SVM_OFFSET);

			*reinterpret_cast<UINT32*>(&pVirtCpuInfo->guestVmcb.statusFields.rax) = cpuidResult[0];
			*reinterpret_cast<UINT32*>(&pGuestRegisters->rbx) = cpuidResult[1];
			*reinterpret_cast<UINT32*>(&pGuestRegisters->rcx) = cpuidResult[2];
			*reinterpret_cast<UINT32*>(&pGuestRegisters->rdx) = cpuidResult[3];

			//KdPrint(("CPUID Result: eax = %x, ebx = %x, ecx = %x, edx = %x\n", (int)pVirtCpuInfo->guestVmcb.statusFields.rax,
			//(int)pGuestRegisters->rbx,
			//(int)pGuestRegisters->rcx,
			//(int)pGuestRegisters->rdx));
		}
		break;
	}
	case VMEXIT_REASON_MSR:
	{
		ULARGE_INTEGER value = {};
		UINT32 msrNum = (UINT32)pGuestRegisters->rcx;
		bool isWriteAccess = pVirtCpuInfo->guestVmcb.controlFields.exitInfo1;

		KdPrint(("%s address = %x", isWriteAccess ? "wrmsr" : "rdmsr", msrNum));

		if (isWriteAccess)
		{
			value.LowPart = (UINT32)pVirtCpuInfo->guestVmcb.statusFields.rax;
			value.HighPart = (UINT32)pGuestRegisters->rdx;

			if (pVirtCpuInfo->otherInfo.pMsrInterceptPlugin != NULL &&
				pVirtCpuInfo->otherInfo.pMsrInterceptPlugin->HandleMsrInterceptWrite(pVirtCpuInfo, pGuestRegisters,
																					 pGuestVmcbPhyAddr, pHostVmcbPhyAddr,
																					 msrNum, value))
				return;

			//�������ͻ������� EFER MSR �� SVME λ �� VM_CR MSR �� SVMDIS λ
			if (msrNum == IA32_MSR_EFER && !(value.LowPart & (1UL << EFER_SVME_OFFSET)) ||
				msrNum == IA32_MSR_VM_CR && !(value.LowPart & (1ULL << VM_CR_SVMDIS_OFFSET)))
				KeBugCheck(MANUALLY_INITIATED_CRASH);

			__writemsr(msrNum, value.QuadPart);
		}
		else
		{
			if (pVirtCpuInfo->otherInfo.pMsrInterceptPlugin != NULL &&
				pVirtCpuInfo->otherInfo.pMsrInterceptPlugin->HandleMsrImterceptRead(pVirtCpuInfo, pGuestRegisters, 
																					pGuestVmcbPhyAddr, pHostVmcbPhyAddr, 
																					msrNum, &value))
				return;

			value.QuadPart = __readmsr(msrNum);

			if (msrNum == IA32_MSR_VM_CR)
				value.QuadPart |= (1ULL << VM_CR_SVMDIS_OFFSET);
			if (msrNum == IA32_MSR_EFER)
				value.QuadPart &= ~(1UL << EFER_SVME_OFFSET);

			*reinterpret_cast<UINT32*>(&pVirtCpuInfo->guestVmcb.statusFields.rax) = value.LowPart;
			*reinterpret_cast<UINT32*>(&pGuestRegisters->rdx) = value.HighPart;
		}
		break;
	}
	case VMEXIT_REASON_VMRUN:
	{
		KeBugCheck(MANUALLY_INITIATED_CRASH);
		break;
	}
	default:
		break;
	}

	//guest����һ��ָ��ִ��
	pVirtCpuInfo->guestVmcb.statusFields.rip = pVirtCpuInfo->guestVmcb.controlFields.nRip;

	return;
}

#pragma code_seg("PAGE")
void CPUString(char* outputString)
{
	PAGED_CODE();
	UINT32 cpuid_result[4] = {};
	__cpuidex((int*)cpuid_result, 0, 0);
	memcpy(outputString, &cpuid_result[1], sizeof(UINT32));
	memcpy(outputString + sizeof(UINT32), &cpuid_result[3], sizeof(UINT32));
	memcpy(outputString + sizeof(UINT32) * 2, &cpuid_result[2], sizeof(UINT32));
	outputString[3 * sizeof(UINT32)] = 0;
}

//����MSR���ر�־λmap
#pragma code_seg("PAGE")
NTSTATUS MsrPremissionsMapManager::Init()
{
	PAGED_CODE();

	if (IsInited())
		return STATUS_SUCCESS;

	const UINT32 BITS_PER_MSR = 2;
	//FIRST_MSR_RANGE_BASE = 0x00000000;
	//FIRST_MSRPM_OFFSET = 0x000 * CHAR_BIT;
	const UINT32 SECOND_MSR_RANGE_BASE = 0xc0000000;
	const UINT32 SECOND_MSRPM_OFFSET = 0x800 * CHAR_BIT;
	const UINT32 THIRD_MSR_RANGE_BASE = 0xc0010000;
	const UINT32 THIRD_MSRPM_OFFSET = 0x1000 * CHAR_BIT;
	const ULONG EFER_OFFSET = SECOND_MSRPM_OFFSET + ((IA32_MSR_EFER - SECOND_MSR_RANGE_BASE) * BITS_PER_MSR);
	const ULONG VM_CR_OFFSET = THIRD_MSRPM_OFFSET + ((IA32_MSR_VM_CR - THIRD_MSR_RANGE_BASE) * BITS_PER_MSR);
	RTL_BITMAP bitmapHeader = {};

	//�������������ڴ�
	pMsrPremissionsMapVirtAddr = MmAllocateContiguousMemory(2ULL * PAGE_SIZE, highestPhyAddr);
	if (pMsrPremissionsMapVirtAddr == NULL)
	{
		KdPrint(("MsrPremissionsMapManager::Init(): Memory not enough!\n"));
		return STATUS_INSUFFICIENT_RESOURCES;
	}

	//��ʼ���ڴ��ֵ
	RtlInitializeBitMap(&bitmapHeader, (PULONG)pMsrPremissionsMapVirtAddr, 2 * PAGE_SIZE * CHAR_BIT);
	RtlClearAllBits(&bitmapHeader);

	//EFER��ȡ����
	RtlSetBits(&bitmapHeader, EFER_OFFSET, 1);
	//EFERд������
	RtlSetBits(&bitmapHeader, EFER_OFFSET + 1, 1);
	//VM_CR��ȡ����
	RtlSetBits(&bitmapHeader, VM_CR_OFFSET, 1);
	//VM_CRд������
	RtlSetBits(&bitmapHeader, VM_CR_OFFSET + 1, 1);

	if (pMsrInterceptPlugin != NULL)
		pMsrInterceptPlugin->SetMsrPremissionMap(bitmapHeader);

	//��ȡ������ַ
	pMsrPremissionsMapPhyAddr = (PVOID)MmGetPhysicalAddress(pMsrPremissionsMapVirtAddr).QuadPart;
	return STATUS_SUCCESS;
}

#pragma code_seg("PAGE")
void MsrPremissionsMapManager::Deinit()
{
	PAGED_CODE();
	if (pMsrPremissionsMapVirtAddr != NULL)
	{
		MmFreeContiguousMemory(pMsrPremissionsMapVirtAddr);
		pMsrPremissionsMapVirtAddr = NULL;
		pMsrPremissionsMapPhyAddr = NULL;
	}
}

#pragma code_seg("PAGE")
SVMStatus SVMManager::CheckSVM()
{
	PAGED_CODE();
	char szCpuString[13];
	CPUString(szCpuString);
	if (strcmp(szCpuString, "AuthenticAMD"))
		return SVMS_NONAMDCPU;

	SVMStatus result = SVMS_UNUSED;
	UINT32 cpuid_result[4] = {};

	do
	{
		//��ѯSMV֧��
		__cpuidex((int*)cpuid_result, CPUID_FN_SVM_FEATURE, 0);

		//CPUID Fn 8000_0001h ecx �� 2 λ (0 base ��ͬ) �Ƿ�Ϊ 1
		if (!(cpuid_result[2] & (1UL << CPUID_FN_80000001_ECX_SVM_OFFSET)))
			break;

		result = ((SVMStatus)(result | SVMS_SUPPORTED));

		//��ѯSVM����
		UINT64 msrValue = __readmsr(IA32_MSR_VM_CR);

		//VM_CR MSR �Ĵ��� �� 4 λ SVMDIS �Ƿ�Ϊ 0
		if (msrValue & 1ULL << VM_CR_SVMDIS_OFFSET)
			break;

		result = ((SVMStatus)(result | SVMS_ENABLED));
	} while (false);

	return result;
}

#pragma code_seg("PAGE")
NTSTATUS SVMManager::Init()
{
	PAGED_CODE();
	NTSTATUS result = STATUS_SUCCESS;
	UINT32 idx = 0;
	do
	{
		//����Ƿ�֧��AMD-V
		SVMStatus svmStatus = CheckSVM();

		result = STATUS_INSUFFICIENT_RESOURCES;

		if (svmStatus & SVMStatus::SVMS_NONAMDCPU)
		{
			KdPrint(("SVMManager::Init(): Not AMD Processor!\n"));
			break;
		}

		if (!(svmStatus & SVMStatus::SVMS_SUPPORTED))
		{
			KdPrint(("SVMManager::Init(): SVM feature is not supported!\n"));
			break;
		}

		if (!(svmStatus & SVMStatus::SVMS_ENABLED))
		{
			KdPrint(("SVMManager::Init(): SVM feature is not enabled!\n"));
			break;
		}

		msrPremissionMap.SetPlugin(pMsrInterceptPlugin);

		//Ϊÿһ��CPU����������⻯�ر�����Դ
		//�����ȳ�ʼ��ÿ��CPU����Դָ��
		cpuCnt = KeQueryActiveProcessorCountEx(ALL_PROCESSOR_GROUPS);
		pVirtCpuInfo = (VirtCpuInfo**)ExAllocatePool2(POOL_FLAG_NON_PAGED, cpuCnt * sizeof(VirtCpuInfo*), SVM_TAG);
		if (pVirtCpuInfo == NULL || !NT_SUCCESS(msrPremissionMap.Init()))
		{
			KdPrint(("SVMManager::Init(): Memory not enough!\n"));
			break;
		}

		result = STATUS_SUCCESS;
		//Ϊÿ��CPU����������⻯������ڴ�
		for (idx = 0; idx < cpuCnt; ++idx)
		{
			pVirtCpuInfo[idx] = (VirtCpuInfo*)MmAllocateContiguousMemory(sizeof(VirtCpuInfo), highestPhyAddr);
			if (pVirtCpuInfo[idx] == NULL)
			{
				result = STATUS_INSUFFICIENT_RESOURCES;
				break;
			}
			RtlZeroMemory(pVirtCpuInfo[idx], sizeof(VirtCpuInfo));
			pVirtCpuInfo[idx]->otherInfo.pMsrInterceptPlugin = pMsrInterceptPlugin;
			pVirtCpuInfo[idx]->otherInfo.pCpuIdInterceptPlugin = pCpuIdInterceptPlugin;
		}

		if (!NT_SUCCESS(result))
		{
			KdPrint(("SVMManager::Init(): Memory not enough!\n"));
			break;
		}
		//�������⻯
		result = EnterVirtualization();

		if (!NT_SUCCESS(result))
		{
			KdPrint(("SVMManager::Init(): Can not enter virtualization!\n"));
			break;
		}

	} while (false);

	if (!NT_SUCCESS(result))
		Deinit();

	return result;
}

#pragma code_seg("PAGE")
void SVMManager::Deinit()
{
	PAGED_CODE();
	if (pVirtCpuInfo != NULL && cpuCnt)
	{
		UINT64 idx = 0;
		PROCESSOR_NUMBER processorNum = {};
		GROUP_AFFINITY affinity = {}, oldAffinity = {};

		for (idx = 0; idx < cpuCnt; ++idx)
		{
			if (pVirtCpuInfo[idx] != NULL)
			{
				//����Ѿ��������⻯�����պ����˳����⻯
				if (pVirtCpuInfo[idx]->otherInfo.isInVirtualizaion)
				{
					KeGetProcessorNumberFromIndex((ULONG)idx, &processorNum);

					affinity = {};
					affinity.Group = processorNum.Group;
					affinity.Mask = 1ULL << processorNum.Number;
					KeSetSystemGroupAffinityThread(&affinity, &oldAffinity);

					LeaveVirtualization();

					KeRevertToUserGroupAffinityThread(&oldAffinity);
				}
				MmFreeContiguousMemory(pVirtCpuInfo[idx]);
				pVirtCpuInfo[idx] = NULL;
			}
		}
		ExFreePoolWithTag(pVirtCpuInfo, SVM_TAG);
		pVirtCpuInfo = NULL;
		cpuCnt = 0;
	}
	msrPremissionMap.Deinit();
}

#pragma code_seg("PAGE")
NTSTATUS SVMManager::EnterVirtualization()
{
	PAGED_CODE();
	NTSTATUS status = STATUS_SUCCESS;
	PROCESSOR_NUMBER processorNum = {};
	GROUP_AFFINITY affinity = {}, oldAffinity = {};
	UINT32 idx = 0;
	for (idx = 0; idx < cpuCnt; ++idx)
	{
		status = KeGetProcessorNumberFromIndex(idx, &processorNum);
		if (!NT_SUCCESS(status))
			break;

		affinity = {};
		affinity.Group = processorNum.Group;
		affinity.Mask = 1ULL << processorNum.Number;
		KeSetSystemGroupAffinityThread(&affinity, &oldAffinity);

		GenericRegisters registerBackup = {};
		_save_or_load_regs(&registerBackup);

		if (!pVirtCpuInfo[idx]->otherInfo.isInVirtualizaion)
		{
			//��ǽ������⻯֮����Ҫ�ָ��ļĴ���
			registerBackup.rax = (UINT64)&registerBackup;
			//����Ѿ���������⻯
			pVirtCpuInfo[idx]->otherInfo.isInVirtualizaion = TRUE;

			UINT64 gdtrBase = 0, idtrBase = 0;
			UINT16 gdtrLimit = 0, idtrLimit = 0;
			UINT16 trSelector = 0, ldtrSelector = 0;
			_mysgdt(&gdtrBase, &gdtrLimit);
			_mysidt(&idtrBase, &idtrLimit);
			_mystr(&trSelector);
			_mysldt(&ldtrSelector);

			UINT64 eferBackup = __readmsr(IA32_MSR_EFER);
			__writemsr(IA32_MSR_SVM_MSR_VM_HSAVE_PA, MmGetPhysicalAddress(&pVirtCpuInfo[idx]->hostStatus).QuadPart);
			__writemsr(IA32_MSR_EFER, eferBackup | (1ULL << EFER_SVME_OFFSET));

			pVirtCpuInfo[idx]->guestVmcb.controlFields.interceptOpcodes1
				= Opcode1InterceptBits::CPUID;//Opcode1InterceptBits::RDMSR_WRMSR;
			//vmrun���ر���򿪣�����vmrun��ʧ��
			pVirtCpuInfo[idx]->guestVmcb.controlFields.interceptOpcodes2
				= Opcode2InterceptBits::VMRUN;
			pVirtCpuInfo[idx]->guestVmcb.controlFields.msrpmBasePA = msrPremissionMap.GetPhyAddress();
			pVirtCpuInfo[idx]->guestVmcb.controlFields.guestASID = 1;

			pVirtCpuInfo[idx]->guestVmcb.statusFields.gdtr.base = gdtrBase;
			pVirtCpuInfo[idx]->guestVmcb.statusFields.gdtr.limit = gdtrLimit;
			pVirtCpuInfo[idx]->guestVmcb.statusFields.idtr.base = idtrBase;
			pVirtCpuInfo[idx]->guestVmcb.statusFields.idtr.limit = idtrLimit;

			//X64 ����κ����ݶε�base��limit����Ч��
			//base ǿ��Ϊ 0��ǿ��ƽ̹�Σ�
			pVirtCpuInfo[idx]->guestVmcb.statusFields.cs.selector = _cs_selector();
			pVirtCpuInfo[idx]->guestVmcb.statusFields.cs.attrib = _GetSegmentAttribute(_cs_selector(), gdtrBase);

			pVirtCpuInfo[idx]->guestVmcb.statusFields.ds.selector = _ds_selector();
			pVirtCpuInfo[idx]->guestVmcb.statusFields.ds.attrib = _GetSegmentAttribute(_ds_selector(), gdtrBase);

			pVirtCpuInfo[idx]->guestVmcb.statusFields.es.selector = _es_selector();
			pVirtCpuInfo[idx]->guestVmcb.statusFields.es.attrib = _GetSegmentAttribute(_es_selector(), gdtrBase);

			pVirtCpuInfo[idx]->guestVmcb.statusFields.ss.selector = _ss_selector();
			pVirtCpuInfo[idx]->guestVmcb.statusFields.ss.attrib = _GetSegmentAttribute(_ss_selector(), gdtrBase);

			//�������һ����Ϣ����ʹ��vmsaveָ��ֱ�ӻ�ȡ
			//����Ϊ���о�ԭ���ֶ���ȡ
			//*************************************** BEGIN ***************************************

			pVirtCpuInfo[idx]->guestVmcb.statusFields.fs.selector = _fs_selector();
			pVirtCpuInfo[idx]->guestVmcb.statusFields.fs.attrib = _GetSegmentAttribute(_fs_selector(), gdtrBase);

			pVirtCpuInfo[idx]->guestVmcb.statusFields.gs.selector = _gs_selector();
			pVirtCpuInfo[idx]->guestVmcb.statusFields.gs.attrib = _GetSegmentAttribute(_gs_selector(), gdtrBase);

			//����TR LDTR base limit ��Ȼ��Ч
			pVirtCpuInfo[idx]->guestVmcb.statusFields.ldtr.selector = ldtrSelector;
			pVirtCpuInfo[idx]->guestVmcb.statusFields.ldtr.base = _GetSegmentBaseAddress(ldtrSelector, gdtrBase);
			pVirtCpuInfo[idx]->guestVmcb.statusFields.ldtr.limit = _GetSegmentLimit(ldtrSelector, gdtrBase);
			pVirtCpuInfo[idx]->guestVmcb.statusFields.ldtr.attrib = _GetSegmentAttribute(ldtrSelector, gdtrBase);

			pVirtCpuInfo[idx]->guestVmcb.statusFields.tr.selector = trSelector;
			pVirtCpuInfo[idx]->guestVmcb.statusFields.tr.base = _GetSegmentBaseAddress(trSelector, gdtrBase);
			pVirtCpuInfo[idx]->guestVmcb.statusFields.tr.limit = _GetSegmentLimit(trSelector, gdtrBase);
			pVirtCpuInfo[idx]->guestVmcb.statusFields.tr.attrib = _GetSegmentAttribute(trSelector, gdtrBase);

			//FSBase GSBase KenrelGSBase ���Բ�Ϊ0 �����Ƿ���MSR�Ĵ��������
			/*
			IA32_MSR_FS_BASE���±�0xC0000100��
			IA32_MSR_GS_BASE���±�0xC0000101��
			IA32_MSR_KERNEL_GS_BASE���±�0xC0000102��
			*/

			pVirtCpuInfo[idx]->guestVmcb.statusFields.fs.base = __readmsr(IA32_MSR_FS_BASE);
			pVirtCpuInfo[idx]->guestVmcb.statusFields.gs.base = __readmsr(IA32_MSR_GS_BASE);
			pVirtCpuInfo[idx]->guestVmcb.statusFields.kernelGsBase = __readmsr(IA32_MSR_KERNEL_GS_BASE);

			//����32λϵͳ����Ҫ��� SYSENTER_CS SYSENTER_ESP SYSENTER_EIP

			//pVirtCpuInfo[idx]->guestVmcb.statusFields.sysenterCs = __readmsr(IA32_MSR_SYSENTER_CS);
			//pVirtCpuInfo[idx]->guestVmcb.statusFields.sysenterEsp = __readmsr(IA32_MSR_SYSENTER_ESP);
			//pVirtCpuInfo[idx]->guestVmcb.statusFields.sysenterEip = __readmsr(IA32_MSR_SYSENTER_EIP);

			pVirtCpuInfo[idx]->guestVmcb.statusFields.star = __readmsr(IA32_MSR_STAR);
			pVirtCpuInfo[idx]->guestVmcb.statusFields.lstar = __readmsr(IA32_MSR_LSTAR);
			pVirtCpuInfo[idx]->guestVmcb.statusFields.cstar = __readmsr(IA32_MSR_CSTAR);
			pVirtCpuInfo[idx]->guestVmcb.statusFields.sfmask = __readmsr(IA32_MSR_SF_MASK);

			//*************************************** END ***************************************

			//��� VMCB EFER �� EFER ֵ��SVMEλ����Ϊ1������vmrun��ʧ��
			pVirtCpuInfo[idx]->guestVmcb.statusFields.efer = __readmsr(IA32_MSR_EFER);
			pVirtCpuInfo[idx]->guestVmcb.statusFields.cr0 = __readcr0();
			pVirtCpuInfo[idx]->guestVmcb.statusFields.cr2 = __readcr2();
			pVirtCpuInfo[idx]->guestVmcb.statusFields.cr3 = __readcr3();
			pVirtCpuInfo[idx]->guestVmcb.statusFields.cr4 = __readcr4();
			pVirtCpuInfo[idx]->guestVmcb.statusFields.rax = registerBackup.rax;
			pVirtCpuInfo[idx]->guestVmcb.statusFields.rflags = registerBackup.rflags;
			pVirtCpuInfo[idx]->guestVmcb.statusFields.rsp = registerBackup.rsp;
			pVirtCpuInfo[idx]->guestVmcb.statusFields.rip = registerBackup.rip;
			pVirtCpuInfo[idx]->guestVmcb.statusFields.gPat = __readmsr(IA32_MSR_PAT);

			pVirtCpuInfo[idx]->guestVmcb.statusFields.cpl = _cs_selector() & 0x3;

			pVirtCpuInfo[idx]->hostVmcb.statusFields = pVirtCpuInfo[idx]->guestVmcb.statusFields;

			//__svm_vmsave((size_t)MmGetPhysicalAddress(&pVirtCpuInfo[idx]->guestVmcb).QuadPart);
			//__svm_vmsave((size_t)MmGetPhysicalAddress(&pVirtCpuInfo[idx]->hostVmcb).QuadPart);

			_run_svm_vmrun
			(
				pVirtCpuInfo[idx],
				(PVOID)MmGetPhysicalAddress(&pVirtCpuInfo[idx]->guestVmcb).QuadPart,
				(PVOID)MmGetPhysicalAddress(&pVirtCpuInfo[idx]->hostVmcb).QuadPart,
				pVirtCpuInfo[idx]->stack + sizeof pVirtCpuInfo[idx]->stack
			);

			//��Ӧ�÷���
			//������ش���vmrunʧ��
			//ֱ�� BugCheck

			KeBugCheck(MANUALLY_INITIATED_CRASH);
		}

		KeRevertToUserGroupAffinityThread(&oldAffinity);

		if (!NT_SUCCESS(status))
			break;
	}

	return status;
}

#pragma code_seg("PAGE")
void SVMManager::LeaveVirtualization()
{
	PAGED_CODE();
	int result[4] = {};
	//����CPUIDָ��֪ͨVMM�˳�
	__cpuidex(result, GUEST_CALL_VMM_CPUID_FUNCTION, 0);
}