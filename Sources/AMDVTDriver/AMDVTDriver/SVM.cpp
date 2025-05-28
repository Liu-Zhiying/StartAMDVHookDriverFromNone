#include "SVM.h"
#include "VMCB.h"
#include <intrin.h>

//AMD SVM û��ר�ŵ�VMMCALLָ�ֻ��ʹ���Զ���CPUID
//AMD �ֲ��ϸ����⻯Ԥ����CPUID ID Ϊ 0x40000000~0x400000ff
constexpr UINT32 GUEST_CALL_VMM_CPUID_FUNCTION = 0x400000ff;
constexpr UINT32 EXIT_SVM_CPUID_SUBFUNCTION = 0x00000000;
constexpr UINT32 IS_IN_SVM_CPUID_SUBFUNCTION = 0x00000001;
constexpr UINT32 SVM_TAG = MAKE_TAG('s', 'v', 'm', ' ');

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
	//��һ���������Լ���ӣ����ಿ�ֺ�git��Ŀһ��
	//��һ�����Ƿ���ڿ�Type��Ա��X64ǿ��ƽ̹�Σ����ڴ���κ����ݶ���һ���ֲ�����
	//�����Ŷ�(gate segment)��ϵͳ��(system segment)������Щ��Ա�����Ҷ�����в�ͬ������ο�CPU�ֲ�
	//��������Ҫ��ȡϵͳ��(TSS LDT)�Ļ�ַ
	struct
	{
		UINT32 BaseHigh4Byte;
		UINT32 Reserved;
	} OptionalField;
} SEGMENT_DESCRIPTOR, * PSEGMENT_DESCRIPTOR;

//����ṹ�������ַ https://learn.microsoft.com/en-us/cpp/build/exception-handling-x64?view=msvc-170
//����� MASM .PUSHFRAME ָ�����Ϊ����
typedef struct _MACHINE_FRAME
{
	UINT64 Rip;
	UINT64 Cs;
	UINT64 EFlags;
	UINT64 OldRsp;
	UINT64 Ss;
} MACHINE_FRAME, * PMACHINE_FRAME;

//���������ȫ�ճ�https://github.com/tandasat/SimpleSvm
//ԭ����������SvGetSegmentAccessRight
//��ȡ�μĴ���Attribute
#pragma code_seg("PAGE")
SegmentAttribute GetSegmentAttribute(_In_ UINT16 SegmentSelector, _In_ ULONG_PTR GdtBase)
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

	return attribute;
}

//��ȡ�μĴ���Base
#pragma code_seg("PAGE")
UINT64 GetSegmentBaseAddress(_In_ UINT16 SegmentSelector, _In_ ULONG_PTR GdtBase)
{
	PAGED_CODE();
	PSEGMENT_DESCRIPTOR descriptor;
	UINT64 baseAddress = 0;

	descriptor = reinterpret_cast<PSEGMENT_DESCRIPTOR>(
		GdtBase + (SegmentSelector & ~0x7));

	baseAddress |= descriptor->Fields.BaseLow;
	baseAddress |= ((UINT64)descriptor->Fields.BaseMiddle) << 16;
	baseAddress |= ((UINT64)descriptor->Fields.BaseHigh) << 24;
	if (!descriptor->Fields.System)
		baseAddress |= ((UINT64)descriptor->OptionalField.BaseHigh4Byte) << 32;

	return baseAddress;
}

//��ȡ�μĴ���Limit
#pragma code_seg("PAGE")
UINT32 GetSegmentLimit2(_In_ UINT16 SegmentSelector, _In_ ULONG_PTR GdtBase)
{
	PAGED_CODE();
	PSEGMENT_DESCRIPTOR descriptor;
	UINT32 limit = 0;

	descriptor = reinterpret_cast<PSEGMENT_DESCRIPTOR>(
		GdtBase + (SegmentSelector & ~0x7));

	limit |= descriptor->Fields.LimitLow;
	limit |= ((UINT64)descriptor->Fields.LimitHigh) << 16;

	/*
		��ȡ���������е� limit �ֶΣ����������е� limit �ֶ��� 20 λ��ֵ����Ϊ�� 4 λ�͵� 16 λ��
		������ȣ�G��λ��
			��� G = 0��limit �ĵ�λ���ֽڣ���Χ�� 1B �� 1MB��
			��� G = 1��limit �ĵ�λ�� 4KB����Χ�� 4KB �� 4GB��
		���� limit��
			�� G = 0 ʱ��limit �ļ��㹫ʽΪ�� {Limit} = {Low 16 bits} + ({High 4 bits} << 16)
			�� G = 1 ʱ��limit �ļ��㹫ʽΪ�� {Limit} = (({Low 16 bits} + ({High 4 bits} << 16))) << 12) + 0xFFF
	*/

	if (descriptor->Fields.Granularity)
	{
		limit <<= 12;
		limit |= 0xfff;
	}

	return limit;
}

//���Ĵ���
#pragma code_seg()
extern "C" void CompareGenericRegisters(const GenericRegisters& genericRegistersNow, GenericRegisters& genericRegistersPrev)
{

#define ASSERT_REGISTER_IS_EQUAL(regField) \
	NT_ASSERT(!RtlCompareMemory(&genericRegistersNow.regField, &genericRegistersPrev.regField, sizeof(genericRegistersNow.regField)))

	if (!KdDebuggerNotPresent)
	{
		ASSERT_REGISTER_IS_EQUAL(xmm0);
		ASSERT_REGISTER_IS_EQUAL(xmm1);
		ASSERT_REGISTER_IS_EQUAL(xmm2);
		ASSERT_REGISTER_IS_EQUAL(xmm3);
		ASSERT_REGISTER_IS_EQUAL(xmm4);
		ASSERT_REGISTER_IS_EQUAL(xmm5);
		ASSERT_REGISTER_IS_EQUAL(xmm6);
		ASSERT_REGISTER_IS_EQUAL(xmm7);
		ASSERT_REGISTER_IS_EQUAL(xmm8);
		ASSERT_REGISTER_IS_EQUAL(xmm9);
		ASSERT_REGISTER_IS_EQUAL(xmm10);
		ASSERT_REGISTER_IS_EQUAL(xmm11);
		ASSERT_REGISTER_IS_EQUAL(xmm12);
		ASSERT_REGISTER_IS_EQUAL(xmm13);
		ASSERT_REGISTER_IS_EQUAL(xmm14);
		ASSERT_REGISTER_IS_EQUAL(xmm15);
		ASSERT_REGISTER_IS_EQUAL(r15);
		ASSERT_REGISTER_IS_EQUAL(r14);
		ASSERT_REGISTER_IS_EQUAL(r13);
		ASSERT_REGISTER_IS_EQUAL(r12);
		ASSERT_REGISTER_IS_EQUAL(r11);
		ASSERT_REGISTER_IS_EQUAL(r10);
		ASSERT_REGISTER_IS_EQUAL(r9);
		ASSERT_REGISTER_IS_EQUAL(r8);
		ASSERT_REGISTER_IS_EQUAL(rbp);
		ASSERT_REGISTER_IS_EQUAL(rsi);
		ASSERT_REGISTER_IS_EQUAL(rdi);
		ASSERT_REGISTER_IS_EQUAL(rdx);
		ASSERT_REGISTER_IS_EQUAL(rcx);
		ASSERT_REGISTER_IS_EQUAL(rbx);
	}

#undef ASSERT_REGISTER_IS_EQUAL
}

//��ʼ��KTRAP_FRAME�ṹ��
#pragma code_seg()
extern "C" void FillMachineFrame(MACHINE_FRAME& machineFrame, const GenericRegisters& guestRegistars, const VirtCpuInfo& virtCpuInfo)
{
	UNREFERENCED_PARAMETER(guestRegistars);
	machineFrame = {};

	machineFrame.Rip = virtCpuInfo.guestVmcb.controlFields.nRip;
	machineFrame.Cs = virtCpuInfo.guestVmcb.statusFields.cs.selector;
	machineFrame.Ss = virtCpuInfo.guestVmcb.statusFields.ss.selector;
	machineFrame.OldRsp = virtCpuInfo.guestVmcb.statusFields.rsp;
	machineFrame.EFlags = (UINT32)virtCpuInfo.guestVmcb.statusFields.rflags;
}

//#VMEXIT������
#pragma code_seg()
extern "C" void VmExitHandler(VirtCpuInfo* pVirtCpuInfo, GenericRegisters* pGuestRegisters, PVOID pGuestVmcbPhyAddr, PVOID pHostVmcbPhyAddr)
{
	pGuestRegisters->rip = pVirtCpuInfo->guestVmcb.statusFields.rip;
	pGuestRegisters->rsp = pVirtCpuInfo->guestVmcb.statusFields.rsp;
	pGuestRegisters->rax = pVirtCpuInfo->guestVmcb.statusFields.rax;
	pGuestRegisters->rflags = pVirtCpuInfo->guestVmcb.statusFields.rflags;

	IMsrBackupRestorePlugin* pMsrHookPlugin = pVirtCpuInfo->otherInfo.pSvmManager->pMsrBackupRestorePlugin;

	//��� MSR ���ز�����ڣ�����VM֮�󱣴�Guest�ͻָ�Host��MSR
	if (pMsrHookPlugin != NULL)
	{
		pMsrHookPlugin->SaveGuestMsrForCpu(pVirtCpuInfo->otherInfo.cpuIdx);
		pMsrHookPlugin->LoadHostMsrForCpu(pVirtCpuInfo->otherInfo.cpuIdx);
	}

	//ת����SVMManager::VmExitHandler����
	pVirtCpuInfo->otherInfo.pSvmManager->VmExitHandler(pVirtCpuInfo, pGuestRegisters, pGuestVmcbPhyAddr, pHostVmcbPhyAddr);

	//��� MSR ���ز�����ڣ��˳�VM֮ǰ�ָ�Guest�ͱ���Host��MSR
	if (pMsrHookPlugin != NULL)
	{
		pMsrHookPlugin->SaveHostMsrForCpu(pVirtCpuInfo->otherInfo.cpuIdx);
		pMsrHookPlugin->LoadGuestMsrForCpu(pVirtCpuInfo->otherInfo.cpuIdx);
	}

	pVirtCpuInfo->guestVmcb.statusFields.rip = pGuestRegisters->rip;
	pVirtCpuInfo->guestVmcb.statusFields.rsp = pGuestRegisters->rsp;
	pVirtCpuInfo->guestVmcb.statusFields.rax = pGuestRegisters->rax;
	pVirtCpuInfo->guestVmcb.statusFields.rflags = pGuestRegisters->rflags;
}

//��ȡCPU�����̵��ַ���
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

	constexpr UINT32 BITS_PER_MSR = 2;
	//FIRST_MSR_RANGE_BASE = 0x00000000;
	//FIRST_MSRPM_OFFSET = 0x000 * CHAR_BIT;
	constexpr UINT32 SECOND_MSR_RANGE_BASE = 0xc0000000;
	constexpr UINT32 SECOND_MSRPM_OFFSET = 0x800 * CHAR_BIT;
	constexpr UINT32 THIRD_MSR_RANGE_BASE = 0xc0010000;
	constexpr UINT32 THIRD_MSRPM_OFFSET = 0x1000 * CHAR_BIT;
	constexpr ULONG EFER_OFFSET = SECOND_MSRPM_OFFSET + ((IA32_MSR_EFER - SECOND_MSR_RANGE_BASE) * BITS_PER_MSR);
	constexpr ULONG VM_CR_OFFSET = THIRD_MSRPM_OFFSET + ((IA32_MSR_VM_CR - THIRD_MSR_RANGE_BASE) * BITS_PER_MSR);
	RTL_BITMAP bitmapHeader = {};

	//�������������ڴ�
	pMsrPremissionsMapVirtAddr = AllocContiguousMem(2ULL * PAGE_SIZE, SVM_TAG);
	if (pMsrPremissionsMapVirtAddr == NULL)
	{
		KdPrint(("MsrPremissionsMapManager::Init(): Memory not enough!\n"));
		return STATUS_INSUFFICIENT_RESOURCES;
	}

	//��ʼ���ڴ��ֵ
	RtlInitializeBitMap(&bitmapHeader, (PULONG)pMsrPremissionsMapVirtAddr, 2 * PAGE_SIZE * CHAR_BIT);
	RtlClearAllBits(&bitmapHeader);

	//EFER��ȡд������
	RtlSetBits(&bitmapHeader, EFER_OFFSET, 2);
	//VM_CR��ȡд������
	RtlSetBits(&bitmapHeader, VM_CR_OFFSET, 2);

	//���MSR���ز�����ڣ��ò���������ر�־λ
	if (pMsrInterceptPlugin != NULL)
		pMsrInterceptPlugin->SetMsrPremissionMap(bitmapHeader);

	//��ȡ�����ַ
	pMsrPremissionsMapPhyAddr = (PVOID)MmGetPhysicalAddress(pMsrPremissionsMapVirtAddr).QuadPart;
	return STATUS_SUCCESS;
}

#pragma code_seg("PAGE")
void MsrPremissionsMapManager::Deinit()
{
	PAGED_CODE();
	if (pMsrPremissionsMapVirtAddr != NULL)
	{
		FreeContigousMem(pMsrPremissionsMapVirtAddr, SVM_TAG);
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
	//����Ƿ���AMD CPU
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

		//��ѯNPT����

		__cpuidex((int*)cpuid_result, CPUID_FN_NPT_FEATURE, 0);

		//CPUID Fn 8000_000Ah edx �� 0 λ �Ƿ�Ϊ 1
		if (!(cpuid_result[3] & (1UL << NPT_ENABLE_OFFSET)))
			break;

		result = ((SVMStatus)(result | SVMS_NPT_ENABLED));

	} while (false);

	return result;
}

#pragma code_seg("PAGE")
NTSTATUS SVMManager::Init()
{
	PAGED_CODE();
	NTSTATUS status = STATUS_SUCCESS;
	UINT32 idx = 0;

	do
	{
		//����Ƿ�֧��AMD-V
		SVMStatus svmStatus = CheckSVM();

		status = STATUS_INSUFFICIENT_RESOURCES;

		//���⻯Ӳ�����
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

		//����ṩ��NPTҳ�����SVM��֧��NPT����ô��ʾ��֧��NPT
		if (!(svmStatus & SVMStatus::SVMS_NPT_ENABLED) && pNCr3Provider != NULL)
		{
			KdPrint(("SVMManager::Init(): NPT feature is not enabled!\n"));
			break;
		}

		msrPremissionMap.SetPlugin(pMsrInterceptPlugin);

		//Ϊÿһ��CPU����������⻯�ر�����Դ
		//�����ȳ�ʼ��ÿ��CPU����Դָ��
		cpuCnt = KeQueryActiveProcessorCountEx(ALL_PROCESSOR_GROUPS);
		pVirtCpuInfo = (VirtCpuInfo**)AllocNonPagedMem(cpuCnt * sizeof(VirtCpuInfo*), SVM_TAG);

		if (pVirtCpuInfo == NULL)
		{
			KdPrint(("SVMManager::Init(): Cpu virtualization memory failed!\n"));
			break;
		}

		status = msrPremissionMap.Init();
		if (!NT_SUCCESS(status))
		{
			KdPrint(("SVMManager::Init(): MSR premission map init failed!\n"));
			break;
		}

		status = STATUS_SUCCESS;

		//Ϊÿ��CPU����������⻯������ڴ�
		for (idx = 0; idx < cpuCnt; ++idx)
		{
			pVirtCpuInfo[idx] = (VirtCpuInfo*)AllocNonPagedMem(sizeof(VirtCpuInfo), SVM_TAG);
			if (pVirtCpuInfo[idx] == NULL)
			{
				status = STATUS_INSUFFICIENT_RESOURCES;
				break;
			}
			RtlZeroMemory(pVirtCpuInfo[idx], sizeof(VirtCpuInfo));
			pVirtCpuInfo[idx]->otherInfo.pSvmManager = this;
			pVirtCpuInfo[idx]->otherInfo.cpuIdx = idx;
		}

		if (!NT_SUCCESS(status))
		{
			KdPrint(("SVMManager::Init(): CPU Virtualization resource init failed!\n"));
			break;
		}

		//�������⻯
		status = EnterVirtualization();

		if (!NT_SUCCESS(status))
		{
			KdPrint(("SVMManager::Init(): Can not enter virtualization!\n"));
			break;
		}

	} while (false);

	if (!NT_SUCCESS(status))
		Deinit();

	return status;
}

#pragma code_seg("PAGE")
void SVMManager::Deinit()
{
	PAGED_CODE();
	if (pVirtCpuInfo != NULL && cpuCnt)
	{
		LeaveVirtualization();

		for (SIZE_TYPE idx = 0; idx < cpuCnt; ++idx)
		{
			FreeNonPagedMem(pVirtCpuInfo[idx], SVM_TAG);
			pVirtCpuInfo[idx] = NULL;
		}
		FreeNonPagedMem(pVirtCpuInfo, SVM_TAG);
		pVirtCpuInfo = NULL;
		cpuCnt = 0;
	}
	msrPremissionMap.Deinit();
}

#pragma code_seg("PAGE")
NTSTATUS SVMManager::EnterVirtualization()
{
	PAGED_CODE();

	auto enterVirtualizationCore = [this](UINT32 cpuIdx) -> NTSTATUS
		{
			GenericRegisters registerBackup = {};

			_save_or_load_regs(&registerBackup);

			if (!pVirtCpuInfo[cpuIdx]->otherInfo.isInVirtualizaion)
			{
				//����Ѿ���������⻯
				pVirtCpuInfo[cpuIdx]->otherInfo.isInVirtualizaion = TRUE;

				UINT64 eferBackup = __readmsr(IA32_MSR_EFER);
				__writemsr(IA32_MSR_SVM_MSR_VM_HSAVE_PA, MmGetPhysicalAddress(&pVirtCpuInfo[cpuIdx]->hostStatus).QuadPart);
				__writemsr(IA32_MSR_EFER, eferBackup | (1ULL << EFER_SVME_OFFSET));

				pVirtCpuInfo[cpuIdx]->guestVmcb.controlFields.interceptOpcodes1
					= Opcode1InterceptBits::CPUID | Opcode1InterceptBits::RDMSR_WRMSR;
				//vmrun���ر���򿪣�����vmrun��ʧ��
				pVirtCpuInfo[cpuIdx]->guestVmcb.controlFields.interceptOpcodes2
					= Opcode2InterceptBits::VMRUN;

				//����ϵ����ز�����ڣ��򿪶ϵ�����
				if (pBreakpointInterceptPlugin != NULL)
					pVirtCpuInfo[cpuIdx]->guestVmcb.controlFields.interceptExceptionX = (1UL << BP_EXCEPTION_VECTOR_INDEX);

				//���UD���ز�����ڣ���UD����
				if (pInvalidOpcodeInterceptPlugin != NULL)
					pVirtCpuInfo[cpuIdx]->guestVmcb.controlFields.interceptExceptionX |= (1UL << UD_EXCEPTION_VECTOR_INDEX);

				//���DE���ز�����ڣ���DE����
				if (pSingleStepInterceptPlugin != NULL)
					pVirtCpuInfo[cpuIdx]->guestVmcb.controlFields.interceptExceptionX |= (1LL << DB_EXCEPTION_VECTOR_INDEX);

				pVirtCpuInfo[cpuIdx]->guestVmcb.controlFields.msrpmBasePA = msrPremissionMap.GetPhyAddress();
				pVirtCpuInfo[cpuIdx]->guestVmcb.controlFields.guestASID = 1;

				if (pNCr3Provider != NULL)
				{
					PVOID nCr3Pa = pNCr3Provider->GetNCr3ForCore(cpuIdx);
					if (nCr3Pa != (PVOID)INVALID_ADDR)
					{
						KdPrint(("SVMManager::EnterVirtualization(): Enable NPT\n"));
						pVirtCpuInfo[cpuIdx]->guestVmcb.controlFields.extendFeatures1.fields.enableNestedPage = true;
						pVirtCpuInfo[cpuIdx]->guestVmcb.controlFields.nCr3 = (UINT64)nCr3Pa;
					}
				}

				SAVE_GUEST_STATUS_FROM_REGS(pVirtCpuInfo[cpuIdx], &registerBackup, registerBackup.rflags, registerBackup.rsp, registerBackup.rip);

				pVirtCpuInfo[cpuIdx]->hostVmcb.statusFields = pVirtCpuInfo[cpuIdx]->guestVmcb.statusFields;

				//��Ҫʱ����syscall��sysret
				if (!enableSce)
					pVirtCpuInfo[cpuIdx]->guestVmcb.statusFields.efer &= ~(1 << SCE_ENABLE_OFFSET);
				else
					pVirtCpuInfo[cpuIdx]->guestVmcb.statusFields.efer |= (UINT64)(1 << SCE_ENABLE_OFFSET);

				//__svm_vmsave((size_t)MmGetPhysicalAddress(&pVirtCpuInfo[cpuIdx]->guestVmcb).QuadPart);
				//__svm_vmsave((size_t)MmGetPhysicalAddress(&pVirtCpuInfo[cpuIdx]->hostVmcb).QuadPart);

				//���MSR HOOK������ڣ�����VM֮ǰ����Guest��Host��MSR
				if (pMsrBackupRestorePlugin != NULL)
				{
					pMsrBackupRestorePlugin->SaveGuestMsrForCpu(cpuIdx);
					pMsrBackupRestorePlugin->SaveHostMsrForCpu(cpuIdx);
				}

				_run_svm_vmrun
				(
					pVirtCpuInfo[cpuIdx],
					(PVOID)MmGetPhysicalAddress(&pVirtCpuInfo[cpuIdx]->guestVmcb).QuadPart,
					(PVOID)MmGetPhysicalAddress(&pVirtCpuInfo[cpuIdx]->hostVmcb).QuadPart,
					pVirtCpuInfo[cpuIdx]->stack1 + sizeof pVirtCpuInfo[cpuIdx]->stack1
				);

				//��Ӧ�÷���
				//������ش���vmrunʧ��
				//ֱ�� BugCheck
				__debugbreak();
				KeBugCheck(MANUALLY_INITIATED_CRASH);
			}

			return STATUS_SUCCESS;
		};

	return RunOnEachCore(0, cpuCnt, enterVirtualizationCore);
}

#pragma code_seg("PAGE")
void SVMManager::LeaveVirtualization()
{
	PAGED_CODE();

	//����CPUIDָ��֪ͨVMM�˳�
	auto coreAction = [this](UINT32 idx) -> NTSTATUS
	{
		int result[4] = {};
		if (pVirtCpuInfo[idx] != NULL)
		{
			//����Ѿ��������⻯�����պ����˳����⻯
			if (pVirtCpuInfo[idx]->otherInfo.isInVirtualizaion)
			{
				__cpuidex(result, GUEST_CALL_VMM_CPUID_FUNCTION, 0);
				pVirtCpuInfo[idx]->otherInfo.isInVirtualizaion = FALSE;
			}
		}
		return STATUS_SUCCESS;
	};

	RunOnEachCore(0, cpuCnt, coreAction);
}

#pragma code_seg()
void SVMManager::VmExitHandler(VirtCpuInfo* pVMMVirtCpuInfo, GenericRegisters* pGuestRegisters, PVOID pGuestVmcbPhyAddr, PVOID pHostVmcbPhyAddr)
{
	UNREFERENCED_PARAMETER(pHostVmcbPhyAddr);
	UNREFERENCED_PARAMETER(pGuestVmcbPhyAddr);

	//����ռĴ������������ִ�к��˳������
	pGuestRegisters->extraInfo1 = 0;
	pGuestRegisters->extraInfo2 = 0;

	switch ((VmExitReasons)pVMMVirtCpuInfo->guestVmcb.controlFields.exitCode)
	{
	case VMEXIT_REASON_CPUID:
	{
		if (pCpuIdInterceptPlugin != NULL &&
			pCpuIdInterceptPlugin->HandleCpuid(pVMMVirtCpuInfo, pGuestRegisters,
				pGuestVmcbPhyAddr, pHostVmcbPhyAddr))
			break;

		if (((int)pGuestRegisters->rax) == GUEST_CALL_VMM_CPUID_FUNCTION)
		{
			switch (pGuestRegisters->rcx)
			{
			case EXIT_SVM_CPUID_SUBFUNCTION:
			{
				//������Ǵ��ں�ģʽ�����˳������
				if (!IsKernelAddress((PVOID)pVMMVirtCpuInfo->guestVmcb.controlFields.nRip))
					break;

				//ͨ��
				//����pGuestRegisters->extraInfo1Ϊ&pVMMVirtCpuInfo->regsBackup.genericRegisters1 �� 
				//����pGuestRegisters->extraInfo2ΪpVMMVirtCpuInfo->guestVmcb.controlFields.nRip
				//��֪_run_svm_vmrun�˳�vmm
				pGuestRegisters->extraInfo1 = (UINT64)&pVMMVirtCpuInfo->regsBackup.genericRegisters1;
				pGuestRegisters->extraInfo2 = (UINT64)pVMMVirtCpuInfo->guestVmcb.controlFields.nRip;

				//��gif�򿪵���û���˳�VMM��һ��ʱ������ж�
				_disable();
				//���˳�VMMʱ��GIF�������˳���ϵͳ����ղ����жϼ������ڽ���Hostģʽ��ʱ��GIF�ǹر�״̬
				__svm_stgi();
				//����guest״̬
				__svm_vmload((SIZE_TYPE)pGuestVmcbPhyAddr);

				//�˳����⻯������ִ��guest
				UINT64 eferVal = __readmsr(IA32_MSR_EFER);
				__writemsr(IA32_MSR_EFER, eferVal & ~(1ULL << EFER_SVME_OFFSET));

				break;
			}
			case IS_IN_SVM_CPUID_SUBFUNCTION:
			{
				*reinterpret_cast<UINT32*>(&pGuestRegisters->rax) = 'IN';
				*reinterpret_cast<UINT32*>(&pGuestRegisters->rbx) = 'AMD';
				*reinterpret_cast<UINT32*>(&pGuestRegisters->rcx) = 'SVM';
				break;
			}
			}
		}
		else
		{
			int cpuidResult[4] = {};

			__cpuidex(cpuidResult, (int)pGuestRegisters->rax, (int)pGuestRegisters->rcx);

			if (((int)pGuestRegisters->rax) == CPUID_FN_SVM_FEATURE)
				cpuidResult[2] &= ~(1UL << CPUID_FN_80000001_ECX_SVM_OFFSET);

			*reinterpret_cast<UINT32*>(&pGuestRegisters->rax) = cpuidResult[0];
			*reinterpret_cast<UINT32*>(&pGuestRegisters->rbx) = cpuidResult[1];
			*reinterpret_cast<UINT32*>(&pGuestRegisters->rcx) = cpuidResult[2];
			*reinterpret_cast<UINT32*>(&pGuestRegisters->rdx) = cpuidResult[3];
		}

		//guest����һ��ָ��ִ��
		pGuestRegisters->rip = pVMMVirtCpuInfo->guestVmcb.controlFields.nRip;

		break;
	}
	case VMEXIT_REASON_MSR:
	{
		ULARGE_INTEGER value = {};
		UINT32 msrNum = (UINT32)pGuestRegisters->rcx;
		bool isWriteAccess = pVMMVirtCpuInfo->guestVmcb.controlFields.exitInfo1;

		if (isWriteAccess)
		{
			value.LowPart = (UINT32)pGuestRegisters->rax;
			value.HighPart = (UINT32)pGuestRegisters->rdx;

			if (pMsrInterceptPlugin != NULL &&
				pMsrInterceptPlugin->HandleMsrInterceptWrite(pVMMVirtCpuInfo, pGuestRegisters,
					pGuestVmcbPhyAddr, pHostVmcbPhyAddr,
					msrNum))
				break;

			//������ͻ������� EFER MSR �� SVME λ �� VM_CR MSR �� SVMDIS λ
			if (msrNum == IA32_MSR_EFER && !(value.LowPart & (1UL << EFER_SVME_OFFSET)) ||
				msrNum == IA32_MSR_VM_CR && !(value.LowPart & (1ULL << VM_CR_SVMDIS_OFFSET)))
			{
				__debugbreak();
				KeBugCheck(MANUALLY_INITIATED_CRASH);
			}

			__writemsr(msrNum, value.QuadPart);
		}
		else
		{
			if (pMsrInterceptPlugin != NULL &&
				pMsrInterceptPlugin->HandleMsrImterceptRead(pVMMVirtCpuInfo, pGuestRegisters,
					pGuestVmcbPhyAddr, pHostVmcbPhyAddr,
					msrNum))
				break;

			value.QuadPart = __readmsr(msrNum);

			if (msrNum == IA32_MSR_VM_CR)
				value.QuadPart |= (1ULL << VM_CR_SVMDIS_OFFSET);
			if (msrNum == IA32_MSR_EFER)
				value.QuadPart &= ~(1UL << EFER_SVME_OFFSET);

			*reinterpret_cast<UINT32*>(&pGuestRegisters->rax) = value.LowPart;
			*reinterpret_cast<UINT32*>(&pGuestRegisters->rdx) = value.HighPart;
		}

		//guest����һ��ָ��ִ��
		pGuestRegisters->rip = pVMMVirtCpuInfo->guestVmcb.controlFields.nRip;

		break;
	}
	case VMEXIT_REASON_EXCEPTION_BP:
	{
		if (pBreakpointInterceptPlugin != NULL &&
			pBreakpointInterceptPlugin->HandleBreakpoint(pVMMVirtCpuInfo, pGuestRegisters, pGuestVmcbPhyAddr, pHostVmcbPhyAddr))
			break;

		//Ĭ��ֱ��ע��ϵ��쳣��guest����
		pVMMVirtCpuInfo->guestVmcb.controlFields.eventInj.data = 0;
		pVMMVirtCpuInfo->guestVmcb.controlFields.eventInj.fields.vector = BP_EXCEPTION_VECTOR_INDEX;
		pVMMVirtCpuInfo->guestVmcb.controlFields.eventInj.fields.type = 3;
		pVMMVirtCpuInfo->guestVmcb.controlFields.eventInj.fields.vaild = 1;
		pGuestRegisters->rip = pVMMVirtCpuInfo->guestVmcb.controlFields.nRip;
		break;
	}
	case VMEXIT_REASON_EXCEPTION_UD:
	{
		if (pInvalidOpcodeInterceptPlugin != NULL &&
			pInvalidOpcodeInterceptPlugin->HandleInvalidOpcode(pVMMVirtCpuInfo, pGuestRegisters, pGuestVmcbPhyAddr, pHostVmcbPhyAddr))
			break;

		//ע��UD�쳣��guest����
		pVMMVirtCpuInfo->guestVmcb.controlFields.eventInj.data = 0;
		pVMMVirtCpuInfo->guestVmcb.controlFields.eventInj.fields.vector = UD_EXCEPTION_VECTOR_INDEX;
		pVMMVirtCpuInfo->guestVmcb.controlFields.eventInj.fields.type = 3;
		pVMMVirtCpuInfo->guestVmcb.controlFields.eventInj.fields.vaild = 1;
		break;
	}
	case VMEXIT_REASON_EXCEPTION_DB:
	{
		if (pSingleStepInterceptPlugin != NULL &&
			pSingleStepInterceptPlugin->HandleSignleStep(pVMMVirtCpuInfo, pGuestRegisters, pGuestVmcbPhyAddr, pHostVmcbPhyAddr))
			break;

		//ע��DB�쳣��guest����
		pVMMVirtCpuInfo->guestVmcb.controlFields.eventInj.data = 0;
		pVMMVirtCpuInfo->guestVmcb.controlFields.eventInj.fields.vector = DB_EXCEPTION_VECTOR_INDEX;
		pVMMVirtCpuInfo->guestVmcb.controlFields.eventInj.fields.type = 3;
		pVMMVirtCpuInfo->guestVmcb.controlFields.eventInj.fields.vaild = 1;
		break;
	}
	case VMEXIT_REASON_VMRUN:
	{
		//ע��ϵ��쳣��guest����
		pVMMVirtCpuInfo->guestVmcb.controlFields.eventInj.data = 0;
		pVMMVirtCpuInfo->guestVmcb.controlFields.eventInj.fields.vector = BP_EXCEPTION_VECTOR_INDEX;
		pVMMVirtCpuInfo->guestVmcb.controlFields.eventInj.fields.type = 3;
		pVMMVirtCpuInfo->guestVmcb.controlFields.eventInj.fields.vaild = 1;
		pGuestRegisters->rip = pVMMVirtCpuInfo->guestVmcb.controlFields.nRip;
		break;
	}
	case VMEXIT_REASON_NPF:
	{
		if (pNpfInterceptPlugin != NULL &&
			pNpfInterceptPlugin->HandleNpf(pVMMVirtCpuInfo, pGuestRegisters, pGuestVmcbPhyAddr, pHostVmcbPhyAddr))
			break;

		__debugbreak();
		KeBugCheck(MANUALLY_INITIATED_CRASH);
		break;
	}
	default:
	{
		__debugbreak();
		KeBugCheck(MANUALLY_INITIATED_CRASH);
		break;
	}
	}

	//EFLAGS TF ��־λΪ 1 �򸽼�DE�ж�

	//ԭ���������ַ
	//https://howtohypervise.blogspot.com/2019/01/a-common-missight-in-most-hypervisors.html

	//��Ҳ���Կ�й¶��VMPԴ�룬�����ʹ�������ַ���������⻯

	//Ӳ���ϵ���������Ӷϵ�Ĵ����Ҳ�û��д����Ҫ�Ļ��Լ���

	if (pGuestRegisters->rflags & (1ULL << EFLAGS_TF_OFFSET))
	{
		pVMMVirtCpuInfo->guestVmcb.controlFields.eventInj.data = 0;
		pVMMVirtCpuInfo->guestVmcb.controlFields.eventInj.fields.vector = DB_EXCEPTION_VECTOR_INDEX;
		pVMMVirtCpuInfo->guestVmcb.controlFields.eventInj.fields.type = 3;
		pVMMVirtCpuInfo->guestVmcb.controlFields.eventInj.fields.vaild = 1;
	}
}
