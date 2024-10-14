#include "SVM.h"
#include "VMCB.h"
#include <intrin.h>

//AMD SVM 没有专门的VMMCALL指令，只能使用自定义CPUID
//AMD 手册上给虚拟化预留的CPUID ID 为 0x40000000~0x400000ff
constexpr UINT32 GUEST_CALL_VMM_CPUID_FUNCTION = 0x400000ff;
constexpr UINT32 SVM_TAG = MAKE_TAG('s', 'v', 'm', ' ');

//GDT表项，参考https://wiki.osdev.org/Global_Descriptor_Table#System_Segment_Descriptor
//照抄https://github.com/tandasat/SimpleSvm
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
	//这一部分是我自己添加，其余部分和git项目一样
	//这一部分是否存在看Type成员，X64强制平坦段，对于代码段和数据段这一部分不存在
	//对于门段(gate segment)和系统段(system segment)才有这些成员，而且定义各有不同，具体参考CPU手册
	//这里我需要获取系统段(TSS LDT)的基址
	struct
	{
		UINT32 BaseHigh4Byte;
		UINT32 Reserved;
	} OptionalField;
} SEGMENT_DESCRIPTOR, * PSEGMENT_DESCRIPTOR;

//一系列汇编函数
//源代码在SVM_asm.asm里面
//主要都是寄存器读取操作
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
//用于备份和还原寄存器上下文
extern "C" void _save_or_load_regs(GenericRegisters* pRegisters);
//执行vmrun相关操作
extern "C" void _run_svm_vmrun(VirtCpuInfo* pInfo, PVOID pGuestVmcbPhyAddr, PVOID pHostVmcbPhyAddr, PVOID pStack);

//这个函数完全照抄https://github.com/tandasat/SimpleSvm
//原函数名字是SvGetSegmentAccessRight
//获取段寄存器Attribute
#pragma code_seg("PAGE")
SegmentAttribute GetSegmentAttribute(_In_ UINT16 SegmentSelector, _In_ ULONG_PTR GdtBase)
{
	PAGED_CODE();
	PSEGMENT_DESCRIPTOR descriptor = NULL;
	SEGMENT_ATTRIBUTE attribute = {};

	//关于段选择子的结构参考https://wiki.osdev.org/Segment_Selector
	//低3bit是标志，这里不管基址是LDT的情况，这个函数设计就是假设基址是GDT
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

//获取段寄存器Base
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
	baseAddress |= ((UINT64)descriptor->OptionalField.BaseHigh4Byte) << 32;

	return baseAddress;
}

//获取段寄存器Limit
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

	return limit;
}

//#VMEXIT处理函数
#pragma code_seg()
extern "C" void VmExitHandler(VirtCpuInfo* pVirtCpuInfo, GenericRegisters* pGuestRegisters, PVOID pGuestVmcbPhyAddr, PVOID pHostVmcbPhyAddr)
{
	//转发到SVMManager::VmExitHandler函数
	return pVirtCpuInfo->otherInfo.pSvmManager->VmExitHandler(pVirtCpuInfo, pGuestRegisters, pGuestVmcbPhyAddr, pHostVmcbPhyAddr);
}

//获取CPU生产商的字符串
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

//分配MSR拦截标志位map
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

	//分配物理连续内存
	pMsrPremissionsMapVirtAddr = AllocContiguousMem(2ULL * PAGE_SIZE, SVM_TAG);
	if (pMsrPremissionsMapVirtAddr == NULL)
	{
		KdPrint(("MsrPremissionsMapManager::Init(): Memory not enough!\n"));
		return STATUS_INSUFFICIENT_RESOURCES;
	}

	//初始化内存的值
	RtlInitializeBitMap(&bitmapHeader, (PULONG)pMsrPremissionsMapVirtAddr, 2 * PAGE_SIZE * CHAR_BIT);
	RtlClearAllBits(&bitmapHeader);

	//EFER读取写入拦截
	RtlSetBits(&bitmapHeader, EFER_OFFSET, 2);
	//VM_CR读取写入拦截
	RtlSetBits(&bitmapHeader, VM_CR_OFFSET, 2);

	//如果MSR拦截插件存在，让插件设置拦截标志位
	if (pMsrInterceptPlugin != NULL)
		pMsrInterceptPlugin->SetMsrPremissionMap(bitmapHeader);

	//获取物理地址
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
	//检查是否是AMD CPU
	if (strcmp(szCpuString, "AuthenticAMD"))
		return SVMS_NONAMDCPU;

	SVMStatus result = SVMS_UNUSED;
	UINT32 cpuid_result[4] = {};

	do
	{
		//查询SMV支持
		__cpuidex((int*)cpuid_result, CPUID_FN_SVM_FEATURE, 0);

		//CPUID Fn 8000_0001h ecx 第 2 位 (0 base 下同) 是否为 1
		if (!(cpuid_result[2] & (1UL << CPUID_FN_80000001_ECX_SVM_OFFSET)))
			break;

		result = ((SVMStatus)(result | SVMS_SUPPORTED));

		//查询SVM启用
		UINT64 msrValue = __readmsr(IA32_MSR_VM_CR);

		//VM_CR MSR 寄存器 第 4 位 SVMDIS 是否为 0
		if (msrValue & 1ULL << VM_CR_SVMDIS_OFFSET)
			break;

		result = ((SVMStatus)(result | SVMS_ENABLED));

		//查询NPT启用

		__cpuidex((int*)cpuid_result, CPUID_FN_NPT_FEATURE, 0);

		//CPUID Fn 8000_000Ah edx 第 0 位 (0 base 下同) 是否为 1
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
		//检查是否支持AMD-V
		SVMStatus svmStatus = CheckSVM();

		status = STATUS_INSUFFICIENT_RESOURCES;

		//虚拟化硬件检查
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

		//如果提供了NPT页表而且SVM不支持NPT，那么提示不支持NPT
		if (!(svmStatus & SVMStatus::SVMS_NPT_ENABLED) && pNCr3Provider != NULL)
		{
			KdPrint(("SVMManager::Init(): NPT feature is not enabled!\n"));
			break;
		}

		msrPremissionMap.SetPlugin(pMsrInterceptPlugin);

		//为每一个CPU分配进入虚拟化必备的资源
		//这里先初始化每个CPU的资源指针
		cpuCnt = KeQueryActiveProcessorCountEx(ALL_PROCESSOR_GROUPS);
		pVirtCpuInfo = (VirtCpuInfo**)AllocNonPagedMem(cpuCnt * sizeof(VirtCpuInfo*), SVM_TAG);

		if (pVirtCpuInfo == NULL || !NT_SUCCESS(msrPremissionMap.Init()))
		{
			KdPrint(("SVMManager::Init(): MSR premission map init failed!\n"));
			break;
		}

		status = STATUS_SUCCESS;
		//为每个CPU分配进入虚拟化所需的内存
		for (idx = 0; idx < cpuCnt; ++idx)
		{
			pVirtCpuInfo[idx] = (VirtCpuInfo*)AllocContiguousMem(sizeof(VirtCpuInfo), SVM_TAG);
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
		//进入虚拟化
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
		UINT64 idx = 0;
		PROCESSOR_NUMBER processorNum = {};
		GROUP_AFFINITY affinity = {}, oldAffinity = {};

		for (idx = 0; idx < cpuCnt; ++idx)
		{
			if (pVirtCpuInfo[idx] != NULL)
			{
				//如果已经进入虚拟化，则按照核心退出虚拟化
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
				FreeContigousMem(pVirtCpuInfo[idx], SVM_TAG);
				pVirtCpuInfo[idx] = NULL;
			}
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
	NTSTATUS status = STATUS_SUCCESS;
	PROCESSOR_NUMBER processorNum = {};
	GROUP_AFFINITY affinity = {}, oldAffinity = {};
	UINT32 cpuIdx = 0;
	GenericRegisters registerBackup = {};

	for (cpuIdx = 0; cpuIdx < cpuCnt; ++cpuIdx)
	{
		status = KeGetProcessorNumberFromIndex(cpuIdx, &processorNum);
		if (!NT_SUCCESS(status))
			break;

		affinity = {};
		affinity.Group = processorNum.Group;
		affinity.Mask = 1ULL << processorNum.Number;

		KeSetSystemGroupAffinityThread(&affinity, &oldAffinity);

		_save_or_load_regs(&registerBackup);
		//标记进入虚拟化之后，需要恢复的寄存器
		registerBackup.rax = (UINT64)&registerBackup;

		if (!pVirtCpuInfo[cpuIdx]->otherInfo.isInVirtualizaion)
		{
			//标记已经进入过虚拟化
			pVirtCpuInfo[cpuIdx]->otherInfo.isInVirtualizaion = TRUE;

			UINT64 gdtrBase = 0, idtrBase = 0;
			UINT16 gdtrLimit = 0, idtrLimit = 0;
			UINT16 trSelector = 0, ldtrSelector = 0;
			_mysgdt(&gdtrBase, &gdtrLimit);
			_mysidt(&idtrBase, &idtrLimit);
			_mystr(&trSelector);
			_mysldt(&ldtrSelector);

			UINT64 eferBackup = __readmsr(IA32_MSR_EFER);
			__writemsr(IA32_MSR_SVM_MSR_VM_HSAVE_PA, MmGetPhysicalAddress(&pVirtCpuInfo[cpuIdx]->hostStatus).QuadPart);
			__writemsr(IA32_MSR_EFER, eferBackup | (1ULL << EFER_SVME_OFFSET));

			pVirtCpuInfo[cpuIdx]->guestVmcb.controlFields.interceptOpcodes1
				= Opcode1InterceptBits::CPUID | Opcode1InterceptBits::RDMSR_WRMSR;
			//vmrun拦截必须打开，否则vmrun会失败
			pVirtCpuInfo[cpuIdx]->guestVmcb.controlFields.interceptOpcodes2
				= Opcode2InterceptBits::VMRUN;

			//如果断点拦截插件存在，打开断点拦截
			if (pBreakpointInterceptPlugin != NULL)
				pVirtCpuInfo[cpuIdx]->guestVmcb.controlFields.interceptExceptionX = (1UL << BP_EXPECTION_VECTOR_INDEX);

			//如果UD拦截插件存在，打开UD拦截
			if (pInvalidOpcodeInterceptPlugin != NULL)
				pVirtCpuInfo[cpuIdx]->guestVmcb.controlFields.interceptExceptionX |= (1UL << UD_EXCEPTION_VECTOR_INDEX);

			//如果DE拦截插件存在，打开DE拦截
			if (pDebugInterceptPlugin != NULL)
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

			pVirtCpuInfo[cpuIdx]->guestVmcb.statusFields.gdtr.base = gdtrBase;
			pVirtCpuInfo[cpuIdx]->guestVmcb.statusFields.gdtr.limit = gdtrLimit;
			pVirtCpuInfo[cpuIdx]->guestVmcb.statusFields.idtr.base = idtrBase;
			pVirtCpuInfo[cpuIdx]->guestVmcb.statusFields.idtr.limit = idtrLimit;

			//X64 代码段和数据段的base和limit是无效的
			//base 强制为 0（强制平坦段）
			pVirtCpuInfo[cpuIdx]->guestVmcb.statusFields.cs.selector = _cs_selector();
			pVirtCpuInfo[cpuIdx]->guestVmcb.statusFields.cs.attrib = GetSegmentAttribute(_cs_selector(), gdtrBase).AsUInt16;

			pVirtCpuInfo[cpuIdx]->guestVmcb.statusFields.ds.selector = _ds_selector();
			pVirtCpuInfo[cpuIdx]->guestVmcb.statusFields.ds.attrib = GetSegmentAttribute(_ds_selector(), gdtrBase).AsUInt16;

			pVirtCpuInfo[cpuIdx]->guestVmcb.statusFields.es.selector = _es_selector();
			pVirtCpuInfo[cpuIdx]->guestVmcb.statusFields.es.attrib = GetSegmentAttribute(_es_selector(), gdtrBase).AsUInt16;

			pVirtCpuInfo[cpuIdx]->guestVmcb.statusFields.ss.selector = _ss_selector();
			pVirtCpuInfo[cpuIdx]->guestVmcb.statusFields.ss.attrib = GetSegmentAttribute(_ss_selector(), gdtrBase).AsUInt16;

			//下面的这一组信息可以使用vmsave指令直接获取
			//这里为了研究原理手动获取
			//*************************************** BEGIN ***************************************

			pVirtCpuInfo[cpuIdx]->guestVmcb.statusFields.fs.selector = _fs_selector();
			pVirtCpuInfo[cpuIdx]->guestVmcb.statusFields.fs.attrib = GetSegmentAttribute(_fs_selector(), gdtrBase).AsUInt16;

			pVirtCpuInfo[cpuIdx]->guestVmcb.statusFields.gs.selector = _gs_selector();
			pVirtCpuInfo[cpuIdx]->guestVmcb.statusFields.gs.attrib = GetSegmentAttribute(_gs_selector(), gdtrBase).AsUInt16;

			//对于TR LDTR base limit 依然有效
			pVirtCpuInfo[cpuIdx]->guestVmcb.statusFields.ldtr.selector = ldtrSelector;
			pVirtCpuInfo[cpuIdx]->guestVmcb.statusFields.ldtr.base = GetSegmentBaseAddress(ldtrSelector, gdtrBase);
			pVirtCpuInfo[cpuIdx]->guestVmcb.statusFields.ldtr.limit = GetSegmentLimit2(ldtrSelector, gdtrBase);
			pVirtCpuInfo[cpuIdx]->guestVmcb.statusFields.ldtr.attrib = GetSegmentAttribute(ldtrSelector, gdtrBase).AsUInt16;

			pVirtCpuInfo[cpuIdx]->guestVmcb.statusFields.tr.selector = trSelector;
			pVirtCpuInfo[cpuIdx]->guestVmcb.statusFields.tr.base = GetSegmentBaseAddress(trSelector, gdtrBase);
			pVirtCpuInfo[cpuIdx]->guestVmcb.statusFields.tr.limit = GetSegmentLimit2(trSelector, gdtrBase);
			pVirtCpuInfo[cpuIdx]->guestVmcb.statusFields.tr.attrib = GetSegmentAttribute(trSelector, gdtrBase).AsUInt16;

			//FSBase GSBase KenrelGSBase 可以不为0 但是是放在MSR寄存器里面的
			/*
			IA32_MSR_FS_BASE（下标0xC0000100）
			IA32_MSR_GS_BASE（下标0xC0000101）
			IA32_MSR_KERNEL_GS_BASE（下标0xC0000102）
			*/

			pVirtCpuInfo[cpuIdx]->guestVmcb.statusFields.fs.base = __readmsr(IA32_MSR_FS_BASE);
			pVirtCpuInfo[cpuIdx]->guestVmcb.statusFields.gs.base = __readmsr(IA32_MSR_GS_BASE);
			pVirtCpuInfo[cpuIdx]->guestVmcb.statusFields.kernelGsBase = __readmsr(IA32_MSR_KERNEL_GS_BASE);

			//对于32位系统才需要填充 SYSENTER_CS SYSENTER_ESP SYSENTER_EIP

			//pVirtCpuInfo[idx]->guestVmcb.statusFields.sysenterCs = __readmsr(IA32_MSR_SYSENTER_CS);
			//pVirtCpuInfo[idx]->guestVmcb.statusFields.sysenterEsp = __readmsr(IA32_MSR_SYSENTER_ESP);
			//pVirtCpuInfo[idx]->guestVmcb.statusFields.sysenterEip = __readmsr(IA32_MSR_SYSENTER_EIP);

			pVirtCpuInfo[cpuIdx]->guestVmcb.statusFields.star = __readmsr(IA32_MSR_STAR);
			pVirtCpuInfo[cpuIdx]->guestVmcb.statusFields.lstar = __readmsr(IA32_MSR_LSTAR);
			pVirtCpuInfo[cpuIdx]->guestVmcb.statusFields.cstar = __readmsr(IA32_MSR_CSTAR);
			pVirtCpuInfo[cpuIdx]->guestVmcb.statusFields.sfmask = __readmsr(IA32_MSR_SF_MASK);

			//*************************************** END ***************************************

			//填充 VMCB EFER 的 EFER 值中SVME位必须为1，否则vmrun会失败
			pVirtCpuInfo[cpuIdx]->guestVmcb.statusFields.efer = __readmsr(IA32_MSR_EFER);

			//需要时禁用syscall和sysret
			if (!enableSce)
				pVirtCpuInfo[cpuIdx]->guestVmcb.statusFields.efer &= ~(1 << SCE_ENABLE_OFFSET);

			pVirtCpuInfo[cpuIdx]->guestVmcb.statusFields.cr0 = __readcr0();
			pVirtCpuInfo[cpuIdx]->guestVmcb.statusFields.cr2 = __readcr2();
			pVirtCpuInfo[cpuIdx]->guestVmcb.statusFields.cr3 = __readcr3();
			pVirtCpuInfo[cpuIdx]->guestVmcb.statusFields.cr4 = __readcr4();
			pVirtCpuInfo[cpuIdx]->guestVmcb.statusFields.rax = registerBackup.rax;
			pVirtCpuInfo[cpuIdx]->guestVmcb.statusFields.rflags = registerBackup.rflags;
			pVirtCpuInfo[cpuIdx]->guestVmcb.statusFields.rsp = registerBackup.rsp;
			pVirtCpuInfo[cpuIdx]->guestVmcb.statusFields.rip = registerBackup.rip;
			pVirtCpuInfo[cpuIdx]->guestVmcb.statusFields.gPat = __readmsr(IA32_MSR_PAT);

			pVirtCpuInfo[cpuIdx]->guestVmcb.statusFields.cpl = _cs_selector() & 0x3;

			pVirtCpuInfo[cpuIdx]->hostVmcb.statusFields = pVirtCpuInfo[cpuIdx]->guestVmcb.statusFields;

			//__svm_vmsave((size_t)MmGetPhysicalAddress(&pVirtCpuInfo[idx]->guestVmcb).QuadPart);
			//__svm_vmsave((size_t)MmGetPhysicalAddress(&pVirtCpuInfo[idx]->hostVmcb).QuadPart);

			_run_svm_vmrun
			(
				pVirtCpuInfo[cpuIdx],
				(PVOID)MmGetPhysicalAddress(&pVirtCpuInfo[cpuIdx]->guestVmcb).QuadPart,
				(PVOID)MmGetPhysicalAddress(&pVirtCpuInfo[cpuIdx]->hostVmcb).QuadPart,
				pVirtCpuInfo[cpuIdx]->stack + sizeof pVirtCpuInfo[cpuIdx]->stack
			);

			//不应该返回
			//如果返回代表vmrun失败
			//直接 BugCheck

			KeBugCheck(MANUALLY_INITIATED_CRASH);
		}

		KeRevertToUserGroupAffinityThread(&oldAffinity);
		
	}
	return status;
}

#pragma code_seg("PAGE")
void SVMManager::LeaveVirtualization()
{
	PAGED_CODE();
	int result[4] = {};
	//调用CPUID指令通知VMM退出
	__cpuidex(result, GUEST_CALL_VMM_CPUID_FUNCTION, 0);
}

#pragma code_seg()
void SVMManager::VmExitHandler(VirtCpuInfo* pVMMVirtCpuInfo, GenericRegisters* pGuestRegisters, PVOID pGuestVmcbPhyAddr, PVOID pHostVmcbPhyAddr)
{
	UNREFERENCED_PARAMETER(pHostVmcbPhyAddr);
	UNREFERENCED_PARAMETER(pGuestVmcbPhyAddr);

	//先清空寄存器，代表这次执行后不退出虚拟机
	pGuestRegisters->extraInfo1 = 0;
	pGuestRegisters->extraInfo2 = 0;

	switch ((VmExitReasons)pVMMVirtCpuInfo->guestVmcb.controlFields.exitCode)
	{
	case VMEXIT_REASON_CPUID:
	{
		if (pCpuIdInterceptPlugin != NULL &&
			pCpuIdInterceptPlugin->HandleCpuid(pVMMVirtCpuInfo, pGuestRegisters,
				pGuestVmcbPhyAddr, pHostVmcbPhyAddr))
			return;

		if (((int)pVMMVirtCpuInfo->guestVmcb.statusFields.rax) == GUEST_CALL_VMM_CPUID_FUNCTION)
		{
			switch (pGuestRegisters->rcx)
			{
			case 0:
			{
				//设置退出虚拟化之后的指令寄存器和栈寄存器
				pGuestRegisters->extraInfo1 = pVMMVirtCpuInfo->guestVmcb.controlFields.nRip;
				pGuestRegisters->extraInfo2 = pVMMVirtCpuInfo->guestVmcb.statusFields.rsp;

				//设置RFlags
				pGuestRegisters->rflags = pVMMVirtCpuInfo->guestVmcb.statusFields.rflags;

				//在退出VMM时打开GIF，否则退出后系统会接收不了中断假死，在进入Host模式的时候GIF是关闭状态
				__svm_stgi();
				__svm_vmsave((SIZE_TYPE)pGuestVmcbPhyAddr);

				//退出虚拟化并继续执行guest
				UINT64 eferVal = __readmsr(IA32_MSR_EFER);
				__writemsr(IA32_MSR_EFER, eferVal & ~(1ULL << EFER_SVME_OFFSET));
				__writeeflags((UINT32)pVMMVirtCpuInfo->guestVmcb.statusFields.rflags);

				break;
			}
			}
		}
		else
		{
			int cpuidResult[4] = {};

			__cpuidex(cpuidResult, (int)pVMMVirtCpuInfo->guestVmcb.statusFields.rax, (int)pGuestRegisters->rcx);

			if (((int)pVMMVirtCpuInfo->guestVmcb.statusFields.rax) == CPUID_FN_SVM_FEATURE)
				cpuidResult[2] &= ~(1UL << CPUID_FN_80000001_ECX_SVM_OFFSET);

			*reinterpret_cast<UINT32*>(&pVMMVirtCpuInfo->guestVmcb.statusFields.rax) = cpuidResult[0];
			*reinterpret_cast<UINT32*>(&pGuestRegisters->rbx) = cpuidResult[1];
			*reinterpret_cast<UINT32*>(&pGuestRegisters->rcx) = cpuidResult[2];
			*reinterpret_cast<UINT32*>(&pGuestRegisters->rdx) = cpuidResult[3];
		}

		//guest到下一条指令执行
		pVMMVirtCpuInfo->guestVmcb.statusFields.rip = pVMMVirtCpuInfo->guestVmcb.controlFields.nRip;

		break;
	}
	case VMEXIT_REASON_MSR:
	{
		ULARGE_INTEGER value = {};
		UINT32 msrNum = (UINT32)pGuestRegisters->rcx;
		bool isWriteAccess = pVMMVirtCpuInfo->guestVmcb.controlFields.exitInfo1;

		if (isWriteAccess)
		{
			value.LowPart = (UINT32)pVMMVirtCpuInfo->guestVmcb.statusFields.rax;
			value.HighPart = (UINT32)pGuestRegisters->rdx;

			if (pMsrInterceptPlugin != NULL &&
				pMsrInterceptPlugin->HandleMsrInterceptWrite(pVMMVirtCpuInfo, pGuestRegisters,
					pGuestVmcbPhyAddr, pHostVmcbPhyAddr,
					msrNum))
				return;

			//不允许客户机设置 EFER MSR 的 SVME 位 和 VM_CR MSR 的 SVMDIS 位
			if (msrNum == IA32_MSR_EFER && !(value.LowPart & (1UL << EFER_SVME_OFFSET)) ||
				msrNum == IA32_MSR_VM_CR && !(value.LowPart & (1ULL << VM_CR_SVMDIS_OFFSET)))
				KeBugCheck(MANUALLY_INITIATED_CRASH);

			__writemsr(msrNum, value.QuadPart);
		}
		else
		{
			if (pMsrInterceptPlugin != NULL &&
				pMsrInterceptPlugin->HandleMsrImterceptRead(pVMMVirtCpuInfo, pGuestRegisters,
					pGuestVmcbPhyAddr, pHostVmcbPhyAddr,
					msrNum))
				return;

			value.QuadPart = __readmsr(msrNum);

			if (msrNum == IA32_MSR_VM_CR)
				value.QuadPart |= (1ULL << VM_CR_SVMDIS_OFFSET);
			if (msrNum == IA32_MSR_EFER)
				value.QuadPart &= ~(1UL << EFER_SVME_OFFSET);

			*reinterpret_cast<UINT32*>(&pVMMVirtCpuInfo->guestVmcb.statusFields.rax) = value.LowPart;
			*reinterpret_cast<UINT32*>(&pGuestRegisters->rdx) = value.HighPart;
		}

		//guest到下一条指令执行
		pVMMVirtCpuInfo->guestVmcb.statusFields.rip = pVMMVirtCpuInfo->guestVmcb.controlFields.nRip;

		break;
	}
	case VMEXIT_REASON_EXCEPTION_BP:
	{
		if (pBreakpointInterceptPlugin != NULL &&
			pBreakpointInterceptPlugin->HandleBreakpoint(pVMMVirtCpuInfo, pGuestRegisters, pGuestVmcbPhyAddr, pHostVmcbPhyAddr))
			return;

		//默认直接注入断点异常由guest处理
		pVMMVirtCpuInfo->guestVmcb.controlFields.eventInj.data = 0;
		pVMMVirtCpuInfo->guestVmcb.controlFields.eventInj.fields.vector = BP_EXPECTION_VECTOR_INDEX;
		pVMMVirtCpuInfo->guestVmcb.controlFields.eventInj.fields.type = 3;
		pVMMVirtCpuInfo->guestVmcb.controlFields.eventInj.fields.vaild = 1;
		pVMMVirtCpuInfo->guestVmcb.statusFields.rip = pVMMVirtCpuInfo->guestVmcb.controlFields.nRip;
		break;
	}
	case VMEXIT_REASON_EXCEPTION_UD:
	{
		if (pInvalidOpcodeInterceptPlugin != NULL &&
			pInvalidOpcodeInterceptPlugin->HandleInvalidOpcode(pVMMVirtCpuInfo, pGuestRegisters, pGuestVmcbPhyAddr, pHostVmcbPhyAddr))
			return;

		//注入UD异常由guest处理
		pVMMVirtCpuInfo->guestVmcb.controlFields.eventInj.data = 0;
		pVMMVirtCpuInfo->guestVmcb.controlFields.eventInj.fields.vector = UD_EXCEPTION_VECTOR_INDEX;
		pVMMVirtCpuInfo->guestVmcb.controlFields.eventInj.fields.type = 3;
		pVMMVirtCpuInfo->guestVmcb.controlFields.eventInj.fields.vaild = 1;
		break;
	}
	case VMEXIT_REASON_EXCEPTION_DB:
	{
		if (pDebugInterceptPlugin != NULL &&
			pDebugInterceptPlugin->HandleDebug(pVMMVirtCpuInfo, pGuestRegisters, pGuestVmcbPhyAddr, pHostVmcbPhyAddr))
			return;

		//注入DB异常由guest处理
		pVMMVirtCpuInfo->guestVmcb.controlFields.eventInj.data = 0;
		pVMMVirtCpuInfo->guestVmcb.controlFields.eventInj.fields.vector = DB_EXCEPTION_VECTOR_INDEX;
		pVMMVirtCpuInfo->guestVmcb.controlFields.eventInj.fields.type = 3;
		pVMMVirtCpuInfo->guestVmcb.controlFields.eventInj.fields.vaild = 1;
		break;
	}
	case VMEXIT_REASON_VMRUN:
	{
		//注入断点异常由guest处理
		pVMMVirtCpuInfo->guestVmcb.controlFields.eventInj.data = 0;
		pVMMVirtCpuInfo->guestVmcb.controlFields.eventInj.fields.vector = BP_EXPECTION_VECTOR_INDEX;
		pVMMVirtCpuInfo->guestVmcb.controlFields.eventInj.fields.type = 3;
		pVMMVirtCpuInfo->guestVmcb.controlFields.eventInj.fields.vaild = 1;
		pVMMVirtCpuInfo->guestVmcb.statusFields.rip = pVMMVirtCpuInfo->guestVmcb.controlFields.nRip;
		break;
	}
	case VMEXIT_REASON_NPF:
	{
		if (pNpfInterceptPlugin != NULL &&
			pNpfInterceptPlugin->HandleNpf(pVMMVirtCpuInfo, pGuestRegisters, pGuestVmcbPhyAddr, pHostVmcbPhyAddr))
			return;
		break;
	}
	default:
	{
		KeBugCheck(MANUALLY_INITIATED_CRASH);
		break;
	}
	}
}
