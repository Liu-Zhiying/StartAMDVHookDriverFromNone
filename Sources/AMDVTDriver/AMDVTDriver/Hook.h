#ifndef HOOK_H
#define HOOK_H

#include "Basic.h"
#include "SVM.h"
#include "PageTable.h"
#include "CasLockers.h"
#include <intrin.h>

//配置MSR HOOK参数的CPUID的Function
constexpr UINT32 CONFIGURE_MSR_HOOK_CPUID_FUNCTION = 0x400000fe;
constexpr UINT32 READ_MSR_CPUID_SUBFUNCTION = 0x00000000;
constexpr UINT32 WRITE_MSR_CPUID_SUBFUNCTION = 0x00000001;
//配置NPT HOOK参数的CPUID的Function
constexpr UINT32 NPT_HOOK_TOOL_CPUID_FUNCTION = 0x400000fd;
constexpr UINT32 CHANGE_PAGE_SIZE_CPUID_SUBFUNCTION = 0x00000000;
constexpr UINT32 COPY_MEMORY_CPUID_SUBFUNCTION = 0x00000001;
constexpr UINT32 GET_PHYSICAL_ADDRESS_SUBFUNCTION = 0x00000002;
constexpr UINT32 CHANGE_PAGE_TABLE_PERMISSION_CPUID_SUBFUNCTION = 0x00000003;
constexpr UINT32 SWAP_SMALL_PAGE_PPN_CPUID_SUBFUNCTION = 0x00000004;
constexpr UINT32 ADD_HOOK_ITEM_CPUID_SUBFUNCTION = 0x00000005;
constexpr UINT32 REMOVE_HOOK_ITEM_CPUID_SUBFUNCTION = 0x00000006;
constexpr UINT32 ADD_LEVEL3_REF_ITEM_CPUID_SUBFUNCTION = 0x00000007;
constexpr UINT32 REMOVE_LEVEL3_REF_ITEM_CPUID_SUBFUNCTION = 0x00000008;
constexpr UINT32 ADD_SWAPPAGE_REF_CNT_CPUID_SUBFUNCTION = 0x00000009;
constexpr UINT32 REMOVE_SWAPPAGE_REF_CNT_CPUID_SUBFUNCTION = 0x0000000A;
constexpr UINT32 ALLOC_NONPAGED_EXECUTEABLE_MEMORY_CPUID_SUBFUNCTION = 0x0000000B;
constexpr UINT32 FREE_NONPAGED_EXECUTEABLE_MEMORY_CPUID_SUBFUNCTION = 0x0000000C;
constexpr UINT32 OPERATE_REF_COUNT_CPUID_SUBFUNCTION = 0x0000000D;
constexpr UINT32 COPY_SWAPPAGE_REF_CNT_CPUID_SUBFUNCTION = 0x0000000E;
constexpr UINT32 COPY_LEVEL3_REF_ITEM_CPUID_SUBFUNCTION = 0x0000000F;
constexpr UINT32 COPY_HOOKRECORD_CPUID_SUBFUNCTION = 0x00000010;
constexpr UINT32 COPY_SHARED_DATA_CPUID_SUBFUNCTION = 0x00000011;
constexpr UINT32 DESTROY_SHARED_DATA_COPY_CPUID_SUBFUNCTION = 0x00000012;
constexpr UINT32 RESTORE_CR3_CPUID_SUBFUNCTION = 0x00000013;
constexpr UINT32 ALLOC_NONPAGED_MEMORY_CPUID_SUBFUNCTION = 0x00000014;
constexpr UINT32 FREE_NONPAGED_MEMORY_CPUID_SUBFUNCTION = 0x00000015;

constexpr UINT32 HOOK_TAG = MAKE_TAG('h', 'o', 'o', 'k');

//int 3 opcode
constexpr UINT32 NptHookCode = 0xCC;

//辅助函数，用于跳转到VMM处理
extern "C" void SetRegsThenCpuid(PTR_TYPE* rax, PTR_TYPE* rbx, PTR_TYPE* rcx, PTR_TYPE* rdx);

//一些调用 VMM CPUID处理功能的参数定义
struct MsrHookParameter
{
	//锁定的MXR真实值
	PTR_TYPE realValue;
	//VMM用于欺骗Guest的值
	PTR_TYPE* pFakeValues;
	//msr寄存器编号
	UINT32 msrNum;
	//是否启用Hook
	bool enabled;
};

enum PageTableType
{
	ExternalPageTable,
	InternalPageTable
};
//COPY_MEMORY_CPUID_SUBFUNCTION 
struct MemoryCopyInfo
{
	PVOID pSource;
	PVOID pDestination;
	SIZE_TYPE Length;
};
//CHANGE_PAGE_SIZE_CPUID_SUBFUNCTION
struct ChangePageSizeInfo
{
	PTR_TYPE pLevel3PhyAddr;
	ULONG cpuIdx;
	PageTableType type;
	bool beLarge;
};
//CHANGE_PAGE_TABLE_PERMISSION_CPUID_SUBFUNCTION
struct ChangePageTablePermissionInfo
{
	PageTableLevel123Entry permission;
	PTR_TYPE physicalAddress;
	PageTableType type;
	ULONG cpuIdx;
	UINT32 level;
};
//SWAP_SMALL_PAGE_PPN_CPUID_SUBFUNCTION
struct SwapSmallPagePpnInfo
{
	PTR_TYPE physicalAddress1;
	PTR_TYPE physicalAddress2;
	PageTableType type;
	ULONG cpuIdx;
};

//三个enum和OperateRefCountInfo struct 都是  OPERATE_REF_COUNT_CPUID_SUBFUNCTION 的参数

enum RefCountOperationType
{
	IncrementCount,
	DecrementCount
};

enum RefCountOperationObjectType
{
	SwapPageRefCntObject,
	Level3RefObject
};

struct OperateRefCountInfo
{
	SIZE_TYPE idx;
	RefCountOperationType operationType;
	RefCountOperationObjectType objectType;
};

//无效MSR编号常量
const UINT32 INVALID_MSRNUM = (UINT32)-1;

//HOOK MSR_LSTAR 的函数原型，GenericRegisters 的 extraInfo1 是 用户态 rsp 地址
typedef void(*pLStarHookCallback)(GenericRegisters* pRegisters, PVOID param1, PVOID param2, PVOID param3);

//READ_MSR_CPUID_SUBFUNCTION 和 WRITE_MSR_CPUID_SUBFUNCTION 的参数
struct MsrOperationParameter
{
	//MSR 编号
	UINT32 msrNum;
	//MSR 值数组的指针，索引是核心索引
	PTR_TYPE* pValueInOut;
};

//MSR HOOK 管理器，msrHookCount代表要Hook的MSR的个数
template<SIZE_TYPE msrHookCount>
class MsrHookManager : public IManager, public IMsrInterceptPlugin, public ICpuidInterceptPlugin
{
	//MSR HOOK 值备份
	MsrHookParameter parameters[msrHookCount];
	//是否已经初始化
	bool inited;
	//CPO核心个数
	ULONG cpuCnt;
	//锁
	ReadWriteLock locker;
public:
	MsrHookManager();
	//设置每个要hook的msr的编号
	void SetHookMsrs(UINT32(&msrNums)[msrHookCount]);
	virtual NTSTATUS Init() override;
	virtual void Deinit() override;
	virtual void SetMsrPremissionMap(RTL_BITMAP& bitmap) override;
	virtual bool HandleMsrImterceptRead(VirtCpuInfo* pVirtCpuInfo, GenericRegisters* pGuestRegisters,
		PVOID pGuestVmcbPhyAddr, PVOID pHostVmcbPhyAddr,
		UINT32 msrNum) override;
	virtual bool HandleMsrInterceptWrite(VirtCpuInfo* pVirtCpuInfo, GenericRegisters* pGuestRegisters,
		PVOID pGuestVmcbPhyAddr, PVOID pHostVmcbPhyAddr,
		UINT32 msrNum) override;
	virtual bool HandleCpuid(VirtCpuInfo* pVirtCpuInfo, GenericRegisters* pGuestRegisters,
		PVOID pGuestVmcbPhyAddr, PVOID pHostVmcbPhyAddr) override;
	//启用 msr hook，msrNum代表编号，realValue 代表真实值，之后对msr的读写都是在欺骗值的内存中，不会影响真实值
	void EnableMsrHook(UINT32 msrNum, PTR_TYPE realValue);
	//禁用 msr hook，writeFakeValueToMsr代表是否将欺骗值写入msr以还原msr
	void DisableMsrHook(UINT32 msrNum, bool writeFakeValueToMsr = true);
	#pragma code_seg("PAGE")
	virtual ~MsrHookManager() { PAGED_CODE(); Deinit(); }
};

#pragma code_seg("PAGE")
template<SIZE_TYPE msrHookCount>
MsrHookManager<msrHookCount>::MsrHookManager() : inited(false), cpuCnt(0)
{
	PAGED_CODE();
	//给msr参数默认值
	RtlZeroMemory(&parameters, sizeof parameters);
	for (MsrHookParameter& param : parameters)
		param.msrNum = INVALID_MSRNUM;
}

#pragma code_seg("PAGE")
template<SIZE_TYPE msrHookCount>
void MsrHookManager<msrHookCount>::SetHookMsrs(UINT32(&msrNums)[msrHookCount])
{
	PAGED_CODE();
	for (SIZE_TYPE idx = 0; idx < msrHookCount; ++idx)
		parameters[idx].msrNum = msrNums[idx];
}

#pragma code_seg("PAGE")
template<SIZE_TYPE msrHookCount>
NTSTATUS MsrHookManager<msrHookCount>::Init()
{
	PAGED_CODE();
	NTSTATUS status = STATUS_SUCCESS;
	if (!inited)
	{
		//获取CPU核心数
		cpuCnt = KeQueryActiveProcessorCountEx(ALL_PROCESSOR_GROUPS);
		//为每个要hook的msr分配值备份空间
		for (MsrHookParameter& param : parameters)
		{
			param.pFakeValues = (PTR_TYPE*)AllocNonPagedMem(sizeof * param.pFakeValues * cpuCnt, HOOK_TAG);
			if (param.pFakeValues == NULL)
			{
				status = STATUS_INSUFFICIENT_RESOURCES;
				break;
			}
			RtlZeroMemory(param.pFakeValues, sizeof * param.pFakeValues * cpuCnt);
		}

		if (NT_SUCCESS(status))
			inited = true;
	}
	return status;
}

#pragma code_seg("PAGE")
template <SIZE_TYPE msrHookCount>
void MsrHookManager<msrHookCount>::Deinit()
{
	PAGED_CODE();
	if (inited)
	{
		PROCESSOR_NUMBER processorNum = {};
		GROUP_AFFINITY affinity = {}, oldAffinity = {};
		MsrOperationParameter optParam = {};

		//回写欺骗值到每个核心的MSR
		for (SIZE_TYPE idx1 = 0; idx1 < msrHookCount; ++idx1)
		{
			if (parameters[idx1].enabled)
			{
				for (ULONG idx2 = 0; idx2 < cpuCnt; ++idx2)
				{
					KeGetProcessorNumberFromIndex(idx2, &processorNum);

					affinity = {};
					affinity.Group = processorNum.Group;
					affinity.Mask = 1ULL << processorNum.Number;
					KeSetSystemGroupAffinityThread(&affinity, &oldAffinity);

					optParam.msrNum = parameters[idx1].msrNum;
					optParam.pValueInOut = &parameters[idx1].pFakeValues[idx2];

					PTR_TYPE regs[] = { CONFIGURE_MSR_HOOK_CPUID_FUNCTION, parameters[idx1].msrNum, WRITE_MSR_CPUID_SUBFUNCTION, (PTR_TYPE)&optParam };
					SetRegsThenCpuid(&regs[0], &regs[1], &regs[2], &regs[3]);

					KeRevertToUserGroupAffinityThread(&oldAffinity);
				}

				parameters[idx1].enabled = false;
			}
		}
		//释放内存
		for (MsrHookParameter param : parameters)
		{
			if (param.pFakeValues != NULL)
			{
				FreeNonPagedMem(param.pFakeValues, HOOK_TAG);
				param.pFakeValues = NULL;
			}
		}
		//清空成员
		cpuCnt = 0;

		inited = false;
	}
}

#pragma code_seg("PAGE")
template<SIZE_TYPE msrHookCount>
inline void MsrHookManager<msrHookCount>::SetMsrPremissionMap(RTL_BITMAP& bitmap)
{
	PAGED_CODE();
	constexpr UINT32 BITS_PER_MSR = 2;
	constexpr UINT32 FIRST_MSR_RANGE_BASE = 0x00000000;
	constexpr UINT32 FIRST_MSRPM_OFFSET = 0x000 * CHAR_BIT;
	constexpr UINT32 SECOND_MSR_RANGE_BASE = 0xc0000000;
	constexpr UINT32 SECOND_MSRPM_OFFSET = 0x800 * CHAR_BIT;
	constexpr UINT32 THIRD_MSR_RANGE_BASE = 0xc0010000;
	constexpr UINT32 THIRD_MSRPM_OFFSET = 0x1000 * CHAR_BIT;
	constexpr UINT32 MSRPM_MSR_LENGTH = 0x2000;

	//根据要hook的msr编号设置msr permission map
	for (const MsrHookParameter& param : parameters)
	{
		UINT32 msrpmOffset = 0;
		if (param.msrNum >= FIRST_MSR_RANGE_BASE && param.msrNum < FIRST_MSR_RANGE_BASE + MSRPM_MSR_LENGTH)
			msrpmOffset = FIRST_MSRPM_OFFSET + ((param.msrNum - FIRST_MSR_RANGE_BASE) * BITS_PER_MSR);
		else if (param.msrNum >= SECOND_MSR_RANGE_BASE && param.msrNum < SECOND_MSR_RANGE_BASE + MSRPM_MSR_LENGTH)
			msrpmOffset = SECOND_MSRPM_OFFSET + ((param.msrNum - SECOND_MSR_RANGE_BASE) * BITS_PER_MSR);
		else if (param.msrNum >= THIRD_MSR_RANGE_BASE && param.msrNum < THIRD_MSR_RANGE_BASE + MSRPM_MSR_LENGTH)
			msrpmOffset = THIRD_MSRPM_OFFSET + ((param.msrNum - THIRD_MSR_RANGE_BASE) * BITS_PER_MSR);
		else
			continue;
		RtlSetBits(&bitmap, msrpmOffset, 2);
	}
}

#pragma code_seg()
template<SIZE_TYPE msrHookCount>
inline bool MsrHookManager<msrHookCount>::HandleMsrImterceptRead(VirtCpuInfo* pVirtCpuInfo, GenericRegisters* pGuestRegisters,
	PVOID pGuestVmcbPhyAddr, PVOID pHostVmcbPhyAddr,
	UINT32 msrNum)
{
	UNREFERENCED_PARAMETER(pVirtCpuInfo);
	UNREFERENCED_PARAMETER(pGuestRegisters);
	UNREFERENCED_PARAMETER(pGuestVmcbPhyAddr);
	UNREFERENCED_PARAMETER(pHostVmcbPhyAddr);

	bool handled = false;

	locker.ReadLock();

	for (SIZE_TYPE idx = 0; idx < msrHookCount; ++idx)
	{
		//MSR Hook启用且MSR编号匹配则返回欺骗值
		if (parameters[idx].enabled && msrNum == parameters[idx].msrNum)
		{
			LARGE_INTEGER value = {};
			value.QuadPart = parameters[idx].pFakeValues[pVirtCpuInfo->otherInfo.cpuIdx];
			*reinterpret_cast<UINT32*>(&pGuestRegisters->rax) = value.LowPart;
			*reinterpret_cast<UINT32*>(&pGuestRegisters->rdx) = value.HighPart;
			pGuestRegisters->rip = pVirtCpuInfo->guestVmcb.controlFields.nRip;
			handled = true;
			break;
		}
	}

	locker.ReadUnlock();

	return handled;
}

#pragma code_seg()
template<SIZE_TYPE msrHookCount>
inline bool MsrHookManager<msrHookCount>::HandleMsrInterceptWrite(VirtCpuInfo* pVirtCpuInfo, GenericRegisters* pGuestRegisters,
	PVOID pGuestVmcbPhyAddr, PVOID pHostVmcbPhyAddr,
	UINT32 msrNum)
{
	UNREFERENCED_PARAMETER(pVirtCpuInfo);
	UNREFERENCED_PARAMETER(pGuestRegisters);
	UNREFERENCED_PARAMETER(pGuestVmcbPhyAddr);
	UNREFERENCED_PARAMETER(pHostVmcbPhyAddr);

	bool handled = false;

	locker.ReadLock();

	for (SIZE_TYPE idx = 0; idx < msrHookCount; ++idx)
	{
		//MSR Hook启用且MSR编号匹配则保存新值为欺骗值
		if (parameters[idx].enabled && msrNum == parameters[idx].msrNum)
		{
			LARGE_INTEGER value = {};
			value.LowPart = (UINT32)pGuestRegisters->rax;
			value.HighPart = (UINT32)pGuestRegisters->rdx;
			parameters[idx].pFakeValues[pVirtCpuInfo->otherInfo.cpuIdx] = value.QuadPart;
			pGuestRegisters->rip = pVirtCpuInfo->guestVmcb.controlFields.nRip;
			handled = true;
			break;
		}
	}

	locker.ReadUnlock();

	return handled;
}

#pragma code_seg()
template<SIZE_TYPE msrHookCount>
inline bool MsrHookManager<msrHookCount>::HandleCpuid(VirtCpuInfo* pVirtCpuInfo, GenericRegisters* pGuestRegisters,
	PVOID pGuestVmcbPhyAddr, PVOID pHostVmcbPhyAddr)
{
	UNREFERENCED_PARAMETER(pGuestVmcbPhyAddr);
	UNREFERENCED_PARAMETER(pHostVmcbPhyAddr);

	//eax为配置MSR HOOK的CPUID编号
	if (((int)pGuestRegisters->rax) == CONFIGURE_MSR_HOOK_CPUID_FUNCTION)
	{
		bool handled = false;
		MsrOperationParameter* pOptParam = (MsrOperationParameter*)pGuestRegisters->rdx;

		if (((int)pGuestRegisters->rcx) == READ_MSR_CPUID_SUBFUNCTION)
		{
			/*
			IA32_MSR_EFER
			IA32_MSR_PAT
			IA32_MSR_FS_BASE
			IA32_MSR_GS_BASE
			IA32_MSR_KERNEL_GS_BASE
			IA32_MSR_STAR
			IA32_MSR_LSTAR
			IA32_MSR_CSTAR
			IA32_MSR_SF_MASK
			IA32_MSR_SYSENTER_CS
			IA32_MSR_SYSENTER_ESP
			IA32_MSR_SYSENTER_EIP
			这些msr寄存器是由VMCB决定，所以从VMCB中读取
			其他msr则直接读
			*/

			switch (pOptParam->msrNum)
			{
			case IA32_MSR_EFER:
				*pOptParam->pValueInOut = pVirtCpuInfo->guestVmcb.statusFields.efer;
				break;
			case IA32_MSR_PAT:
				*pOptParam->pValueInOut = pVirtCpuInfo->guestVmcb.statusFields.gPat;
				break;
			case IA32_MSR_FS_BASE:
				*pOptParam->pValueInOut = pVirtCpuInfo->guestVmcb.statusFields.fs.base;
				break;
			case IA32_MSR_GS_BASE:
				*pOptParam->pValueInOut = pVirtCpuInfo->guestVmcb.statusFields.gs.base;
				break;
			case IA32_MSR_KERNEL_GS_BASE:
				*pOptParam->pValueInOut = pVirtCpuInfo->guestVmcb.statusFields.kernelGsBase;
				break;
			case IA32_MSR_STAR:
				*pOptParam->pValueInOut = pVirtCpuInfo->guestVmcb.statusFields.star;
				break;
			case IA32_MSR_LSTAR:
				*pOptParam->pValueInOut = pVirtCpuInfo->guestVmcb.statusFields.lstar;
				break;
			case IA32_MSR_CSTAR:
				*pOptParam->pValueInOut = pVirtCpuInfo->guestVmcb.statusFields.cstar;
				break;
			case IA32_MSR_SF_MASK:
				*pOptParam->pValueInOut = pVirtCpuInfo->guestVmcb.statusFields.sfmask;
				break;
			case IA32_MSR_SYSENTER_CS:
				*pOptParam->pValueInOut = pVirtCpuInfo->guestVmcb.statusFields.sysenterCs;
				break;
			case IA32_MSR_SYSENTER_ESP:
				*pOptParam->pValueInOut = pVirtCpuInfo->guestVmcb.statusFields.sysenterEsp;
				break;
			case IA32_MSR_SYSENTER_EIP:
				*pOptParam->pValueInOut = pVirtCpuInfo->guestVmcb.statusFields.sysenterEip;
				break;
			default:
				*pOptParam->pValueInOut = __readmsr(pOptParam->msrNum);
				break;
			}

			pGuestRegisters->rip = pVirtCpuInfo->guestVmcb.controlFields.nRip;

			handled = true;
		}
		else if (((int)pGuestRegisters->rcx) == WRITE_MSR_CPUID_SUBFUNCTION)
		{
			/*
			IA32_MSR_EFER
			IA32_MSR_PAT
			IA32_MSR_FS_BASE
			IA32_MSR_GS_BASE
			IA32_MSR_KERNEL_GS_BASE
			IA32_MSR_STAR
			IA32_MSR_LSTAR
			IA32_MSR_CSTAR
			IA32_MSR_SF_MASK
			IA32_MSR_SYSENTER_CS
			IA32_MSR_SYSENTER_ESP
			IA32_MSR_SYSENTER_EIP
			这些msr寄存器是由VMCB决定，所以直接写入VMCB
			其他msr则直接写
			*/

			switch (pOptParam->msrNum)
			{
			case IA32_MSR_EFER:
				pVirtCpuInfo->guestVmcb.statusFields.efer = *pOptParam->pValueInOut;
				break;
			case IA32_MSR_PAT:
				pVirtCpuInfo->guestVmcb.statusFields.gPat = *pOptParam->pValueInOut;
				break;
			case IA32_MSR_FS_BASE:
				pVirtCpuInfo->guestVmcb.statusFields.fs.base = *pOptParam->pValueInOut;
				break;
			case IA32_MSR_GS_BASE:
				pVirtCpuInfo->guestVmcb.statusFields.gs.base = *pOptParam->pValueInOut;
				break;
			case IA32_MSR_KERNEL_GS_BASE:
				pVirtCpuInfo->guestVmcb.statusFields.kernelGsBase = *pOptParam->pValueInOut;
				break;
			case IA32_MSR_STAR:
				pVirtCpuInfo->guestVmcb.statusFields.star = *pOptParam->pValueInOut;
				break;
			case IA32_MSR_LSTAR:
				pVirtCpuInfo->guestVmcb.statusFields.lstar = *pOptParam->pValueInOut;
				break;
			case IA32_MSR_CSTAR:
				pVirtCpuInfo->guestVmcb.statusFields.cstar = *pOptParam->pValueInOut;
				break;
			case IA32_MSR_SF_MASK:
				pVirtCpuInfo->guestVmcb.statusFields.sfmask = *pOptParam->pValueInOut;
				break;
			case IA32_MSR_SYSENTER_CS:
				pVirtCpuInfo->guestVmcb.statusFields.sysenterCs = *pOptParam->pValueInOut;
				break;
			case IA32_MSR_SYSENTER_ESP:
				pVirtCpuInfo->guestVmcb.statusFields.sysenterEsp = *pOptParam->pValueInOut;
				break;
			case IA32_MSR_SYSENTER_EIP:
				pVirtCpuInfo->guestVmcb.statusFields.sysenterEip = *pOptParam->pValueInOut;
				break;
			default:
				__writemsr(pOptParam->msrNum, *pOptParam->pValueInOut);
				break;
			}

			pGuestRegisters->rip = pVirtCpuInfo->guestVmcb.controlFields.nRip;

			handled = true;
		}

		return handled;
	}
	return false;
}

#pragma code_seg("PAGE")
template<SIZE_TYPE msrHookCount>
inline void MsrHookManager<msrHookCount>::EnableMsrHook(UINT32 msrNum, PTR_TYPE realValue)
{
	PAGED_CODE();
	PROCESSOR_NUMBER processorNum = {};
	GROUP_AFFINITY affinity = {}, oldAffinity = {};
	MsrOperationParameter optParam = {};
	PTR_TYPE regs[4] = {};

	locker.WriteLock();

	for (SIZE_TYPE idx1 = 0; idx1 < msrHookCount; ++idx1)
	{
		//如果没有启用该msr的hook，而且msr编号匹配
		if (!parameters[idx1].enabled && parameters[idx1].msrNum == msrNum)
		{
			for (ULONG idx2 = 0; idx2 < cpuCnt; ++idx2)
			{
				KeGetProcessorNumberFromIndex(idx2, &processorNum);

				affinity = {};
				affinity.Group = processorNum.Group;
				affinity.Mask = 1ULL << processorNum.Number;
				KeSetSystemGroupAffinityThread(&affinity, &oldAffinity);

				//读取每一个核心的原值作为欺骗值
				optParam.msrNum = msrNum;
				optParam.pValueInOut = &parameters[idx1].pFakeValues[idx2];

				regs[0] = CONFIGURE_MSR_HOOK_CPUID_FUNCTION;
				regs[1] = msrNum;
				regs[2] = READ_MSR_CPUID_SUBFUNCTION;
				regs[3] = (PTR_TYPE)&optParam;

				SetRegsThenCpuid(&regs[0], &regs[1], &regs[2], &regs[3]);

				//写入真实值到每个核心
				optParam.msrNum = msrNum;
				optParam.pValueInOut = &realValue;

				regs[0] = CONFIGURE_MSR_HOOK_CPUID_FUNCTION;
				regs[1] = msrNum;
				regs[2] = WRITE_MSR_CPUID_SUBFUNCTION;
				regs[3] = (PTR_TYPE)&optParam;

				SetRegsThenCpuid(&regs[0], &regs[1], &regs[2], &regs[3]);

				KeRevertToUserGroupAffinityThread(&oldAffinity);
			}
			parameters[idx1].enabled = true;
		}
	}

	locker.WriteUnlock();
}

#pragma code_seg("PAGE")
template<SIZE_TYPE msrHookCount>
inline void MsrHookManager<msrHookCount>::DisableMsrHook(UINT32 msrNum, bool writeFakeValueToMsr)
{
	PAGED_CODE();
	PROCESSOR_NUMBER processorNum = {};
	GROUP_AFFINITY affinity = {}, oldAffinity = {};
	MsrOperationParameter optParam = {};

	locker.WriteLock();

	for (SIZE_TYPE idx1 = 0; idx1 < msrHookCount; ++idx1)
	{
		//如果已经启用该msr的hook，而且msr编号匹配
		if (parameters[idx1].enabled && parameters[idx1].msrNum == msrNum)
		{
			//回写欺骗值到每个核心的MSR
			if (writeFakeValueToMsr)
			{
				for (ULONG idx2 = 0; idx2 < cpuCnt; ++idx2)
				{
					KeGetProcessorNumberFromIndex(idx2, &processorNum);

					affinity = {};
					affinity.Group = processorNum.Group;
					affinity.Mask = 1ULL << processorNum.Number;
					KeSetSystemGroupAffinityThread(&affinity, &oldAffinity);

					optParam.msrNum = msrNum;
					optParam.pValueInOut = &parameters[idx1].pFakeValues[idx2];

					SetRegsThenCpuid(CONFIGURE_MSR_HOOK_CPUID_FUNCTION, msrNum, WRITE_MSR_CPUID_SUBFUNCTION, (PTR_TYPE)&optParam);

					KeRevertToUserGroupAffinityThread(&oldAffinity);
				}
			}
			parameters[idx1].enabled = false;
		}
	}

	locker.WriteUnlock();
}

//MSR_LSTAR HOOK 帮助函数，启用HOOK
//启用IA32_MSR_LSTAR HOOK 使用之前需要调用MsrHookManager::SetHookMsrs注册IA32_MSR_LSTAR
#pragma code_seg("PAGE")
template<SIZE_TYPE msrCnt>
void EnableLStrHook(MsrHookManager<msrCnt>* pMsrHookManager, pLStarHookCallback pCallback, PVOID param1, PVOID param2, PVOID param3)
{
	PAGED_CODE();
	extern void SetLStrHookEntryParameters(PTR_TYPE oldEntry, PTR_TYPE pCallback, PTR_TYPE param1, PTR_TYPE param2, PTR_TYPE param3);
	extern PTR_TYPE GetLStarHookEntry();

	MsrOperationParameter optParam = {};
	PTR_TYPE pOldEntry = NULL;
	optParam.msrNum = IA32_MSR_LSTAR;
	optParam.pValueInOut = &pOldEntry;

	PTR_TYPE regs[] = { CONFIGURE_MSR_HOOK_CPUID_FUNCTION, IA32_MSR_LSTAR, READ_MSR_CPUID_SUBFUNCTION, (PTR_TYPE)&optParam };

	SetRegsThenCpuid(&regs[0], &regs[1], &regs[2], &regs[3]);

	SetLStrHookEntryParameters((PTR_TYPE)pOldEntry, (PTR_TYPE)pCallback, (PTR_TYPE)param1, (PTR_TYPE)param2, (PTR_TYPE)param3);
	pMsrHookManager->EnableMsrHook(IA32_MSR_LSTAR, (PTR_TYPE)GetLStarHookEntry());
}

//MSR_LSTAR HOOK 帮助函数，禁用HOOK
#pragma code_seg("PAGE")
template<SIZE_TYPE msrCnt>
void DisableLStrHook(MsrHookManager<msrCnt>* pMsrHookManager)
{
	PAGED_CODE();
	pMsrHookManager->DisableMsrHook(IA32_MSR_LSTAR);
}

//页表Level3改小页的记录项，如果计数为0，则可以恢复大页
struct SmallPageLevel2RefCnt
{
	//包含level 1 2 3偏移的的物理地址
	PTR_TYPE level3PhyAddr;
	SIZE_TYPE refCnt;
	#pragma code_seg()
	SmallPageLevel2RefCnt() : level3PhyAddr(INVALID_ADDR), refCnt(0) {}
};

//交换页的记录
struct SwapPageRefCnt
{
	//原始页面的虚拟地址
	PVOID pOriginVirtAddr;
	//替换页面的虚拟地址
	PVOID pSwapVirtAddr;
	SIZE_TYPE refCnt;
	#pragma code_seg()
	SwapPageRefCnt() : pOriginVirtAddr(NULL), pSwapVirtAddr(NULL), refCnt(0) {}
};

//hook条目记录
struct NptHookRecord
{
	//hook原始虚拟地址
	PVOID pOriginVirtAddr;
	//hook的跳转地址
	PVOID pGotoVirtAddr;
	#pragma code_seg()
	NptHookRecord() : pOriginVirtAddr(NULL), pGotoVirtAddr(NULL) {}
};

//NPT HOOK 核心间共享的数据，主要是HOOK记录、小页记录、交换页记录
class NptHookSharedData
{
public:
	KernelVector<SmallPageLevel2RefCnt, HOOK_TAG> level3Refs;
	KernelVector<SwapPageRefCnt, HOOK_TAG> swapPageRefs;
	KernelVector<NptHookRecord, HOOK_TAG> hookRecords;

	//通过hook的原始虚拟地址查找记录（HookRecord）
	SIZE_TYPE FindHookRecordByOriginVirtAddr(PVOID pOriginAddr) const;
	//通过物理地址（只带有Level 4 3 2三级偏移）查找小页记录（SmallPageLevel3RefCnt）
	SIZE_TYPE FindSmallPageLevel2RefCntByPhyAddr(PTR_TYPE phyAddr) const;
	//通过hook源物理地址查找交换页记录（SwapPageRefCnt）
	SIZE_TYPE FindSwapPageRefCntByOriginPhyAddr(PTR_TYPE phyAddr) const;
	//通过hook源虚拟地址查找交换页记录（SwapPageRefCnt）
	SIZE_TYPE FindSwapPageRefCntByOriginVirtAddr(PVOID pOriginAddr) const;

	NptHookSharedData() = default;
	~NptHookSharedData() = default;

	//默认拷贝和移动函数
	#pragma code_seg("PAGE")
	NptHookSharedData(const NptHookSharedData&) = default;
	#pragma code_seg("PAGE")
	NptHookSharedData& operator=(const NptHookSharedData&) = default;
	#pragma code_seg("PAGE")
	NptHookSharedData(NptHookSharedData&&) = default;
	#pragma code_seg("PAGE")
	NptHookSharedData& operator=(NptHookSharedData&&) = default;
};

//每个核心的NPT HOOK状态
struct CoreNptHookStatus
{
	enum PremissionStatus
	{
		HookPageNotExecuted,
		HookPageExecuted
	};
	PremissionStatus premissionStatus;
	PTR_TYPE pLastActiveHookPageVirtAddr;
	//核心间共享的数据的拷贝的指针7

	//核心间共享的数据会有两份，一份在NptHookManager中，另一份则由这个指针指向
	//修改HOOK时，先更新NptHookManager中的数据，再拷贝一份NptHookManager中，并将拷贝的指针更新到这个指针中，最后销毁这个指针旧值指向的数据

	const NptHookSharedData* pSharedData;
public:
	#pragma code_seg()
	CoreNptHookStatus() : premissionStatus(HookPageNotExecuted), pLastActiveHookPageVirtAddr(NULL), pSharedData(NULL) {}
};

class NptHookManager : public IManager, public IBreakprointInterceptPlugin, public INpfInterceptPlugin, public ICpuidInterceptPlugin
{
	//核心间共享数据
	NptHookSharedData sharedData;
	//核心间共享数据拷贝的指针
	NptHookSharedData* pSharedDataCopy;
	//每个核心的NPT HOOK状态
	CoreNptHookStatus* pCoreNptHookStatus;
	//外部页表管理器的指针
	PageTableManager* pPageTableManager;
	//内部页表管理器，每个核心在内部页表和外部页表之间切换，加快NPT HOOK的速度
	PageTableManager internalPageTableManager;

	//使用大页映射和使用小页映射切换
	NTSTATUS ChangeLargePageToSmallPage(PTR_TYPE pOriginLevel3PhyAddr, PageTableType type);
	NTSTATUS ChangeSmallPageToLargePage(PTR_TYPE pOriginLevel3PhyAddr, PageTableType type);
	//修改页表的权限
	NTSTATUS ChangePageTablePermission(PTR_TYPE physicalAddress, PageTableLevel123Entry permission, PageTableType type, UINT32 level);
	//交换小页的PPN
	NTSTATUS SwapSmallPagePpn(PTR_TYPE physicalAddrees1, PTR_TYPE physicalAddress2, PageTableType type);
	//取消hook对页表的操作
	NTSTATUS CancelHookOperation(const SwapPageRefCnt& swapPageInfo);
	//同步共享数据
	void SyncSharedData();

	//上面的成员函数的核心功能都通过CPUID交由VMM处理

public:
	#pragma code_seg("PAGE")
	void SetPageTableManager(PageTableManager* _pPageTableManager) { PAGED_CODE(); pPageTableManager = _pPageTableManager; }
	//HOOK 跳转
	virtual bool HandleBreakpoint(VirtCpuInfo* pVirtCpuInfo, GenericRegisters* pGuestRegisters,
		PVOID pGuestVmcbPhyAddr, PVOID pHostVmcbPhyAddr) override;
	//HOOK页表权限修改
	virtual bool HandleNpf(VirtCpuInfo* pVirtCpuInfo, GenericRegisters* pGuestRegisters,
		PVOID pGuestVmcbPhyAddr, PVOID pHostVmcbPhyAddr) override;
	//提供修改HOOK使用的必须功能
	virtual bool HandleCpuid(VirtCpuInfo* pVirtCpuInfo, GenericRegisters* pGuestRegisters,
		PVOID pGuestVmcbPhyAddr, PVOID pHostVmcbPhyAddr) override;
	#pragma code_seg("PAGE")
	NptHookManager() : pPageTableManager(NULL), pSharedDataCopy(NULL), pCoreNptHookStatus(NULL) { PAGED_CODE(); }
	//添加hook
	NTSTATUS AddHook(const NptHookRecord& record);
	//删除hook，pHookOriginVirtAddr是hook位置的虚拟地址
	NTSTATUS RemoveHook(PVOID pHookOriginVirtAddr);
	virtual NTSTATUS Init() override;
	virtual void Deinit() override;
	#pragma code_seg("PAGE")
	virtual ~NptHookManager() { PAGED_CODE(); Deinit(); }
};

#endif
