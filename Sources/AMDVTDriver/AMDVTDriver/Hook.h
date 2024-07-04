#ifndef HOOK_H
#define HOOK_H

#include "Basic.h"
#include "SVM.h"
#include <intrin.h>

//配置MSR HOOK参数的CPUID的Function
const UINT32 CONFIGURE_MSR_HOOK_CPUID_FUNCTION = 0x400000fe;
const UINT32 READ_MSR_CPUID_SUBFUNCTION = 0x00000000;
const UINT32 WRITE_MSR_CPUID_SUBFUNCTION = 0x00000001;

const UINT32 HOOK_TAG = MAKE_TAG('h', 'o', 'o', 'k');

//辅助函数，用于跳转到VMM处理MSR HOOK参数的修改
extern "C" void SetRegsThenCpuid(UINT32 eax, UINT32 ebx, UINT32 ecx, PTR_TYPE rdx);

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

const UINT32 INVALID_MSRNUM = (UINT32)-1;

template<SIZE_T msrHookCount>
class MsrHookManager : public IManager, public IMsrInterceptPlugin, public ICpuidInterceptPlugin
{
	KMUTEX operationLock;
	MsrHookParameter parameters[msrHookCount];
	bool inited;
	ULONG cpuCnt;

	struct MsrOperationParameter
	{
		UINT32 msrNum;
		PTR_TYPE* pValueInOut;
	};

public:
	MsrHookManager();
	void SetHookMsrs(UINT32(&msrNums)[msrHookCount]);
	virtual NTSTATUS Init() override;
	virtual void Deinit() override;
	virtual void SetMsrPremissionMap(RTL_BITMAP& bitmap) override;
	virtual bool HandleMsrImterceptRead(VirtCpuInfo* pVirtCpuInfo, GenericRegisters* pGuestRegisters,
		PVOID pGuestVmcbPhyAddr, PVOID pHostVmcbPhyAddr,
		UINT32 msrNum, PULARGE_INTEGER msrValueOut) override;
	virtual bool HandleMsrInterceptWrite(VirtCpuInfo* pVirtCpuInfo, GenericRegisters* pGuestRegisters,
		PVOID pGuestVmcbPhyAddr, PVOID pHostVmcbPhyAddr,
		UINT32 msrNum, ULARGE_INTEGER mstValueIn) override;
	virtual bool HandleCpuid(VirtCpuInfo* pVirtCpuInfo, GenericRegisters* pGuestRegisters,
		PVOID pGuestVmcbPhyAddr, PVOID pHostVmcbPhyAddr) override;
	//启用 msr hook
	void EnableMsrHook(UINT32 msrNum, PTR_TYPE readValue);
	//禁用 msr hook writeFakeValueToMsr代表是否将欺骗值写入msr以还原msr
	void DisableMsrHook(UINT32 msrNum, bool writeFakeValueToMsr = true);
#pragma code_seg("PAGE")
	virtual ~MsrHookManager() { PAGED_CODE(); Deinit(); }
};

#pragma code_seg("PAGE")
template<SIZE_T msrHookCount>
MsrHookManager<msrHookCount>::MsrHookManager() : inited(false), cpuCnt(0)
{
	PAGED_CODE();
	//给msr参数默认值
	operationLock = {};
	RtlZeroMemory(&parameters, sizeof parameters);
	for (MsrHookParameter& param : parameters)
		param.msrNum = INVALID_MSRNUM;
}

#pragma code_seg("PAGE")
template<SIZE_T msrHookCount>
void MsrHookManager<msrHookCount>::SetHookMsrs(UINT32(&msrNums)[msrHookCount])
{
	PAGED_CODE();
	for (SIZE_T idx = 0; idx < msrHookCount; ++idx)
		parameters[idx].msrNum = msrNums[idx];
}

#pragma code_seg("PAGE")
template<SIZE_T msrHookCount>
NTSTATUS MsrHookManager<msrHookCount>::Init()
{
	PAGED_CODE();
	NTSTATUS result = STATUS_SUCCESS;

	cpuCnt = KeQueryActiveProcessorCountEx(ALL_PROCESSOR_GROUPS);

	KeInitializeMutex(&operationLock, 0);

	for (MsrHookParameter& param : parameters)
	{
		param.pFakeValues = (PTR_TYPE*)ExAllocatePool2(POOL_FLAG_NON_PAGED, sizeof * param.pFakeValues * cpuCnt, HOOK_TAG);
		if (param.pFakeValues == NULL)
		{
			result = STATUS_NO_MEMORY;
			break;
		}
		RtlZeroMemory(param.pFakeValues, sizeof * param.pFakeValues * cpuCnt);
	}

	inited = true;
	return result;
}

#pragma code_seg("PAGE")
template <SIZE_T msrHookCount>
void MsrHookManager<msrHookCount>::Deinit()
{
	PAGED_CODE();
	if (inited)
	{
		KeWaitForSingleObject(&operationLock, Executive, KernelMode, FALSE, NULL);

		PROCESSOR_NUMBER processorNum = {};
		GROUP_AFFINITY affinity = {}, oldAffinity = {};
		MsrOperationParameter optParam = {};

		for (SIZE_T idx1 = 0; idx1 < msrHookCount; ++idx1)
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

					SetRegsThenCpuid(CONFIGURE_MSR_HOOK_CPUID_FUNCTION, parameters[idx1].msrNum, WRITE_MSR_CPUID_SUBFUNCTION, (PTR_TYPE)&optParam);

					KeRevertToUserGroupAffinityThread(&oldAffinity);
				}

				parameters[idx1].enabled = false;
			}
		}

		KeReleaseMutex(&operationLock, FALSE);

		for (MsrHookParameter param : parameters)
		{
			if (param.pFakeValues != NULL)
			{
				ExFreePool(param.pFakeValues);
				param.pFakeValues = NULL;
			}
		}

		cpuCnt = 0;

		inited = false;
	}
}

#pragma code_seg("PAGE")
template<SIZE_T msrHookCount>
inline void MsrHookManager<msrHookCount>::SetMsrPremissionMap(RTL_BITMAP& bitmap)
{
	PAGED_CODE();
	const UINT32 BITS_PER_MSR = 2;
	const UINT32 FIRST_MSR_RANGE_BASE = 0x00000000;
	const UINT32 FIRST_MSRPM_OFFSET = 0x000 * CHAR_BIT;
	const UINT32 SECOND_MSR_RANGE_BASE = 0xc0000000;
	const UINT32 SECOND_MSRPM_OFFSET = 0x800 * CHAR_BIT;
	const UINT32 THIRD_MSR_RANGE_BASE = 0xc0010000;
	const UINT32 THIRD_MSRPM_OFFSET = 0x1000 * CHAR_BIT;
	const UINT32 MSRPM_MSR_LENGTH = 0x2000;

	for (const MsrHookParameter& param : parameters)
	{
		UINT32 MSRPM_OFFSET = 0;
		if (param.msrNum >= FIRST_MSR_RANGE_BASE && param.msrNum < FIRST_MSR_RANGE_BASE + MSRPM_MSR_LENGTH)
			MSRPM_OFFSET = FIRST_MSRPM_OFFSET + ((param.msrNum - FIRST_MSR_RANGE_BASE) * BITS_PER_MSR);
		else if (param.msrNum >= SECOND_MSR_RANGE_BASE && param.msrNum < SECOND_MSR_RANGE_BASE + MSRPM_MSR_LENGTH)
			MSRPM_OFFSET = SECOND_MSRPM_OFFSET + ((param.msrNum - SECOND_MSR_RANGE_BASE) * BITS_PER_MSR);
		else if (param.msrNum >= THIRD_MSR_RANGE_BASE && param.msrNum < THIRD_MSR_RANGE_BASE + MSRPM_MSR_LENGTH)
			MSRPM_OFFSET = THIRD_MSRPM_OFFSET + ((param.msrNum - THIRD_MSR_RANGE_BASE) * BITS_PER_MSR);
		else
			continue;
		RtlSetBits(&bitmap, MSRPM_OFFSET, BITS_PER_MSR);
		RtlSetBits(&bitmap, MSRPM_OFFSET + 1, BITS_PER_MSR);
	}
}

#pragma code_seg()
template<SIZE_T msrHookCount>
inline bool MsrHookManager<msrHookCount>::HandleMsrImterceptRead(VirtCpuInfo* pVirtCpuInfo, GenericRegisters* pGuestRegisters,
	PVOID pGuestVmcbPhyAddr, PVOID pHostVmcbPhyAddr,
	UINT32 msrNum, PULARGE_INTEGER msrValueOut)
{
	UNREFERENCED_PARAMETER(pVirtCpuInfo);
	UNREFERENCED_PARAMETER(pGuestRegisters);
	UNREFERENCED_PARAMETER(pGuestVmcbPhyAddr);
	UNREFERENCED_PARAMETER(pHostVmcbPhyAddr);
	bool handled = false;
	KeWaitForSingleObject(&operationLock, Executive, KernelMode, FALSE, NULL);

	for (SIZE_T idx = 0; idx < msrHookCount; ++idx)
	{
		//MSR Hook启用且MSR编号匹配则返回欺骗值
		if (parameters[idx].enabled && msrNum == parameters[idx].msrNum)
		{
			ULONG processorIndexx = KeGetCurrentProcessorIndex();
			msrValueOut->QuadPart = parameters[idx].pFakeValues[processorIndexx];
			pVirtCpuInfo->guestVmcb.statusFields.rip = pVirtCpuInfo->guestVmcb.controlFields.nRip;
			handled = true;
			break;
		}
	}

	KeReleaseMutex(&operationLock, FALSE);
	return handled;
}

#pragma code_seg()
template<SIZE_T msrHookCount>
inline bool MsrHookManager<msrHookCount>::HandleMsrInterceptWrite(VirtCpuInfo* pVirtCpuInfo, GenericRegisters* pGuestRegisters,
	PVOID pGuestVmcbPhyAddr, PVOID pHostVmcbPhyAddr,
	UINT32 msrNum, ULARGE_INTEGER mstValueIn)
{
	UNREFERENCED_PARAMETER(pVirtCpuInfo);
	UNREFERENCED_PARAMETER(pGuestRegisters);
	UNREFERENCED_PARAMETER(pGuestVmcbPhyAddr);
	UNREFERENCED_PARAMETER(pHostVmcbPhyAddr);
	bool handled = false;
	KeWaitForSingleObject(&operationLock, Executive, KernelMode, FALSE, NULL);

	for (SIZE_T idx = 0; idx < msrHookCount; ++idx)
	{
		//MSR Hook启用且MSR编号匹配则保存新值为欺骗值
		if (parameters[idx].enabled && msrNum == parameters[idx].msrNum)
		{
			ULONG processorIndexx = KeGetCurrentProcessorIndex();
			parameters[idx].pFakeValues[processorIndexx] = mstValueIn.QuadPart;
			pVirtCpuInfo->guestVmcb.statusFields.rip = pVirtCpuInfo->guestVmcb.controlFields.nRip;
			handled = true;
			break;
		}
	}

	KeReleaseMutex(&operationLock, FALSE);
	return handled;
}

#pragma code_seg()
template<SIZE_T msrHookCount>
inline bool MsrHookManager<msrHookCount>::HandleCpuid(VirtCpuInfo* pVirtCpuInfo, GenericRegisters* pGuestRegisters,
	PVOID pGuestVmcbPhyAddr, PVOID pHostVmcbPhyAddr)
{
	UNREFERENCED_PARAMETER(pGuestVmcbPhyAddr);
	UNREFERENCED_PARAMETER(pHostVmcbPhyAddr);
	//eax 为配置MSR HOOK的CPUID编号
	if (((int)pVirtCpuInfo->guestVmcb.statusFields.rax) == CONFIGURE_MSR_HOOK_CPUID_FUNCTION)
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

			pVirtCpuInfo->guestVmcb.statusFields.rip = pVirtCpuInfo->guestVmcb.controlFields.nRip;
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


			pVirtCpuInfo->guestVmcb.statusFields.rip = pVirtCpuInfo->guestVmcb.controlFields.nRip;
			handled = true;
		}
		return handled;
	}
	return false;
}

#pragma code_seg()
template<SIZE_T msrHookCount>
inline void MsrHookManager<msrHookCount>::EnableMsrHook(UINT32 msrNum, PTR_TYPE realValue)
{
	KeWaitForSingleObject(&operationLock, Executive, KernelMode, FALSE, NULL);

	PROCESSOR_NUMBER processorNum = {};
	GROUP_AFFINITY affinity = {}, oldAffinity = {};
	MsrOperationParameter optParam = {};

	for (SIZE_T idx1 = 0; idx1 < msrHookCount; ++idx1)
	{
		if (!parameters[idx1].enabled && parameters[idx1].msrNum == msrNum)
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

				SetRegsThenCpuid(CONFIGURE_MSR_HOOK_CPUID_FUNCTION, msrNum, READ_MSR_CPUID_SUBFUNCTION, (PTR_TYPE)&optParam);

				optParam.msrNum = msrNum;
				optParam.pValueInOut = &realValue;

				SetRegsThenCpuid(CONFIGURE_MSR_HOOK_CPUID_FUNCTION, msrNum, WRITE_MSR_CPUID_SUBFUNCTION, (PTR_TYPE)&optParam);

				KeRevertToUserGroupAffinityThread(&oldAffinity);
			}

			parameters[idx1].enabled = true;
		}
	}

	KeReleaseMutex(&operationLock, FALSE);
}

#pragma code_seg()
template<SIZE_T msrHookCount>
inline void MsrHookManager<msrHookCount>::DisableMsrHook(UINT32 msrNum, bool writeFakeValueToMsr)
{
	KeWaitForSingleObject(&operationLock, Executive, KernelMode, FALSE, NULL);

	PROCESSOR_NUMBER processorNum = {};
	GROUP_AFFINITY affinity = {}, oldAffinity = {};
	MsrOperationParameter optParam = {};

	for (SIZE_T idx1 = 0; idx1 < msrHookCount; ++idx1)
	{
		if (parameters[idx1].enabled && parameters[idx1].msrNum == msrNum)
		{
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

			parameters[idx1].enabled = true;
		}
	}

	KeReleaseMutex(&operationLock, FALSE);
}

typedef void(*pLStarHookCallback)();


//启用IA32_MSR_LSTAR HOOK 使用之前需要调用MsrHookManager::SetHookMsrs注册IA32_MSR_LSTAR
template<SIZE_T msrCnt>
void EnableLStrHook(MsrHookManager<msrCnt>* pMsrHookManager, pLStarHookCallback pCallback)
{
	extern void SetLStrHookEntryParameters(PTR_TYPE oldEntry, PTR_TYPE pCallback);	
	extern PTR_TYPE GetLStarHookEntry();
	SetLStrHookEntryParameters((PTR_TYPE)__readmsr(IA32_MSR_LSTAR), (PTR_TYPE)pCallback);
	pMsrHookManager->EnableMsrHook(IA32_MSR_LSTAR, (PTR_TYPE)GetLStarHookEntry());
}

template<SIZE_T msrCnt>
void DisableLStrHook(MsrHookManager<msrCnt>* pMsrHookManager)
{
	pMsrHookManager->DisableMsrHook(IA32_MSR_LSTAR);
}

#endif
