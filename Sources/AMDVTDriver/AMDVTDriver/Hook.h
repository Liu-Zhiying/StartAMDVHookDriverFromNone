#ifndef HOOK_H
#define HOOK_H

#include "Basic.h"
#include "SVM.h"
#include <intrin.h>

//配置MSR HOOK参数的CPUID的Function
const UINT32 CONFIGURE_MSR_HOOK_CPUID_FUNCTION = 0x400000fe;
const UINT32 ENABLE_MSR_HOOK_CPUID_SUBFUNCTION = 0x00000000;
const UINT32 DISABLE_MSR_HOOK_CPUID_SUBFUNCTION = 0x00000001;

//辅助函数，用于跳转到VMM处理MSR HOOK参数的修改
extern "C" void SetRegsThenCpuid(UINT32 eax, UINT32 ebx, UINT32 ecx, PTR_TYPE rdx);

struct MsrHookParameter
{
	//锁定的MXR真实值
	PTR_TYPE realValue;
	//VMM用于欺骗Guest的值
	PTR_TYPE fakeValue;
	//msr寄存器编号
	UINT32 msrNum;
	//是否启用Hook
	bool enabled;
};

const UINT32 INVALID_MSRNUM = (UINT32)-1;

template<SIZE_T msrHookCount>
class MsrHookManager : public IManager, public IMsrInterceptPlugin, public ICpuidInterceptPlugin
{
	KSPIN_LOCK operationLock;
	MsrHookParameter parameters[msrHookCount];
public:
	MsrHookManager();
	void SetHookMsrs(UINT32(&msrNums)[msrHookCount]);
	virtual NTSTATUS Init() override;
	virtual void Deinit() override;
	virtual void SetMsrPremissionMap(RTL_BITMAP& bitmap) override;
	virtual bool HandleMsrImterceptRead(UINT32 msrNum, PULARGE_INTEGER msrValueOut) override;
	virtual bool HandleMsrInterceptWrite(UINT32 msrNum, ULARGE_INTEGER mstValueIn) override;
	virtual bool HandleCpuid(GenericRegisters* pRegisters, PTR_TYPE* pRax) override;
	//启用 msr hook
	void EnableMsrHook(UINT32 msrNum, PTR_TYPE readValue);
	//禁用 msr hook writeFakeValueToMsr代表是否将欺骗值写入msr以还原msr
	void DisableMsrHook(UINT32 msrNum, bool writeFakeValueToMsr = true);
	~MsrHookManager() { Deinit(); }
};

#pragma code_seg("PAGE")
template<SIZE_T msrHookCount>
MsrHookManager<msrHookCount>::MsrHookManager()
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
	KeInitializeSpinLock(&operationLock);
	return STATUS_SUCCESS;
}

#pragma code_seg("PAGE")
template <SIZE_T msrHookCount>
void MsrHookManager<msrHookCount>::Deinit()
{
	PAGED_CODE();
}

template<SIZE_T msrHookCount>
inline void MsrHookManager<msrHookCount>::SetMsrPremissionMap(RTL_BITMAP& bitmap)
{
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

template<SIZE_T msrHookCount>
inline bool MsrHookManager<msrHookCount>::HandleMsrImterceptRead(UINT32 msrNum, PULARGE_INTEGER msrValueOut)
{
	bool handled = false;
	KIRQL oldIrql = {};
	KeAcquireSpinLock(&operationLock, &oldIrql);

	for (SIZE_T idx = 0; idx < msrHookCount; ++idx)
	{
		//MSR Hook启用且MSR编号匹配则返回欺骗值
		if (parameters[idx].enabled && msrNum == parameters[idx].msrNum)
		{
			msrValueOut->QuadPart = parameters[idx].fakeValue;
			handled = true;
			break;
		}
	}

	KeReleaseSpinLock(&operationLock, oldIrql);
	return handled;
}

template<SIZE_T msrHookCount>
inline bool MsrHookManager<msrHookCount>::HandleMsrInterceptWrite(UINT32 msrNum, ULARGE_INTEGER mstValueIn)
{
	bool handled = false;
	KIRQL oldIrql = {};
	KeAcquireSpinLock(&operationLock, &oldIrql);

	for (SIZE_T idx = 0; idx < msrHookCount; ++idx)
	{
		//MSR Hook启用且MSR编号匹配则保存新值为欺骗值
		if (parameters[idx].enabled && msrNum == parameters[idx].msrNum)
		{
			parameters[idx].fakeValue = mstValueIn.QuadPart;
			handled = true;
			break;
		}
	}

	KeReleaseSpinLock(&operationLock, oldIrql);
	return handled;
}

template<SIZE_T msrHookCount>
inline bool MsrHookManager<msrHookCount>::HandleCpuid(GenericRegisters* pGuestRegisters, PTR_TYPE* pRax)
{
	//eax 为配置MSR HOOK的CPUID编号
	if (((int)*pRax) == CONFIGURE_MSR_HOOK_CPUID_FUNCTION)
	{
		UINT32 msrNum = ((UINT32)pGuestRegisters->rbx);
		bool handled = false;
		KIRQL oldIrql = {};
		KeAcquireSpinLock(&operationLock, &oldIrql);

		for (SIZE_T idx = 0; idx < msrHookCount; ++idx)
		{
			//MSR Hook启用且MSR编号匹配则保存新值为欺骗值
			if (msrNum == parameters[idx].msrNum)
			{
				//ecx 为 ENABLE_MSR_HOOK_CPUID_SUBFUNCTION 则为启用 msr hook
				//启用 msr hook ebx为MSR编号 rdx为真实值
				if (((int)pGuestRegisters->rcx) == ENABLE_MSR_HOOK_CPUID_SUBFUNCTION)
				{
					parameters[idx].fakeValue = __readmsr(msrNum);
					parameters[idx].realValue = pGuestRegisters->rdx;
					__writemsr(msrNum, parameters[idx].realValue);
					parameters[idx].enabled = true;
				}
				//ecx 为 DISABLE_MSR_HOOK_CPUID_SUBFUNCTION 则为禁用 msr hook
				//禁用 msr hook ebx为MSR编号 rdx为是否写入欺骗值到msr
				if (((int)pGuestRegisters->rcx) == DISABLE_MSR_HOOK_CPUID_SUBFUNCTION)
				{
					if (pGuestRegisters->rdx)
						__writemsr(msrNum, parameters[idx].fakeValue);
					parameters[idx].enabled = false;
				}
				break;
			}
		}

		KeReleaseSpinLock(&operationLock, oldIrql);
		return handled;
	}
	return false;
}

template<SIZE_T msrHookCount>
inline void MsrHookManager<msrHookCount>::EnableMsrHook(UINT32 msrNum, PTR_TYPE realValue)
{
	SetRegsThenCpuid(CONFIGURE_MSR_HOOK_CPUID_FUNCTION, msrNum, ENABLE_MSR_HOOK_CPUID_SUBFUNCTION, realValue);
}

template<SIZE_T msrHookCount>
inline void MsrHookManager<msrHookCount>::DisableMsrHook(UINT32 msrNum, bool writeFakeValueToMsr)
{
	SetRegsThenCpuid(CONFIGURE_MSR_HOOK_CPUID_FUNCTION, msrNum, DISABLE_MSR_HOOK_CPUID_SUBFUNCTION, writeFakeValueToMsr);
}

#endif
