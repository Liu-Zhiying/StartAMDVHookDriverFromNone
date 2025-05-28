#ifndef HOOK_H
#define HOOK_H

#include "Basic.h"
#include "SVM.h"
#include "PageTable.h"
#include "CasLockers.h"
#include <intrin.h>

//����MSR HOOK������CPUID��Function
constexpr UINT32 CONFIGURE_MSR_HOOK_CPUID_FUNCTION = 0x400000fe;
constexpr UINT32 READ_MSR_CPUID_SUBFUNCTION = 0x00000000;
constexpr UINT32 WRITE_MSR_CPUID_SUBFUNCTION = 0x00000001;
constexpr UINT32 GET_CPU_IDX_CPUID_SUBFUNCTION = 0x00000002;

constexpr UINT32 HOOK_TAG = MAKE_TAG('h', 'o', 'o', 'k');

//int 3 opcode
constexpr UINT32 NptHookCode = 0xCC;

//����������������ת��VMM����
extern "C" void SetRegsThenCpuid(PTR_TYPE* rax, PTR_TYPE* rbx, PTR_TYPE* rcx, PTR_TYPE* rdx);

//һЩ���� VMM CPUID�����ܵĲ�������
struct MsrHookParameter
{
	//MSR ���
	UINT32 msrNum;
	//�Ƿ�����HOOK�������Ǻ��������������Ӧ�ĺ����Ƿ�����hook
	bool* coreHookEnabled;
	//Fake value ֵ�����ָ�룬�����Ǻ�������
	PTR_TYPE* pFakeValues;
	//Guest Real value ֵ�����ָ�룬�����Ǻ�������
	PTR_TYPE* pGuestRealValues;
	//Host Real value ֵ�����ָ�룬�����Ǻ������������MSR��Virtualized MSR����ֵΪNULL
	PTR_TYPE* pHostRealValues;
};

//��ЧMSR��ų���
const UINT32 INVALID_MSRNUM = (UINT32)-1;

//HOOK MSR_LSTAR �ĺ���ԭ�ͣ�GenericRegisters �� extraInfo1 �� �û�̬ rsp ��ַ
typedef void(*pLStarHookCallback)(GenericRegisters* pRegisters, PVOID param1, PVOID param2, PVOID param3);

//READ_MSR_CPUID_SUBFUNCTION �� WRITE_MSR_CPUID_SUBFUNCTION �Ĳ���
struct MsrOperationParameter
{
	//MSR ���
	UINT32 msrNum;
	//MSR ֵ���ڴ��ַ
	PTR_TYPE* pValueInOut;
};

//MSR HOOK ��������msrHookCount����ҪHook��MSR�ĸ���
template<SIZE_TYPE msrHookCount>
class MsrHookManager : public IManager, public IMsrInterceptPlugin, public ICpuidInterceptPlugin, public IMsrBackupRestorePlugin
{
private:
	template<SIZE_TYPE msrCnt>
	friend void EnableLStrHook(MsrHookManager<msrCnt>* pMsrHookManager, pLStarHookCallback pCallback, PVOID param1, PVOID param2, PVOID param3);
	//�ж�MSR�Ƿ���VMCB�����ֶΣ�֧��MSR�����⻯
	static bool IsVirtualizedMsr(UINT32 msrNum)
	{
		static constexpr UINT32 VIRTUALIZED_MSRS[] =
		{
			IA32_MSR_EFER,
			IA32_MSR_PAT,
			IA32_MSR_FS_BASE,
			IA32_MSR_GS_BASE,
			IA32_MSR_KERNEL_GS_BASE,
			IA32_MSR_STAR,
			IA32_MSR_LSTAR,
			IA32_MSR_CSTAR,
			IA32_MSR_SF_MASK,
			IA32_MSR_SYSENTER_CS,
			IA32_MSR_SYSENTER_ESP,
			IA32_MSR_SYSENTER_EIP,
		};

		for (UINT32 virtualizedMsr : VIRTUALIZED_MSRS)
			if (virtualizedMsr == msrNum)
				return true;

		return false;
	}

	//ͨ��MSR��Ų��Ҷ�Ӧ������
	MsrHookParameter* FindHookParameter(UINT32 msrNum)
	{
		for (MsrHookParameter& param : parameters)
			if (param.msrNum == msrNum)
				return &param;
		return NULL;
	}

	//MSR HOOK ֵ����
	MsrHookParameter parameters[msrHookCount];
	//�Ƿ��Ѿ���ʼ��
	bool inited;
	//CPO���ĸ���
	ULONG cpuCnt;
	//��
	ReadWriteLock locker;
public:
	MsrHookManager();
	//����ÿ��Ҫhook��msr�ı��
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
	//���� msr hook��msrNum�����ţ�realValue ������ʵֵ��֮���msr�Ķ�д��������ƭֵ���ڴ��У�����Ӱ����ʵֵ��ֻ�Ե�ǰ������Ч��
	void EnableMsrHook(UINT32 msrNum, PTR_TYPE realValue);
	//���� msr hook��writeFakeValueToMsr�����Ƿ���ƭֵд��msr�Ի�ԭmsr��ֻ�Ե�ǰ������Ч��
	void DisableMsrHook(UINT32 msrNum, bool writeFakeValueToMsr = true);

	//���غͱ���guest��MSR
	virtual void LoadGuestMsrForCpu(UINT32 cpuIdx) override;
	virtual void SaveGuestMsrForCpu(UINT32 cpuIdx) override;

	//���غͱ���host��MSR
	virtual void LoadHostMsrForCpu(UINT32 cpuIdx) override;
	virtual void SaveHostMsrForCpu(UINT32 cpuIdx) override;

	#pragma code_seg("PAGE")
	virtual ~MsrHookManager() { PAGED_CODE(); Deinit(); }
};

#pragma code_seg("PAGE")
template<SIZE_TYPE msrHookCount>
MsrHookManager<msrHookCount>::MsrHookManager() : inited(false), cpuCnt(0)
{
	PAGED_CODE();
	//��msr����Ĭ��ֵ
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
		inited = true;

		//��ȡCPU������
		cpuCnt = KeQueryActiveProcessorCountEx(ALL_PROCESSOR_GROUPS);
		//Ϊÿ��Ҫhook��msr����ֵ���ݿռ�
		for (MsrHookParameter& param : parameters)
		{
			param.pFakeValues = (PTR_TYPE*)AllocNonPagedMem(sizeof * param.pFakeValues * cpuCnt, HOOK_TAG);
			if (param.pFakeValues == NULL)
			{
				status = STATUS_INSUFFICIENT_RESOURCES;
				break;
			}
			RtlZeroMemory(param.pFakeValues, sizeof * param.pFakeValues * cpuCnt);

			param.coreHookEnabled = (bool*)AllocNonPagedMem(sizeof * param.coreHookEnabled * cpuCnt, HOOK_TAG);
			if (param.coreHookEnabled == NULL)
			{
				status = STATUS_INSUFFICIENT_RESOURCES;
				break;
			}
			RtlZeroMemory(param.coreHookEnabled, sizeof * param.coreHookEnabled * cpuCnt);

			param.pGuestRealValues = (PTR_TYPE*)AllocNonPagedMem(sizeof * param.pGuestRealValues * cpuCnt, HOOK_TAG);
			if (param.pGuestRealValues == NULL)
			{
				status = STATUS_INSUFFICIENT_RESOURCES;
				break;
			}
			RtlZeroMemory(param.pGuestRealValues, sizeof * param.pGuestRealValues * cpuCnt);

			if (!IsVirtualizedMsr(param.msrNum))
			{
				param.pHostRealValues = (PTR_TYPE*)AllocNonPagedMem(sizeof * param.pHostRealValues * cpuCnt, HOOK_TAG);
				if (param.pHostRealValues == NULL)
				{
					status = STATUS_INSUFFICIENT_RESOURCES;
					break;
				}
				RtlZeroMemory(param.pHostRealValues, sizeof * param.pHostRealValues * cpuCnt);
			}
			else
			{
				param.pHostRealValues = NULL;
			}
		}

		if (!NT_SUCCESS(status))
			Deinit();
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
		auto coreAction = [this](UINT32 coreIndex) -> NTSTATUS
			{
				MsrOperationParameter optParam = {};
				for (MsrHookParameter& param : parameters)
				{
					if (param.coreHookEnabled[coreIndex])
					{
						optParam.msrNum = param.msrNum; 
						optParam.pValueInOut = &param.pFakeValues[coreIndex];

						PTR_TYPE regs[] = { CONFIGURE_MSR_HOOK_CPUID_FUNCTION, param.msrNum, WRITE_MSR_CPUID_SUBFUNCTION, (PTR_TYPE)&optParam };
						SetRegsThenCpuid(&regs[0], &regs[1], &regs[2], &regs[3]);

						param.coreHookEnabled[coreIndex] = false;
					}
				}
				return STATUS_SUCCESS;
			};

		//��д��ƭֵ��ÿ�����ĵ�MSR
		RunOnEachCore(0, cpuCnt, coreAction);

		//�ͷ��ڴ�
		for (MsrHookParameter param : parameters)
		{
			if (param.pFakeValues != NULL)
			{
				FreeNonPagedMem(param.pFakeValues, HOOK_TAG);
				param.pFakeValues = NULL;
			}

			if (param.coreHookEnabled != NULL)
			{
				FreeNonPagedMem(param.coreHookEnabled, HOOK_TAG);
				param.coreHookEnabled = NULL;
			}

			if (param.pHostRealValues != NULL)
			{
				FreeNonPagedMem(param.pHostRealValues, HOOK_TAG);
				param.pHostRealValues = NULL;
			}

			if (param.pGuestRealValues != NULL)
			{
				FreeNonPagedMem(param.pGuestRealValues, HOOK_TAG);
				param.pGuestRealValues = NULL;
			}
		}
		//��ճ�Ա
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

	//����Ҫhook��msr�������msr permission map
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

	UINT32 cpuIdx = pVirtCpuInfo->otherInfo.cpuIdx;

	for (MsrHookParameter& param : parameters)
	{
		//MSR Hook������MSR���ƥ���򷵻���ƭֵ
		if (msrNum == param.msrNum && param.coreHookEnabled[cpuIdx])
		{
			LARGE_INTEGER value = {};
			value.QuadPart = param.pFakeValues[cpuIdx];
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

	UINT32 cpuIdx = pVirtCpuInfo->otherInfo.cpuIdx;

	for (MsrHookParameter param : parameters)
	{
		//MSR Hook������MSR���ƥ���򱣴���ֵΪ��ƭֵ
		if (msrNum == param.msrNum && param.coreHookEnabled[cpuIdx])
		{
			LARGE_INTEGER value = {};
			value.LowPart = (UINT32)pGuestRegisters->rax;
			value.HighPart = (UINT32)pGuestRegisters->rdx;
			param.pFakeValues[cpuIdx] = value.QuadPart;
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

	//eaxΪ����MSR HOOK��CPUID���
	if (((int)pGuestRegisters->rax) == CONFIGURE_MSR_HOOK_CPUID_FUNCTION)
	{
		bool handled = false;
		MsrOperationParameter* pOptParam = (MsrOperationParameter*)pGuestRegisters->rdx;

		switch ((int)pGuestRegisters->rcx)
		{
		//rdx -> in/out MsrOperationParameter
		case READ_MSR_CPUID_SUBFUNCTION:
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
			��Щmsr�Ĵ�������VMCB���������Դ�VMCB�ж�ȡ
			����msr��ֱ�Ӷ�
			*/

			MsrHookParameter* pHookParameter = FindHookParameter(pOptParam->msrNum);

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
				//����ǵ�¼hook��msr�����guest msr��¼����ȡ��
				if (pHookParameter != NULL)
				{
					*pOptParam->pValueInOut = pHookParameter->pGuestRealValues[pVirtCpuInfo->otherInfo.cpuIdx];
				}
				//���MSR���û�еǼ�HOOK��ֱ������
				else
				{
					__debugbreak();
					KeBugCheck(MANUALLY_INITIATED_CRASH);
				}
				break;
			}

			pGuestRegisters->rip = pVirtCpuInfo->guestVmcb.controlFields.nRip;

			handled = true;

			break;
		}
		//rdx -> in/out MsrOperationParameter
		case WRITE_MSR_CPUID_SUBFUNCTION:
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
			��Щmsr�Ĵ�������VMCB����������ֱ��д��VMCB
			����msr��ֱ��д
			*/

			MsrHookParameter* pHookParameter = FindHookParameter(pOptParam->msrNum);

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
				//����ǵ�¼hook��msr����д��guest msr��¼���棬��vmm����ʱ��Ч
				if (pHookParameter != NULL)
				{
					pHookParameter->pGuestRealValues[pVirtCpuInfo->otherInfo.cpuIdx] = *pOptParam->pValueInOut;
				}
				//���MSR���û�еǼ�HOOK��ֱ������
				else
				{
					__debugbreak();
					KeBugCheck(MANUALLY_INITIATED_CRASH);
				}
				break;
			}

			pGuestRegisters->rip = pVirtCpuInfo->guestVmcb.controlFields.nRip;

			handled = true;

			break;
		}
		//rbx -> out CpuIdx
		case GET_CPU_IDX_CPUID_SUBFUNCTION:
		{
			//���ص�ǰCPU������
			pGuestRegisters->rbx = pVirtCpuInfo->otherInfo.cpuIdx;

			pGuestRegisters->rip = pVirtCpuInfo->guestVmcb.controlFields.nRip;

			handled = true;
			break;
		}
		default:
			break;
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
	locker.WriteLock();

	UINT32 cpuIdx;
	PTR_TYPE regs[4] = {};

	regs[0] = CONFIGURE_MSR_HOOK_CPUID_FUNCTION;
	regs[1] = 0;
	regs[2] = GET_CPU_IDX_CPUID_SUBFUNCTION;
	regs[3] = 0;

	SetRegsThenCpuid(&regs[0], &regs[1], &regs[2], &regs[3]);

	cpuIdx = (UINT32)regs[1];

	MsrOperationParameter optParam = {};

	for (MsrHookParameter& param : parameters)
	{
		if (param.msrNum == msrNum && !param.coreHookEnabled[cpuIdx])
		{
			optParam.msrNum = param.msrNum;

			optParam.pValueInOut = &param.pFakeValues[cpuIdx];

			regs[0] = CONFIGURE_MSR_HOOK_CPUID_FUNCTION;
			regs[1] = 0;
			regs[2] = READ_MSR_CPUID_SUBFUNCTION;
			regs[3] = (PTR_TYPE)&optParam;
			SetRegsThenCpuid(&regs[0], &regs[1], &regs[2], &regs[3]);

			optParam.pValueInOut = &realValue;

			regs[0] = CONFIGURE_MSR_HOOK_CPUID_FUNCTION;
			regs[1] = 0;
			regs[2] = WRITE_MSR_CPUID_SUBFUNCTION;
			regs[3] = (PTR_TYPE)&optParam;
			SetRegsThenCpuid(&regs[0], &regs[1], &regs[2], &regs[3]);

			param.coreHookEnabled[cpuIdx] = true;
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

	UINT32 cpuIdx;
	PTR_TYPE regs[4] = {};

	regs[0] = CONFIGURE_MSR_HOOK_CPUID_FUNCTION;
	regs[1] = 0;
	regs[2] = GET_CPU_IDX_CPUID_SUBFUNCTION;
	regs[3] = 0;

	SetRegsThenCpuid(&regs[0], &regs[1], &regs[2], &regs[3]);

	cpuIdx = (UINT32)regs[1];

	MsrOperationParameter optParam = {};

	for (MsrHookParameter& param : parameters)
	{
		if (param.msrNum == msrNum && param.coreHookEnabled[cpuIdx])
		{
			optParam.msrNum = param.msrNum;
			optParam.pValueInOut = &param.pFakeValues[cpuIdx];

			if (writeFakeValueToMsr)
			{
				regs[0] = CONFIGURE_MSR_HOOK_CPUID_FUNCTION;
				regs[1] = 0;
				regs[2] = WRITE_MSR_CPUID_SUBFUNCTION;
				regs[3] = (PTR_TYPE)&optParam;
				SetRegsThenCpuid(&regs[0], &regs[1], &regs[2], &regs[3]);
			}
			
			param.coreHookEnabled[cpuIdx] = false;
		}
	}

	locker.WriteUnlock();
}

template<SIZE_TYPE msrHookCount>
inline void MsrHookManager<msrHookCount>::LoadGuestMsrForCpu(UINT32 cpuIdx)
{
	for (MsrHookParameter& param : parameters)
	{
		if (param.pGuestRealValues != NULL)
			__writemsr(param.msrNum, param.pGuestRealValues[cpuIdx]);
	}
}

template<SIZE_TYPE msrHookCount>
inline void MsrHookManager<msrHookCount>::SaveGuestMsrForCpu(UINT32 cpuIdx)
{
	for (MsrHookParameter& param : parameters)
	{
		if (param.pGuestRealValues != NULL)
			param.pGuestRealValues[cpuIdx] = __readmsr(param.msrNum);
	}
}

template<SIZE_TYPE msrHookCount>
inline void MsrHookManager<msrHookCount>::LoadHostMsrForCpu(UINT32 cpuIdx)
{
	for (MsrHookParameter& param : parameters)
	{
		if (param.pHostRealValues != NULL)
			__writemsr(param.msrNum, param.pHostRealValues[cpuIdx]);
	}
}

template<SIZE_TYPE msrHookCount>
inline void MsrHookManager<msrHookCount>::SaveHostMsrForCpu(UINT32 cpuIdx)
{
	for (MsrHookParameter& param : parameters)
	{
		if (param.pHostRealValues != NULL)
			param.pHostRealValues[cpuIdx] = __readmsr(param.msrNum);
	}
}

//MSR_LSTAR HOOK ��������������HOOK
//����IA32_MSR_LSTAR HOOK ʹ��֮ǰ��Ҫ����MsrHookManager::SetHookMsrsע��IA32_MSR_LSTAR
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

	auto enableHook = [pMsrHookManager](UINT32 cpuIdx) -> NTSTATUS
		{
			UNREFERENCED_PARAMETER(cpuIdx);
			pMsrHookManager->EnableMsrHook(IA32_MSR_LSTAR, (PTR_TYPE)GetLStarHookEntry());
			return STATUS_SUCCESS;
		};

	RunOnEachCore(0, pMsrHookManager->cpuCnt, enableHook);
}

//MSR_LSTAR HOOK ��������������HOOK
#pragma code_seg("PAGE")
template<SIZE_TYPE msrCnt>
void DisableLStrHook(MsrHookManager<msrCnt>* pMsrHookManager)
{
	PAGED_CODE();

	auto disableHook = [pMsrHookManager](UINT32 cpuIdx) -> NTSTATUS
		{
			UNREFERENCED_PARAMETER(cpuIdx);
			pMsrHookManager->DisableMsrHook(IA32_MSR_LSTAR);
			return STATUS_SUCCESS;
		};

	RunOnEachCore(0, pMsrHookManager->cpuCnt, disableHook);
}

//ҳ��Level3��Сҳ�ļ�¼��������Ϊ0������Իָ���ҳ
struct SmallPageRecord
{
	//����level 1 2 3ƫ�Ƶĵ������ַ
	PTR_TYPE level3PhyAddr;
	PTR_TYPE refCnt;
	#pragma code_seg()
	SmallPageRecord() : level3PhyAddr(INVALID_ADDR), refCnt(0) {}

	DEFAULT_NONPAGED_COPY_AND_MOVE_FUNCTION_FOR_CLASS(SmallPageRecord)
};

//����ҳ�ļ�¼
struct SwapPageRecord
{
	//ԭʼҳ��������ַ
	PVOID pOriginVirtAddr;
	//ԭʼҳ��������ַ���������ֶ���Ϊ�˼���NPF�Ĵ���
	PTR_TYPE pOriginPhyAddr;
	//�滻ҳ��������ַ
	PVOID pSwapVirtAddr;
	//�滻ҳ��������ַ
	PTR_TYPE pSwapPhyAddr;
	//ʹ�ü���
	PTR_TYPE refCnt = 0;
	#pragma code_seg()
	SwapPageRecord() : pOriginVirtAddr(NULL), pOriginPhyAddr(INVALID_ADDR), pSwapVirtAddr(NULL), pSwapPhyAddr(INVALID_ADDR), refCnt(0) {}

	DEFAULT_NONPAGED_COPY_AND_MOVE_FUNCTION_FOR_CLASS(SwapPageRecord)
};

//hook��Ŀ��¼
struct NptHookRecord
{
	//hookԭʼ�����ַ
	PVOID pOriginVirtAddr;
	//hook����ת��ַ
	PVOID pGotoVirtAddr;
	#pragma code_seg()
	NptHookRecord() : pOriginVirtAddr(NULL), pGotoVirtAddr(NULL) {}

	DEFAULT_NONPAGED_COPY_AND_MOVE_FUNCTION_FOR_CLASS(NptHookRecord)
};

//ÿ�����ĵ�NPT HOOK״̬
struct NptHookStatus
{
	enum PremissionStatus
	{
		HookPageNotExecuted,
		HookPageExecuted
	};
	PremissionStatus premissionStatus;
	PTR_TYPE pLastActiveHookPageVirtAddr;
	//���ļ乲������ݵĿ�����ָ��7

	//���ļ乲������ݻ������ݣ�һ����NptHookManager�У���һ���������ָ��ָ��
	//�޸�HOOKʱ���ȸ���NptHookManager�е����ݣ��ٿ���һ��NptHookManager�У�����������ָ����µ����ָ���У�����������ָ���ֵָ�������
public:
#pragma code_seg()
	NptHookStatus() : premissionStatus(HookPageNotExecuted), pLastActiveHookPageVirtAddr(NULL) {}
};

//NPT HOOK ���ļ乲������ݣ���Ҫ��HOOK��¼��Сҳ��¼������ҳ��¼
class NptHookData
{
public:
	KernelVector<SmallPageRecord, HOOK_TAG> smallPageRecord;
	KernelVector<SwapPageRecord, HOOK_TAG> swapPageRecord;
	KernelVector<NptHookRecord, HOOK_TAG> hookRecords;
	NptHookStatus hookStatus;

	//ͨ��hook��ԭʼ�����ַ���Ҽ�¼��HookRecord��
	SIZE_TYPE FindHookRecordByOriginVirtAddr(PTR_TYPE pOriginAddr) const;
	//ͨ�������ַ��ֻ����Level 4 3 2����ƫ�ƣ�����Сҳ��¼��SmallPageLevel3RefCnt��
	SIZE_TYPE FindSmallPageLevel2RefCntByPhyAddr(PTR_TYPE phyAddr) const;
	//ͨ��hookԴ�����ַ���ҽ���ҳ��¼��SwapPageRefCnt��
	SIZE_TYPE FindSwapPageRefCntByOriginPhyAddr(PTR_TYPE phyAddr) const;
	//ͨ��hookԴ�����ַ���ҽ���ҳ��¼��SwapPageRefCnt��
	SIZE_TYPE FindSwapPageRefCntByOriginVirtAddr(PTR_TYPE pOriginAddr) const;
	//ͨ������ҳ�������ַ���ҽ�����¼��SwapPageRefCnt��
	SIZE_TYPE FindSwapPageRefCntBySwapVirtAddr(PTR_TYPE pSwapAddr) const;

	NptHookData() = default;
	~NptHookData() = default;

	DEFAULT_NONPAGED_COPY_AND_MOVE_FUNCTION_FOR_CLASS(NptHookData)
};

class NptHookManager : public IManager, public IBreakprointInterceptPlugin, public INpfInterceptPlugin
{
	//CPU������
	ULONG cpuCnt;
	//���ļ乲������
	KernelVector<NptHookData, HOOK_TAG> hookData;
	//�ⲿҳ���������ָ��
	PageTableManager pageTableManager1;
	//�ڲ�ҳ���������ÿ���������ڲ�ҳ����ⲿҳ��֮���л����ӿ�NPT HOOK���ٶ�
	PageTableManager pageTableManager2;

	//���hook
	NTSTATUS AddHookInSignleCore(const NptHookRecord& record, UINT32 idx);
	//ɾ��hook��pHookOriginVirtAddr��hookλ�õ������ַ
	NTSTATUS RemoveHookInSignleCore(PVOID pHookOriginVirtAddr, UINT32 idx);

	friend class FunctionInterface;

public:
	//����SVMManager
	void SetupSVMManager(SVMManager& svmManager);
	//HOOK ��ת
	virtual bool HandleBreakpoint(VirtCpuInfo* pVirtCpuInfo, GenericRegisters* pGuestRegisters,
		PVOID pGuestVmcbPhyAddr, PVOID pHostVmcbPhyAddr) override;
	//HOOKҳ��Ȩ���޸�
	virtual bool HandleNpf(VirtCpuInfo* pVirtCpuInfo, GenericRegisters* pGuestRegisters,
		PVOID pGuestVmcbPhyAddr, PVOID pHostVmcbPhyAddr) override;
	#pragma code_seg("PAGE")
	NptHookManager() : cpuCnt(0) { PAGED_CODE(); }
	//���hook
	NTSTATUS AddHook(const NptHookRecord& record);
	//ɾ��hook��pHookOriginVirtAddr��hookλ�õ������ַ
	NTSTATUS RemoveHook(PVOID pHookOriginVirtAddr);
	virtual NTSTATUS Init() override;
	virtual void Deinit() override;
	#pragma code_seg("PAGE")
	virtual ~NptHookManager() { PAGED_CODE(); Deinit(); }
};

class FunctionCallerManager : public IManager
{
	//ΪNPT HOOK��ת֮��ĺ�������һ�����Ե���ԭ�������ܵ�ָ���
	static PVOID AllocFunctionCallerForHook(PVOID pFunction);
	//�ͷ�ָ���
	static void FreeFunctionCallerForHook(PVOID pFunctionCaller);

	struct FunctionCallerItem
	{
		PVOID pSourceFunction;
		PVOID pFunctionCaller;

		#pragma code_seg()
		FunctionCallerItem() : pSourceFunction(NULL), pFunctionCaller(NULL) {}

		DEFAULT_NONPAGED_COPY_AND_MOVE_FUNCTION_FOR_CLASS(FunctionCallerItem)
	};

	KernelVector<FunctionCallerItem, HOOK_TAG> functionCallerItems;

	//������û���Ѿ������Caller�ڴ��
	SIZE_TYPE FindFunctionCallerItemBySourceFunction(PVOID pSourceFunction);

public:
	#pragma code_seg()
	FunctionCallerManager() : functionCallerItems() {}

	#pragma code_seg()
	virtual NTSTATUS Init() override { return STATUS_SUCCESS; }
	virtual void Deinit() override;
	#pragma code_seg()
	virtual ~FunctionCallerManager() { Deinit(); }

	PVOID GetFunctionCaller(PVOID pSourceFunction);
	void RemoveFunctionCaller(PVOID pSourceFunction);
};

#endif
