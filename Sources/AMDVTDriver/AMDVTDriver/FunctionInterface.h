#ifndef FUNCTION_INTERFACE_H
#define FUNCTION_INTERFACE_H

#include <ntifs.h>
#include <ntddk.h>
#include <wdm.h>
#include <stdio.h>
#include <intrin.h>
#include "SVM.h"
#include "Hook.h"
#include "PageTable.h"
#include "Basic.h"
#define NOT_DEFINE_PUBLIC_STRCUT
#define KERNEL_USAGE
#include "AMDVDriverSDK.h"

constexpr UINT32 FUNC_TAG = MAKE_TAG('f', 'u', 'n', 'c');

//某些操作在VMM里面容易导致系统崩溃卡死，VMM通过使用这个类把操作移动倒guest中执行

//执行流程
//VMM调用 DelayProcessInGuestFromVMM::DelayProcess 设置要执行的函数入口，参数，当前的guest寄存器状态
//这个函数会备份当前寄存器到DelayProcessInGuestFromVMM对象中，并将guest寄存器状态修改好以执行
//VMM直接返回，执行DelayProcessEntryInGuest，DelayProcessEntryInGuest结尾将调用DelayProcessInGuestFromVMM::CpuidHandler::HandleCpuid
//DelayProcessInGuestFromVMM::CpuidHandler::HandleCpuid将DelayProcessInGuestFromVMM中备份的寄存器值还原并退出
//返回原guest处执行

class DelayProcessInGuestFromVMM
{
	GenericRegisters originGuestRegs;
	VMCB vmcb;
	bool needRestoreVmcb;
	
	class CpuidHandler : public ICpuidInterceptPlugin
	{
		friend class DelayProcessInGuestFromVMM;
		ICpuidInterceptPlugin* pOldCpuidHandler;
	public:
		CpuidHandler() : pOldCpuidHandler(NULL) {}
		virtual bool HandleCpuid(VirtCpuInfo* pVirtCpuInfo, GenericRegisters* pGuestRegisters,
			PVOID pGuestVmcbPhyAddr, PVOID pHostVmcbPhyAddr) override;
	};

	static UINT8 signleObjMem[sizeof(CpuidHandler)];
	static bool isSignleObjInited;

public:
	#pragma code_seg("PGAE")
	DelayProcessInGuestFromVMM() : originGuestRegs({}), vmcb({}), needRestoreVmcb(false) { PAGED_CODE(); }
	#pragma code_seg("PGAE")
	~DelayProcessInGuestFromVMM() { PAGED_CODE(); }

	static CpuidHandler& GetCpuidHandler();

	//将寄存器还原以恢复在原guest位置执行
	void EndDelayProcessInternal(GenericRegisters& guestRegisters, VirtCpuInfo& virtCpuInfo);

public:

	typedef void(*ProcessorFunction)(PVOID param, DelayProcessInGuestFromVMM& delayProcessor);

	//添加新CPUID处理器
	static void AppendCpuidHandler(SVMManager& svmManager);

	//设置某个函数在guest中运行
	void BeginDelayProcess(ProcessorFunction func, PVOID param, GenericRegisters& guestRegisters, VirtCpuInfo* pVirtCpuInfo = NULL);
	
	//在处理器函数获取备份的寄存器值，用于处理器函数返回值写入
	#pragma code_seg()
	GenericRegisters& GetOriginRegs() { return originGuestRegs; }

	//在处理器函数中直接终止处理器函数的执行
	void EndDelayProcess();
};

struct ParamsStore
{
	PVOID param1;
	PVOID param2;
	PVOID param3;
	PVOID param4;
	PVOID pThis;
};

class FunctionInterface : public IManager, public ICpuidInterceptPlugin
{
	typedef NTSTATUS(NTAPI* PPsLookupProcessByProcessId)(HANDLE ProcessId, PEPROCESS* Process);

	SVMManager svmManager;
	NptHookManager nptHookManager;
	FunctionCallerManager functionCallerManager;
	MsrHookManager<1> msrHookManager;
	ICpuidInterceptPlugin* pOldCpuidHandler;
	KernelVector<DelayProcessInGuestFromVMM, FUNC_TAG> delayProcessors;
	KernelVector<ParamsStore, FUNC_TAG> stores;
	PPsLookupProcessByProcessId pPsLookupProcessByProcessId;

	friend void SetLStarCallbackInR3Processor(PVOID param, DelayProcessInGuestFromVMM& delayProcessor);
	friend void ResetLStarCallbackInR3Processor(PVOID param, DelayProcessInGuestFromVMM& delayProcessor);

	SetLStartCallbackParam lstarInfo;
	PEPROCESS pLstarCallbackProcess;

	static void NTAPI LStarHookCallback(GenericRegisters* pRegisters, PVOID param1, PVOID param2, PVOID param3);

public:
	#pragma code_seg("PAGE")
	FunctionInterface() : pOldCpuidHandler(NULL), pPsLookupProcessByProcessId(NULL), pLstarCallbackProcess(NULL), lstarInfo({}) {}

	//设置MSR HOOK参数
	void SetMsrHookParameters();
	//启用MSR HOOK
	void EnableMsrHook();
	//添加新CPUID处理器
	void AppendCpuidHandler();

	//处理拦截的cpuid指令，true代表已经处理，false代表未处理
	virtual bool HandleCpuid(VirtCpuInfo* pVirtCpuInfo, GenericRegisters* pGuestRegisters,
		PVOID pGuestVmcbPhyAddr, PVOID pHostVmcbPhyAddr) override;

	virtual NTSTATUS Init() override;
	virtual void Deinit() override;
	virtual ~FunctionInterface() { PAGED_CODE(); Deinit(); }
};

#endif // !FUNCTION_INTERFACE_H
