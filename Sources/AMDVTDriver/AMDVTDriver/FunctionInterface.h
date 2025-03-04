#ifndef FUNCTION_INTERFACE_H
#define FUNCTION_INTERFACE_H

#include <ntddk.h>
#include <wdm.h>
#include <stdio.h>
#include <intrin.h>
#include "SVM.h"
#include "Hook.h"
#include "PageTable.h"
#include "Basic.h"

constexpr UINT32 FUNC_TAG = MAKE_TAG('f', 'u', 'n', 'c');

//某些操作在VMM里面容易导致系统崩溃卡死，VMM通过使用这个类把操作移动倒guest中执行

//执行流程
//VMM调用 DelayProcessInGuestFromVMM::DelayProcess 设置要执行的函数入口，参数，当前的guest寄存器状态
//这个函数会备份当前寄存器到DelayProcessInGuestFromVMM对象中，并将guest寄存器状态修改好以执行
//VMM直接返回，执行DelayProcessEntryInGuest，DelayProcessEntryInGuest结尾将调用DelayProcessInGuestFromVMM::CpuidHandler::HandleCpuid
//DelayProcessInGuestFromVMM::CpuidHandler::HandleCpuid将elayProcessInGuestFromVMM中备份的寄存器值还原并退出
//返回原guest处执行

class DelayProcessInGuestFromVMM
{
	GenericRegisters originGuestRegs;

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

	static CpuidHandler& GetCpuidHandler();

	//将寄存器还原以恢复在原guest位置执行
	void EndDelayProcessInternal(GenericRegisters & guestRegisters);

public:

	typedef void(*ProcessorFunction)(PVOID param, DelayProcessInGuestFromVMM& delayProcessor);

	DelayProcessInGuestFromVMM() : originGuestRegs({}) {}
	static void AppendCpuidHandler(SVMManager& svmManager);

	//设置某个函数在guest中运行
	void BeginDelayProcess(ProcessorFunction func, PVOID param, GenericRegisters& guestRegisters);

	#pragma code_seg()
	GenericRegisters& GetOriginRegs() { return originGuestRegs; }

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
	SVMManager svmManager;
	NptHookManager nptHookManager;
	FunctionCallerManager functionCallerManager;
	MsrHookManager<1> msrHookManager;
	ICpuidInterceptPlugin* pOldCpuidHandler;
	KernelVector<DelayProcessInGuestFromVMM, FUNC_TAG, MemType::NonPaged> delayProcessors;
	KernelVector<ParamsStore, FUNC_TAG, MemType::NonPaged> stores;

	static void NTAPI LStarHookCallback(GenericRegisters* pRegisters, PVOID param1, PVOID param2, PVOID param3);
public:
	#pragma code_seg("PAGE")
	FunctionInterface() : pOldCpuidHandler(NULL) {}

	void SetMsrHookParameters();
	void EnableMsrHook();
	void AppendCpuidHandler();

	//处理拦截的cpuid指令，true代表已经处理，false代表未处理
	virtual bool HandleCpuid(VirtCpuInfo* pVirtCpuInfo, GenericRegisters* pGuestRegisters,
		PVOID pGuestVmcbPhyAddr, PVOID pHostVmcbPhyAddr) override;

	virtual NTSTATUS Init() override;
	virtual void Deinit() override;
	virtual ~FunctionInterface() { PAGED_CODE(); Deinit(); }
};

#endif // !FUNCTION_INTERFACE_H

