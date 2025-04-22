#include "FunctionInterface.h"

constexpr UINT32 DELAY_PROCESS_END_CPUID_FUNCTION = 0x400000fd;

#pragma data_seg()
UINT8 DelayProcessInGuestFromVMM::signleObjMem[sizeof(DelayProcessInGuestFromVMM::CpuidHandler)] = {};
#pragma data_seg()
bool DelayProcessInGuestFromVMM::isSignleObjInited = false;

//请不要在C/C++中直接调用这个函数，请见FunctionInterface_asm.asm中的定义
//这个函数不会ret，而是在结尾执行cpuid，直接调用将产生灾难性后果
extern "C" void DelayProcessEntryInGuest(DelayProcessInGuestFromVMM::ProcessorFunction func, PVOID param, DelayProcessInGuestFromVMM* obj);

#pragma code_seg("PAGE")
NTSTATUS FunctionInterface::Init()
{
	PAGED_CODE();

	UNICODE_STRING unicodeString = {};
	
	RtlInitUnicodeString(&unicodeString, L"PsLookupProcessByProcessId");

	pPsLookupProcessByProcessId = (PPsLookupProcessByProcessId)MmGetSystemRoutineAddress(&unicodeString);
	if (pPsLookupProcessByProcessId == NULL)
		return STATUS_DRIVER_ENTRYPOINT_NOT_FOUND;

	int cpuCnt = KeQueryActiveProcessorCountEx(ALL_PROCESSOR_GROUPS);

	delayProcessors.SetCapacity(cpuCnt);
	stores.SetCapacity(cpuCnt);

	for (SIZE_TYPE idx = 0; idx < cpuCnt; ++idx)
	{
		delayProcessors.PushBack(DelayProcessInGuestFromVMM());
		stores.PushBack(ParamsStore());
	}
	
	NTSTATUS status = STATUS_SUCCESS;
	do
	{
		SetMsrHookParameters();

		DelayProcessInGuestFromVMM::AppendCpuidHandler(svmManager);
		
		AppendCpuidHandler();

		status = nptHookManager.Init();
		if (!NT_SUCCESS(status))
			break;
		
		status = msrHookManager.Init();
		if (!NT_SUCCESS(status))
			break;
		
		status = functionCallerManager.Init();
		if (!NT_SUCCESS(status))
			break;

		nptHookManager.SetupSVMManager(svmManager);

		status = svmManager.Init();
		if (!NT_SUCCESS(status))
			break;

		EnableMsrHook();

	} while (false);

	if (!NT_SUCCESS(status))
		Deinit();
	
	return status;
}

#pragma code_seg("PAGE")
void FunctionInterface::Deinit()
{
	PAGED_CODE();
	msrHookManager.Deinit();
	svmManager.Deinit();
	nptHookManager.Deinit();
	functionCallerManager.Deinit();
}

#pragma code_seg("PAGE")
void FunctionInterface::AppendCpuidHandler()
{
	if (svmManager.GetCpuidInterceptPlugin() == this)
		return;

	pOldCpuidHandler = svmManager.GetCpuidInterceptPlugin();
	svmManager.SetCpuIdInterceptPlugin(this);
}

#pragma code_seg()
static void NewFunctionCallerProcessor(PVOID param, DelayProcessInGuestFromVMM& delayProcessor)
{
	ParamsStore& store = *((ParamsStore*)param);
	GenericRegisters& regs = delayProcessor.GetOriginRegs();

	regs.rbx = (PTR_TYPE)((FunctionCallerManager*)store.pThis)->GetFunctionCaller(store.param1);

	delayProcessor.EndDelayProcess();
}

#pragma code_seg()
static void DelFunctionCallerProcessor(PVOID param, DelayProcessInGuestFromVMM& delayProcessor)
{
	ParamsStore& store = *((ParamsStore*)param);

	((FunctionCallerManager*)store.pThis)->RemoveFunctionCaller(store.param1);

	delayProcessor.EndDelayProcess();
}

#pragma code_seg()
static void AddNptHookProcessor(PVOID param, DelayProcessInGuestFromVMM& delayProcessor)
{
	ParamsStore& store = *((ParamsStore*)param);
	GenericRegisters& regs = delayProcessor.GetOriginRegs();
	
	regs.rbx = ((NptHookManager*)store.pThis)->AddHook(*((NptHookRecord*)store.param1)) == STATUS_SUCCESS;

	delayProcessor.EndDelayProcess();
}

#pragma code_seg()
static void DelNptHookProcessor(PVOID param, DelayProcessInGuestFromVMM& delayProcessor)
{
	ParamsStore& store = *((ParamsStore*)param);

	((NptHookManager*)store.pThis)->RemoveHook(store.param1);

	delayProcessor.EndDelayProcess();
}

#pragma code_seg()
void SetLStarCallbackInR3Processor(PVOID param, DelayProcessInGuestFromVMM& delayProcessor)
{
	ParamsStore& store = *((ParamsStore*)param);

	const SetLStartCallbackParam& setLstarInfo = *((SetLStartCallbackParam*)store.param1);

	FunctionInterface& functionInterface = *((FunctionInterface*)store.pThis);

	if (functionInterface.pPsLookupProcessByProcessId(PsGetCurrentProcessId(), &functionInterface.lstarInfo.pEprocess) == STATUS_SUCCESS)
	{
		functionInterface.lstarInfo.pCallback = setLstarInfo.callback;
		functionInterface.lstarInfo.param = setLstarInfo.param;
	}
	
	delayProcessor.EndDelayProcess();
}

#pragma code_seg()
void ResetLStarCallbackProcessor(PVOID param, DelayProcessInGuestFromVMM& delayProcessor)
{
	ParamsStore& store = *((ParamsStore*)param);
	FunctionInterface& functionInterface = *((FunctionInterface*)store.pThis);

	ObDereferenceObject(functionInterface.lstarInfo.pEprocess);
 	functionInterface.lstarInfo.pEprocess = NULL;
	functionInterface.lstarInfo.pCallback = NULL;
	functionInterface.lstarInfo.param = NULL;

	delayProcessor.EndDelayProcess();
}

#pragma code_seg()
bool FunctionInterface::HandleCpuid(VirtCpuInfo* pVirtCpuInfo, GenericRegisters* pGuestRegisters, PVOID pGuestVmcbPhyAddr, PVOID pHostVmcbPhyAddr)
{
	if (pGuestRegisters->rax == CALL_FUNCTION_INTERFACE_CPUID_FUNCTION)
	{
		if (pVirtCpuInfo->guestVmcb.statusFields.cpl != 0)
			return false;
		
		int cpuIdx = pVirtCpuInfo->otherInfo.cpuIdx;

		pGuestRegisters->rip = pVirtCpuInfo->guestVmcb.controlFields.nRip;

		switch (pGuestRegisters->rcx)
		{
		case NEW_FUNCTION_CALLER_CPUID_SUBFUNCTION:
		{
			stores[cpuIdx].pThis = &functionCallerManager;
			stores[cpuIdx].param1 = (PVOID)pGuestRegisters->rdx;
			delayProcessors[cpuIdx].BeginDelayProcess(NewFunctionCallerProcessor, &stores[cpuIdx], *pGuestRegisters);
			return true;
		}
		case DEL_FUNCTION_CALLER_CPUID_SUBFUNCTION:
		{
			stores[cpuIdx].pThis = &functionCallerManager;
			stores[cpuIdx].param1 = (PVOID)pGuestRegisters->rdx;
			delayProcessors[cpuIdx].BeginDelayProcess(DelFunctionCallerProcessor, &stores[cpuIdx], *pGuestRegisters);
			return true;
		}
		case ADD_NPT_HOOK_CPUID_SUBFUNCTION:
		{
			stores[cpuIdx].pThis = &nptHookManager;
			stores[cpuIdx].param1 = (PVOID)pGuestRegisters->rdx;
			delayProcessors[cpuIdx].BeginDelayProcess(AddNptHookProcessor, &stores[cpuIdx], *pGuestRegisters);
			return true;
		}
		case DEL_NPT_HOOK_CPUID_SUBFUNCTION:
		{
			stores[cpuIdx].pThis = &nptHookManager;
			stores[cpuIdx].param1 = (PVOID)pGuestRegisters->rdx;
			delayProcessors[cpuIdx].BeginDelayProcess(DelNptHookProcessor, &stores[cpuIdx], *pGuestRegisters);
			return true;
		}
		case SET_SYSCALL_HOOK_CALLBACK_CPUID_SUBFUNCION:
		{
			if (KeGetCurrentIrql() > PASSIVE_LEVEL)
			{
				pGuestRegisters->rbx = 0;
				return true;
			}

			if (!(pVirtCpuInfo->guestVmcb.statusFields.rip & 0xffff000000000000))
			{
				//释放进程句柄
				if (pGuestRegisters->rdx == NULL && lstarInfo.pEprocess != NULL)
				{
					stores[cpuIdx].pThis = (PVOID)this;
					delayProcessors[cpuIdx].BeginDelayProcess(ResetLStarCallbackProcessor, 0, *pGuestRegisters, pVirtCpuInfo);
				}
				else
				{
					stores[cpuIdx].param1 = (PVOID)pGuestRegisters->rdx;
					stores[cpuIdx].param2 = (PVOID)pVirtCpuInfo;
					stores[cpuIdx].pThis = (PVOID)this;

					delayProcessors[cpuIdx].BeginDelayProcess(SetLStarCallbackInR3Processor, &stores[cpuIdx], *pGuestRegisters, pVirtCpuInfo);
				}
			}
			else
			{
				if (pGuestRegisters->rdx == NULL)
				{
					lstarInfo.pEprocess = NULL;
					lstarInfo.pCallback = NULL;
					lstarInfo.param = NULL;
					return true;
				}

				const SetLStartCallbackParam& param = *((const SetLStartCallbackParam*)pGuestRegisters->rdx);

				lstarInfo.pEprocess = NULL;
				lstarInfo.pCallback = param.callback;
				lstarInfo.param = param.param;
			}

			return true;
		}
		default:
			return false;
		}
	}

	return pOldCpuidHandler->HandleCpuid(pVirtCpuInfo, pGuestRegisters, pGuestVmcbPhyAddr, pHostVmcbPhyAddr);
}

#pragma code_seg("PAGE")
void FunctionInterface::EnableMsrHook()
{
	PAGED_CODE();

	//HOOK MSR_LSTAR
	EnableLStrHook<1>(&msrHookManager, LStarHookCallback, (PVOID)this, (PVOID)0, (PVOID)0);
}

#pragma code_seg()
void FunctionInterface::LStarHookCallback(GenericRegisters* pRegisters, PVOID param1, PVOID param2, PVOID param3)
{
	UNREFERENCED_PARAMETER(param2);
	UNREFERENCED_PARAMETER(param3);

	FunctionInterface& functionInterface = *(FunctionInterface*)param1;
	StackDump* pStackDump = (StackDump*)pRegisters->rsp;

	if (functionInterface.lstarInfo.pCallback != NULL)
	{
		if (functionInterface.lstarInfo.pEprocess == NULL)
		{
			functionInterface.lstarInfo.pCallback(*pRegisters, *pStackDump, (UINT64)PsGetCurrentProcessId(), functionInterface.lstarInfo.param);
		}
		else
		{
			PEPROCESS process = NULL;
			NTSTATUS status = PsLookupProcessByProcessId(PsGetCurrentThreadId(), &process);
			
			if (NT_SUCCESS(status))
			{
				StackDump stackDumpCopy = {};

				RtlCopyMemory((PVOID)&stackDumpCopy, pStackDump, sizeof(StackDump));
				
				functionInterface.lstarInfo.pCallback(*pRegisters, stackDumpCopy, (UINT64)PsGetCurrentProcessId(), functionInterface.lstarInfo.param);
			}
		}
	}
}

#pragma code_seg("PAGE")
void FunctionInterface::SetMsrHookParameters()
{
	PAGED_CODE();

	//设置要hook的msr
	//Hook IA32_MSR_LSTAR
	UINT32 msrNums[1] = { IA32_MSR_LSTAR };
	msrHookManager.SetHookMsrs(msrNums);

	//和SVMManager绑定
	svmManager.SetCpuIdInterceptPlugin(&msrHookManager);
	svmManager.SetMsrInterceptPlugin(&msrHookManager);
	svmManager.SetMsrBackupRestorePlugin(&msrHookManager);
}

#pragma code_seg()
bool DelayProcessInGuestFromVMM::CpuidHandler::HandleCpuid(VirtCpuInfo* pVirtCpuInfo, GenericRegisters* pGuestRegisters, PVOID pGuestVmcbPhyAddr, PVOID pHostVmcbPhyAddr)
{
	if (pGuestRegisters->rax == DELAY_PROCESS_END_CPUID_FUNCTION)
	{
		((DelayProcessInGuestFromVMM*)pGuestRegisters->rcx)->EndDelayProcessInternal(*pGuestRegisters, *pVirtCpuInfo);
		return true;
	}

	return pOldCpuidHandler->HandleCpuid(pVirtCpuInfo, pGuestRegisters, pGuestVmcbPhyAddr, pHostVmcbPhyAddr);
}

#pragma code_seg("PAGE")
void DelayProcessInGuestFromVMM::AppendCpuidHandler(SVMManager& svmManager)
{
	if (svmManager.GetCpuidInterceptPlugin() == &GetCpuidHandler())
		return;

	GetCpuidHandler().pOldCpuidHandler = svmManager.GetCpuidInterceptPlugin();
	svmManager.SetCpuIdInterceptPlugin(&GetCpuidHandler());
}

#pragma code_seg()
void DelayProcessInGuestFromVMM::BeginDelayProcess(ProcessorFunction func, PVOID param, GenericRegisters& guestRegisters, VirtCpuInfo* pVirtCpuInfo)
{
	if (pVirtCpuInfo != NULL)
	{
		//备份vmcb
		vmcb = pVirtCpuInfo->guestVmcb;

		//备份额外寄存器
		originGuestRegs = guestRegisters;
		
		//设置回调执行环境
		guestRegisters.extraInfo1 = 0;
		guestRegisters.extraInfo2 = 0;

		guestRegisters.rcx = (PTR_TYPE)func;
		guestRegisters.rdx = (PTR_TYPE)param;
		guestRegisters.r8 = (PTR_TYPE)this;
		guestRegisters.rsp = (PTR_TYPE)pVirtCpuInfo->stack + PAGE_SIZE;

		guestRegisters.rip = (PTR_TYPE)DelayProcessEntryInGuest;

		pVirtCpuInfo->guestVmcb.controlFields.nRip = guestRegisters.rip;

		needRestoreVmcb = true;
	}
}

#pragma code_seg()
void DelayProcessInGuestFromVMM::EndDelayProcess()
{
	PTR_TYPE regs[4] = {};

	regs[0] = DELAY_PROCESS_END_CPUID_FUNCTION;
	regs[1] = 0;
	regs[2] = (PTR_TYPE)this;
	regs[3] = 0;

	SetRegsThenCpuid(&regs[0], &regs[1], &regs[2], &regs[3]);
}

#pragma code_seg("PAGE")
DelayProcessInGuestFromVMM::CpuidHandler& DelayProcessInGuestFromVMM::GetCpuidHandler()
{
	if (!isSignleObjInited)
	{
		CallConstructor((CpuidHandler*)signleObjMem);
		isSignleObjInited = true;
	}

	return *((CpuidHandler*)signleObjMem);
}

#pragma code_seg()
void DelayProcessInGuestFromVMM::EndDelayProcessInternal(GenericRegisters& guestRegisters, VirtCpuInfo& virtCpuInfo)
{
	if (needRestoreVmcb)
	{
		virtCpuInfo.guestVmcb = vmcb;

		PTR_TYPE ripBackup = guestRegisters.rip;

		guestRegisters = originGuestRegs;

		virtCpuInfo.guestVmcb.controlFields.nRip = originGuestRegs.rip;

		guestRegisters.rip = ripBackup;

		needRestoreVmcb = false;
	}
}