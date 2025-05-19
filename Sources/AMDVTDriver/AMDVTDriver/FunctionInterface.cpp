#include "FunctionInterface.h"
#include "UnpublicAPI.h"

constexpr UINT32 DELAY_PROCESS_END_CPUID_FUNCTION = 0x400000fd;

#pragma data_seg()
UINT8 DelayProcessInGuestFromVMM::signleObjMem[sizeof(DelayProcessInGuestFromVMM::CpuidHandler)] = {};
#pragma data_seg()
bool DelayProcessInGuestFromVMM::isSignleObjInited = false;

//这个函数用于DelayProcessInGuestFromVMM跳转处理器函数的入口点
//请不要在C/C++中直接调用这个函数，请见FunctionInterface_asm.asm中的定义
//这个函数不会ret，而是在结尾执行cpuid，直接调用将产生灾难性后果
extern "C" void DelayProcessEntryInGuest(DelayProcessInGuestFromVMM::ProcessorFunction func, PVOID param, DelayProcessInGuestFromVMM* obj);

#pragma code_seg("PAGE")
NTSTATUS FunctionInterface::Init()
{
	PAGED_CODE();
	
	int cpuCnt = KeQueryActiveProcessorCountEx(ALL_PROCESSOR_GROUPS);

	//按照CPU核心初始化延迟调用器和对应的参数
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
		//设置LSTAR HOOK 参数
		SetMsrHookParameters();

		//为延迟调用器注册CPUID Handler
		DelayProcessInGuestFromVMM::AppendCpuidHandler(svmManager);
		
		//为本对象注册CPUID Handler
		AppendCpuidHandler();

		//初始化NPT HOOK
		status = nptHookManager.Init();
		if (!NT_SUCCESS(status))
			break;
		
		//初始化MSR HOOK
		status = msrHookManager.Init();
		if (!NT_SUCCESS(status))
			break;
		
		//初始化函数HOOK管理器
		status = functionCallerManager.Init();
		if (!NT_SUCCESS(status))
			break;

		//将nptHookManager 和 svmManager 绑定
		nptHookManager.SetupSVMManager(svmManager);

		//进入虚拟化
		status = svmManager.Init();
		if (!NT_SUCCESS(status))
			break;

		//启用MSR HOOK
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
	//释放资源和退出虚拟化
	msrHookManager.Deinit();
	svmManager.Deinit();
	nptHookManager.Deinit();
	functionCallerManager.Deinit();
}

#pragma code_seg("PAGE")
void FunctionInterface::AppendCpuidHandler()
{
	PAGED_CODE();

	//防止重复添加
	if (svmManager.GetCpuidInterceptPlugin() == this)
		return;

	//记录上一个CPUID处理器，方便链式调用
	pOldCpuidHandler = svmManager.GetCpuidInterceptPlugin();

	//设置新的CPUID处理器
	svmManager.SetCpuIdInterceptPlugin(this);
}

#pragma code_seg("PAGE")
static void NewFunctionCallerProcessor(PVOID param, DelayProcessInGuestFromVMM& delayProcessor)
{
	PAGED_CODE();

	ParamsStore& store = *((ParamsStore*)param);
	GenericRegisters& regs = delayProcessor.GetOriginRegs();

	//调用FunctionCallerManager生成HOOK函数调用原函数的跳板机器码，并写入返回值
	regs.rbx = (PTR_TYPE)((FunctionCallerManager*)store.pThis)->GetFunctionCaller(store.param1);

	delayProcessor.EndDelayProcess();
}

#pragma code_seg("PAGE")
static void DelFunctionCallerProcessor(PVOID param, DelayProcessInGuestFromVMM& delayProcessor)
{
	PAGED_CODE();

	ParamsStore& store = *((ParamsStore*)param);

	//调用FunctionCallerManager删除跳板代码
	((FunctionCallerManager*)store.pThis)->RemoveFunctionCaller(store.param1);

	delayProcessor.EndDelayProcess();
}

#pragma code_seg("PAGE")
static void AddNptHookProcessor(PVOID param, DelayProcessInGuestFromVMM& delayProcessor)
{
	PAGED_CODE();

	ParamsStore& store = *((ParamsStore*)param);
	GenericRegisters& regs = delayProcessor.GetOriginRegs();
	
	//调用NptHookManager的AddHook方法添加内核NPT HOOK，并写入返回值
	regs.rbx = ((NptHookManager*)store.pThis)->AddHook(*((NptHookRecord*)store.param1)) == STATUS_SUCCESS;

	delayProcessor.EndDelayProcess();
}

#pragma code_seg("PAGE")
static void DelNptHookProcessor(PVOID param, DelayProcessInGuestFromVMM& delayProcessor)
{
	PAGED_CODE();

	ParamsStore& store = *((ParamsStore*)param);
	GenericRegisters& regs = delayProcessor.GetOriginRegs();

	//调用NptHookManager的RemoveHook方法删除内核NPT HOOK，并写入返回值
	regs.rbx = ((NptHookManager*)store.pThis)->RemoveHook(store.param1)
		== STATUS_SUCCESS;

	delayProcessor.EndDelayProcess();
}

#pragma code_seg("PAGE")
void SetLStarCallbackInR3Processor(PVOID param, DelayProcessInGuestFromVMM& delayProcessor)
{
	PAGED_CODE();

	ParamsStore& store = *((ParamsStore*)param);
	SetLStartCallbackParam& setLstarInfo = *((SetLStartCallbackParam*)store.param1);
	FunctionInterface& functionInterface = *((FunctionInterface*)store.pThis);
	GenericRegisters& regs = delayProcessor.GetOriginRegs();

	regs.rbx = 0;

	if (1)
	{
		regs.rbx = 1;
		functionInterface.pid = (UINT64)store.param2;
	}
	else
	{
		functionInterface.pid = -1LL;
		functionInterface.lstarInfo = {};
	}
	
	delayProcessor.EndDelayProcess();
}

#pragma code_seg("PAGE")
void ResetLStarCallbackInR3Processor(PVOID param, DelayProcessInGuestFromVMM& delayProcessor)
{
	PAGED_CODE();

	ParamsStore& store = *((ParamsStore*)param);
	FunctionInterface& functionInterface = *((FunctionInterface*)store.pThis);
	GenericRegisters& regs = delayProcessor.GetOriginRegs();

	functionInterface.lstarInfo = {};
	functionInterface.pid = -1LL;

	regs.rbx = 1;

	delayProcessor.EndDelayProcess();
}

#pragma code_seg()
bool FunctionInterface::HandleCpuid(VirtCpuInfo* pVirtCpuInfo, GenericRegisters* pGuestRegisters, PVOID pGuestVmcbPhyAddr, PVOID pHostVmcbPhyAddr)
{
	//比较CPUID Function是否是对应的CPUID Function
	if (pGuestRegisters->rax == CALL_FUNCTION_INTERFACE_CPUID_FUNCTION)
	{
		int cpuIdx = pVirtCpuInfo->otherInfo.cpuIdx;

		pGuestRegisters->rip = pVirtCpuInfo->guestVmcb.controlFields.nRip;

		//根据对应的功能设置Guest执行特定处理函数。并且在执行完处理函数之后恢复原Guest执行
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
			if (!(pVirtCpuInfo->guestVmcb.statusFields.rip & 0xffff000000000000))
			{
				//释放进程句柄
				if (pGuestRegisters->rdx == NULL)
				{
					stores[cpuIdx].pThis = (PVOID)this;
					delayProcessors[cpuIdx].BeginDelayProcess(ResetLStarCallbackInR3Processor, 0, *pGuestRegisters, pVirtCpuInfo);
				}
				else
				{
					stores[cpuIdx].param1 = (PVOID)pGuestRegisters->rdx;
					stores[cpuIdx].param2 = (PVOID)pGuestRegisters->rbx;
					stores[cpuIdx].pThis = (PVOID)this;

					delayProcessors[cpuIdx].BeginDelayProcess(SetLStarCallbackInR3Processor, &stores[cpuIdx], *pGuestRegisters, pVirtCpuInfo);
				}
			}
			else
			{
				if (pGuestRegisters->rdx == NULL)
				{
					lstarInfo = {};
					pid = -1LL;
				}
				else
				{
					lstarInfo = *((const SetLStartCallbackParam*)pGuestRegisters->rdx);
					pid = -1LL;
				}
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

	if (functionInterface.lstarInfo.callback != NULL)
	{
		if (functionInterface.pid == -1)
		{
			functionInterface.lstarInfo.callback(*pRegisters, *pStackDump, (UINT64)PsGetCurrentProcessId(), functionInterface.lstarInfo.param);
		}
		else
		{

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
	//比较CPUID Function是否是对应的Function
	if (pGuestRegisters->rax == DELAY_PROCESS_END_CPUID_FUNCTION)
	{
		//还原Guest状态。恢复Guest执行
		((DelayProcessInGuestFromVMM*)pGuestRegisters->rcx)->EndDelayProcessInternal(*pGuestRegisters, *pVirtCpuInfo);
		return true;
	}

	return pOldCpuidHandler->HandleCpuid(pVirtCpuInfo, pGuestRegisters, pGuestVmcbPhyAddr, pHostVmcbPhyAddr);
}

#pragma code_seg("PAGE")
void DelayProcessInGuestFromVMM::AppendCpuidHandler(SVMManager& svmManager)
{
	PAGED_CODE();

	//同上一个AppendCpuidHandler函数
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

		//如果调用方来自R3。执行额外的R3向R0的切换步骤
		if (!IsKernelAddress((PVOID)guestRegisters.rip))
		{
			GenericRegisters genericRegs = {};

			_save_or_load_regs(&genericRegs);

			genericRegs.extraInfo1 = 0;
			genericRegs.extraInfo2 = 0;

			genericRegs.rflags |= (1ULL << EFLAGS_IF_OFFSET);

			SAVE_GUEST_STATUS_FROM_REGS(pVirtCpuInfo, genericRegs.rax, genericRegs.rflags, guestRegisters.rsp, guestRegisters.rip);
			
			guestRegisters = genericRegs;
		}

		//设置执行新入口函数
		guestRegisters.rcx = (PTR_TYPE)func;
		guestRegisters.rdx = (PTR_TYPE)param;
		guestRegisters.r8 = (PTR_TYPE)this;
		guestRegisters.rsp = (PTR_TYPE)pVirtCpuInfo->stack2 + sizeof pVirtCpuInfo->stack2;
		guestRegisters.rip = (PTR_TYPE)DelayProcessEntryInGuest;;

		needRestoreVmcb = true;
	}
}

#pragma code_seg()
void DelayProcessInGuestFromVMM::EndDelayProcess()
{
	PTR_TYPE regs[4] = {};

	//调用DelayProcessInGuextFromVMM内部的CPUID 处理器恢复Guest执行
	regs[0] = DELAY_PROCESS_END_CPUID_FUNCTION;
	regs[1] = 0;
	regs[2] = (PTR_TYPE)this;
	regs[3] = 0;

	SetRegsThenCpuid(&regs[0], &regs[1], &regs[2], &regs[3]);
}

#pragma code_seg("PAGE")
DelayProcessInGuestFromVMM::CpuidHandler& DelayProcessInGuestFromVMM::GetCpuidHandler()
{
	PAGED_CODE();

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
		//恢复Guest状态
		virtCpuInfo.guestVmcb = vmcb;

		guestRegisters = originGuestRegs;

		if (!IsKernelAddress((PVOID)originGuestRegs.rip))
			virtCpuInfo.guestVmcb.statusFields.cpl = 3;

		needRestoreVmcb = false;
	}
}