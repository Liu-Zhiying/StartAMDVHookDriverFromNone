#include "FunctionInterface.h"

constexpr UINT32 DELAY_PROCESS_END_CPUID_FUNCTION = 0x400000fd;

#pragma data_seg()
UINT8 DelayProcessInGuestFromVMM::signleObjMem[sizeof(DelayProcessInGuestFromVMM::CpuidHandler)] = {};
#pragma data_seg()
bool DelayProcessInGuestFromVMM::isSignleObjInited = false;

//这个函数用于DelayProcessInGuestFromVMM跳转处理器函数的入口点
//请不要在C/C++中直接调用这个函数，请见FunctionInterface_asm.asm中的定义
//这个函数不会ret，而是在结尾执行cpuid，直接调用将产生灾难性后果
extern "C" void DelayProcessEntryInGuest(DelayProcessInGuestFromVMM::ProcessorFunction func, PVOID param, DelayProcessInGuestFromVMM* obj);

typedef PVOID(*PUserFunction)(PVOID param);

extern "C" PVOID CallUserFunctionFromKernelEntry(PVOID userRsp, PUserFunction userFunction, PVOID param);

#pragma code_seg("PAGED")
void ChangePageAccessForUser(PTR_TYPE virtAddr, bool canUserAccess)
{
	PageTableLevel4* pTopPageTable = NULL;
	GetSysPXEVirtAddr((PTR_TYPE*)&pTopPageTable, __readcr3());

	UINT16 index1 = (virtAddr >> 39) & 0x1ff;
	UINT16 index2 = (virtAddr >> 30) & 0x1ff;
	UINT16 index3 = (virtAddr >> 21) & 0x1ff;
	UINT16 index4 = (virtAddr >> 12) & 0x1ff;
	
	PHYSICAL_ADDRESS phyAddr = {};
	phyAddr.QuadPart = pTopPageTable[(virtAddr >> 39) & 0x1ff].entries->fields.pagePpn;
	PageTableLevel123* pPageTable = (PageTableLevel123*)MmGetVirtualForPhysical(phyAddr);

	for (int i = 3; i > 1; --i)
	{
	 	phyAddr.QuadPart = pPageTable[(virtAddr >> (((i - 1) * 9) + 12)) & 0x1ff].entries->fields.pagePpn;
		pPageTable = (PageTableLevel123*)MmGetVirtualForPhysical(phyAddr);
	}

	pPageTable[(virtAddr >> 12) & 0x1ff].entries->fields.userAccess = canUserAccess;
};

#pragma code_seg("PAGED")
PVOID CallUserFunctionFromKernel(PUserFunction userFunction, PVOID param, bool& isSuccess)
{
	isSuccess = false;

	PageTableLevel4* pTopPageTable = NULL;
	GetSysPXEVirtAddr((PTR_TYPE*)&pTopPageTable, __readcr3());

	for (SIZE_TYPE idx = 0; idx < 0x100; ++idx)
		pTopPageTable[idx].entries->fields.executionDisabled = false;

	PVOID userRsp = AllocPagedMem(PAGE_SIZE * 256, FUNC_TAG);

	if (userRsp == NULL)
		return NULL;

	for (int i = 0; i < 256; ++i)
		ChangePageAccessForUser((PTR_TYPE)userRsp + i * PAGE_SIZE, true);

	PVOID result = CallUserFunctionFromKernelEntry((PVOID)((PTR_TYPE)userRsp + 256 * PAGE_SIZE), userFunction, param);

	isSuccess = true;

	for (int i = 0; i < 256; ++i)
		ChangePageAccessForUser((PTR_TYPE)userRsp + i * PAGE_SIZE, false);

	FreePagedMem(userRsp, FUNC_TAG);

	for (SIZE_TYPE idx = 0; idx < 0x100; ++idx)
		pTopPageTable[idx].entries->fields.executionDisabled = true;

	return result;
}

#pragma code_seg("PAGE")
NTSTATUS CopyUserDataToKernel(PVOID pUserData, SIZE_TYPE dataLength, PVOID kernelBuffer)
{
	NTSTATUS ntStatus = STATUS_SUCCESS;
	PMDL mdl = NULL;
	bool needUnlockPage = false;

	do
	{
		mdl = IoAllocateMdl(pUserData, (ULONG)dataLength, FALSE, TRUE, NULL);

		if (!mdl)
		{
			ntStatus = STATUS_INSUFFICIENT_RESOURCES;
			break;
		}

		__try
		{
			MmProbeAndLockPages(mdl, UserMode, IoReadAccess);
			needUnlockPage = true;
		}
		__except (EXCEPTION_EXECUTE_HANDLER)
		{
			ntStatus = GetExceptionCode();
		}

		if (!needUnlockPage)
			break;

		PVOID buffer = MmGetSystemAddressForMdlSafe(mdl, NormalPagePriority | MdlMappingNoExecute);

		if (!buffer) {
			ntStatus = STATUS_INSUFFICIENT_RESOURCES;
			break;
		}

		RtlCopyMemory(kernelBuffer, buffer, dataLength);

	} while (false);

	if (needUnlockPage)
		MmUnlockPages(mdl);

	if (mdl != NULL)
		IoFreeMdl(mdl);

	return ntStatus;
}

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
	//防止重复添加
	if (svmManager.GetCpuidInterceptPlugin() == this)
		return;

	//记录上一个CPUID处理器，方便链式调用
	pOldCpuidHandler = svmManager.GetCpuidInterceptPlugin();

	//设置新的CPUID处理器
	svmManager.SetCpuIdInterceptPlugin(this);
}

#pragma code_seg()
static void NewFunctionCallerProcessor(PVOID param, DelayProcessInGuestFromVMM& delayProcessor)
{
	ParamsStore& store = *((ParamsStore*)param);
	GenericRegisters& regs = delayProcessor.GetOriginRegs();

	//调用FunctionCallerManager生成HOOK函数调用原函数的跳板机器码，并写入返回值
	regs.rbx = (PTR_TYPE)((FunctionCallerManager*)store.pThis)->GetFunctionCaller(store.param1);

	delayProcessor.EndDelayProcess();
}

#pragma code_seg()
static void DelFunctionCallerProcessor(PVOID param, DelayProcessInGuestFromVMM& delayProcessor)
{
	ParamsStore& store = *((ParamsStore*)param);

	//调用FunctionCallerManager删除跳板代码
	((FunctionCallerManager*)store.pThis)->RemoveFunctionCaller(store.param1);

	delayProcessor.EndDelayProcess();
}

#pragma code_seg()
static void AddNptHookProcessor(PVOID param, DelayProcessInGuestFromVMM& delayProcessor)
{
	ParamsStore& store = *((ParamsStore*)param);
	GenericRegisters& regs = delayProcessor.GetOriginRegs();
	
	//调用NptHookManager的AddHook方法添加内核NPT HOOK，并写入返回值
	regs.rbx = ((NptHookManager*)store.pThis)->AddHook(*((NptHookRecord*)store.param1)) == STATUS_SUCCESS;

	delayProcessor.EndDelayProcess();
}

#pragma code_seg()
static void DelNptHookProcessor(PVOID param, DelayProcessInGuestFromVMM& delayProcessor)
{
	ParamsStore& store = *((ParamsStore*)param);
	GenericRegisters& regs = delayProcessor.GetOriginRegs();

	//调用NptHookManager的RemoveHook方法删除内核NPT HOOK，并写入返回值
	regs.rbx = ((NptHookManager*)store.pThis)->RemoveHook(store.param1)
		== STATUS_SUCCESS;

	delayProcessor.EndDelayProcess();
}

#pragma code_seg()
void SetLStarCallbackInR3Processor(PVOID param, DelayProcessInGuestFromVMM& delayProcessor)
{
	ParamsStore& store = *((ParamsStore*)param);
	SetLStartCallbackParam& setLstarInfo = *((SetLStartCallbackParam*)store.param1);
	FunctionInterface& functionInterface = *((FunctionInterface*)store.pThis);
	GenericRegisters& regs = delayProcessor.GetOriginRegs();

	regs.rbx = 0;

	if (functionInterface.pPsLookupProcessByProcessId(store.param2, &functionInterface.pLstarCallbackProcess) == STATUS_SUCCESS)
	{
		KAPC_STATE state = {};
		KeStackAttachProcess(functionInterface.pLstarCallbackProcess, &state);

		if (PsGetCurrentProcess() == functionInterface.pLstarCallbackProcess)
		{
			if (NT_SUCCESS(CopyUserDataToKernel(&setLstarInfo, sizeof setLstarInfo, &functionInterface.lstarInfo)))
			{
				regs.rbx = 1;
			}
			else
			{
				ObDereferenceObject(functionInterface.pLstarCallbackProcess);
				functionInterface.pLstarCallbackProcess = NULL;
				functionInterface.lstarInfo = {};
			}

			KeUnstackDetachProcess(&state);
		}
	}
	
	delayProcessor.EndDelayProcess();
}

#pragma code_seg()
void ResetLStarCallbackInR3Processor(PVOID param, DelayProcessInGuestFromVMM& delayProcessor)
{
	ParamsStore& store = *((ParamsStore*)param);
	FunctionInterface& functionInterface = *((FunctionInterface*)store.pThis);
	GenericRegisters& regs = delayProcessor.GetOriginRegs();

	if (functionInterface.pLstarCallbackProcess != NULL)
	{
		ObDereferenceObject(functionInterface.pLstarCallbackProcess);
		functionInterface.pLstarCallbackProcess = NULL;
	}
	functionInterface.lstarInfo = {};

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
					pLstarCallbackProcess = NULL;
				}
				else
				{
					const SetLStartCallbackParam& param = *((const SetLStartCallbackParam*)pGuestRegisters->rdx);

					pLstarCallbackProcess = NULL;
					lstarInfo = param;
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
		if (functionInterface.pLstarCallbackProcess == NULL)
		{
			functionInterface.lstarInfo.callback(*pRegisters, *pStackDump, (UINT64)PsGetCurrentProcessId(), functionInterface.lstarInfo.param);
		}
		else
		{
			
			StackDump stackDumpCopy = {};

			if (!NT_SUCCESS(CopyUserDataToKernel((void*)pStackDump, sizeof * pStackDump, (void*)stackDumpCopy)))
				return;

			UINT32 pid = (UINT64)PsGetCurrentProcessId();
		
			KAPC_STATE state = {};
			KeStackAttachProcess(functionInterface.pLstarCallbackProcess, &state);

			if (PsGetCurrentProcess() == functionInterface.pLstarCallbackProcess)
			{
				SIZE_T nPage = sizeof(LStarCallbackArgsPack) / PAGE_SIZE + 1;

				LStarCallbackArgsPack* pPack = (LStarCallbackArgsPack*)AllocPagedMem(nPage * PAGE_SIZE, FUNC_TAG);

				if (pPack == NULL)
					return;

				for (SIZE_T i = 0; i < nPage; ++i)
					ChangePageAccessForUser((PTR_TYPE)pPack + nPage * PAGE_SIZE, true);

				pPack->callback = functionInterface.lstarInfo.callback;
				pPack->guestRegisters = *pRegisters;
				pPack->param = functionInterface.lstarInfo.param;
				pPack->pid = pid;
				RtlCopyMemory((PVOID)&pPack->stackDump, &stackDumpCopy, sizeof(StackDump));

				bool isSuccess = false;
				CallUserFunctionFromKernel(functionInterface.lstarInfo.extraEntry, pPack, isSuccess);

				for (SIZE_T i = 0; i < nPage; ++i)
					ChangePageAccessForUser((PTR_TYPE)pPack + nPage * PAGE_SIZE, false);

				FreePagedMem(pPack, FUNC_TAG);

				KeUnstackDetachProcess(&state);
			}
			else
			{
				ObDereferenceObject(functionInterface.pLstarCallbackProcess);
				functionInterface.pLstarCallbackProcess = NULL;
				functionInterface.lstarInfo = {};
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

		//设置回调执行环境
		guestRegisters.extraInfo1 = 0;
		guestRegisters.extraInfo2 = 0;

		//设置执行新入口函数
		guestRegisters.rcx = (PTR_TYPE)func;
		guestRegisters.rdx = (PTR_TYPE)param;
		guestRegisters.r8 = (PTR_TYPE)this;
		guestRegisters.rsp = (PTR_TYPE)pVirtCpuInfo->stack2 + sizeof pVirtCpuInfo->stack2;

		//如果调用方来自R3。执行额外的R3向R0的切换步骤
		if (!IsKernelAddress((PVOID)guestRegisters.rip))
		{
			GenericRegisters genericRegs;

			_save_or_load_regs(&genericRegs);

			genericRegs.rflags |= (1ULL << EFLAGS_IF_OFFSET);

			SAVE_GUEST_STATUS_FROM_REGS(pVirtCpuInfo, genericRegs.rax, genericRegs.rflags, guestRegisters.rsp, guestRegisters.rip);
			
			guestRegisters.rdi = genericRegs.rdi;
			guestRegisters.rsi = genericRegs.rsi;
			guestRegisters.rbx = genericRegs.rbx;
			guestRegisters.rbp = genericRegs.rbp;
			guestRegisters.r12 = genericRegs.r12;
			guestRegisters.r15 = genericRegs.r15;

			guestRegisters.xmm6 = genericRegs.xmm6;
			guestRegisters.xmm7 = genericRegs.xmm7;
			guestRegisters.xmm8 = genericRegs.xmm8;
			guestRegisters.xmm9 = genericRegs.xmm9;
			guestRegisters.xmm10 = genericRegs.xmm10;
			guestRegisters.xmm11 = genericRegs.xmm11;
			guestRegisters.xmm12 = genericRegs.xmm12;
			guestRegisters.xmm13 = genericRegs.xmm13;
			guestRegisters.xmm14 = genericRegs.xmm14;
			guestRegisters.xmm15 = genericRegs.xmm15;
		}

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