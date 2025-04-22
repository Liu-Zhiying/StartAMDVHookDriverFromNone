#ifndef AMDVDRIVERSDK_H
#define AMDVDRIVERSDK_H

typedef unsigned int UINT32;
typedef unsigned long long PTR_TYPE;
typedef void* PVOID;
#ifndef NULL
#define NULL 0
#endif

//这里面的是需要公开的已经在驱动里使用的某些结构
//如果是驱动内部以实现接口为目的则不要定义这些结构，以避免重复定义
#ifndef NOT_DEFINE_PUBLIC_STRCUT

//方便为类提供非分页的默认拷贝和移动构造函数和运算符
#define DEFAULT_NONPAGED_COPY_AND_MOVE_FUNCTION_FOR_CLASS(classname)																\
_Pragma("code_seg()")																												\
classname(const classname&) = default;																								\
_Pragma("code_seg()")																												\
classname(classname&&) = default;																									\
_Pragma("code_seg()")																												\
classname& operator=(const classname&) = default;																					\
_Pragma("code_seg()")																												\
classname& operator=(classname&&) = default;

//hook条目记录
struct NptHookRecord
{
	//hook原始虚拟地址
	PVOID pOriginVirtAddr;
	//hook的跳转地址
	PVOID pGotoVirtAddr;
#pragma code_seg()
	NptHookRecord() : pOriginVirtAddr(NULL), pGotoVirtAddr(NULL) {}

	DEFAULT_NONPAGED_COPY_AND_MOVE_FUNCTION_FOR_CLASS(NptHookRecord)
};

struct GenericRegisters
{
	M128A xmm0;
	M128A xmm1;
	M128A xmm2;
	M128A xmm3;
	M128A xmm4;
	M128A xmm5;
	M128A xmm6;
	M128A xmm7;
	M128A xmm8;
	M128A xmm9;
	M128A xmm10;
	M128A xmm11;
	M128A xmm12;
	M128A xmm13;
	M128A xmm14;
	M128A xmm15;
	UINT64 r15;
	UINT64 r14;
	UINT64 r13;
	UINT64 r12;
	UINT64 r11;
	UINT64 r10;
	UINT64 r9;
	UINT64 r8;
	UINT64 rbp;
	UINT64 rsi;
	UINT64 rdi;
	UINT64 rdx;
	UINT64 rcx;
	UINT64 rbx;
	UINT64 rax;
	UINT64 rflags;
	UINT64 rip;
	UINT64 rsp;
	UINT64 extraInfo1;
	UINT64 extraInfo2;
};

//辅助函数，用于跳转到VMM处理
extern "C" void SetRegsThenCpuid(PTR_TYPE* rax, PTR_TYPE* rbx, PTR_TYPE* rcx, PTR_TYPE* rdx);

#else

#include "Hook.h"

#endif // NOT_DEFINE_PUBLIC_STRCUT

//用于其他驱动或者应用程序调用此驱动程序功能的头文件

//所有接口实际通过 CPUID 指令与本驱动通讯，这些CPUID用于标识接口ID，但是请不要直接以CPUID指令去调用这些接口
//这个头文件会提供接口包装，请调用这些接口的包装
constexpr UINT32 CALL_FUNCTION_INTERFACE_CPUID_FUNCTION = 0x400000fc;
constexpr UINT32 NEW_FUNCTION_CALLER_CPUID_SUBFUNCTION = 0x00000000;
constexpr UINT32 DEL_FUNCTION_CALLER_CPUID_SUBFUNCTION = 0x00000001;
constexpr UINT32 ADD_NPT_HOOK_CPUID_SUBFUNCTION = 0x00000002;
constexpr UINT32 DEL_NPT_HOOK_CPUID_SUBFUNCTION = 0x00000003;
constexpr UINT32 SET_SYSCALL_HOOK_CALLBACK_CPUID_SUBFUNCION = 0x00000004;

constexpr UINT32 GUEST_CALL_VMM_CPUID_FUNCTION = 0x400000ff;
constexpr UINT32 IS_IN_SVM_CPUID_SUBFUNCTION = 0x00000001;

typedef const UINT8 StackDump[128];

//syscall 拦截回调，r0和r3都可使用
typedef void (*LStarCallback)(GenericRegisters& guestRegisters, StackDump& stackDump, UINT32 pid, PVOID param);

struct SetLStartCallbackParam
{
	LStarCallback callback;
	PVOID param;

public:
	SetLStartCallbackParam() : callback(NULL), param(NULL) {}
};

class AMDVDriverInterface
{
public:
	static bool IsInSVM()
	{
		PTR_TYPE regs[4] = { GUEST_CALL_VMM_CPUID_FUNCTION, 0, IS_IN_SVM_CPUID_SUBFUNCTION, 0 };

		SetRegsThenCpuid(&regs[0], &regs[1], &regs[2], &regs[3]);

		return *reinterpret_cast<UINT32*>(&regs[0]) == 'IN' &&
			   *reinterpret_cast<UINT32*>(&regs[1]) == 'AMD' &&
			   *reinterpret_cast<UINT32*>(&regs[2]) == 'SVM';
	}

	static bool AddNptHook(const NptHookRecord& record)
	{
		PTR_TYPE regs[4] = { CALL_FUNCTION_INTERFACE_CPUID_FUNCTION, 0, ADD_NPT_HOOK_CPUID_SUBFUNCTION, (PTR_TYPE)&record };

		SetRegsThenCpuid(&regs[0], &regs[1], &regs[2], &regs[3]);

		return regs[1];
	}

	static void DelNptHook(PVOID pSourceFunction)
	{
		PTR_TYPE regs[4] = { CALL_FUNCTION_INTERFACE_CPUID_FUNCTION, 0, DEL_NPT_HOOK_CPUID_SUBFUNCTION, (PTR_TYPE)pSourceFunction };

		SetRegsThenCpuid(&regs[0], &regs[1], &regs[2], &regs[3]);
	}

	static PVOID AddFunctionCaller(PVOID pOriginFunction)
	{
		PTR_TYPE regs[4] = { CALL_FUNCTION_INTERFACE_CPUID_FUNCTION, 0, NEW_FUNCTION_CALLER_CPUID_SUBFUNCTION, (PTR_TYPE)pOriginFunction };

		SetRegsThenCpuid(&regs[0], &regs[1], &regs[2], &regs[3]);

		return (PVOID)regs[1];
	}

	static void DelFunctionCaller(PVOID pOriginFunction)
	{
		PTR_TYPE regs[4] = { CALL_FUNCTION_INTERFACE_CPUID_FUNCTION, 0, DEL_FUNCTION_CALLER_CPUID_SUBFUNCTION, (PTR_TYPE)pOriginFunction };

		SetRegsThenCpuid(&regs[0], &regs[1], &regs[2], &regs[3]);
	}

	static bool SetSyscallHookCallback(SetLStartCallbackParam* param)
	{
		PTR_TYPE regs[4] = { CALL_FUNCTION_INTERFACE_CPUID_FUNCTION, 0, SET_SYSCALL_HOOK_CALLBACK_CPUID_SUBFUNCION, (PTR_TYPE)param };

		SetRegsThenCpuid(&regs[0], &regs[1], &regs[2], &regs[3]);

		return regs[1];
	}
};

#endif