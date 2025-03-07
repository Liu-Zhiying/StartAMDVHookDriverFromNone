#ifndef SVM_H
#define SVM_H

#include "Basic.h"
#include "VMCB.h"

// 传入 #VMEXIT 处理函数，用于处理修改guest寄存器状态
// 也用于 进入虚拟化前后的寄存器备份和恢复
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

class IMsrInterceptPlugin;
class ICpuidInterceptPlugin;
class INpfInterceptPlugin;
class SVMManager;

//SVM 每个核心的虚拟化信息
struct VirtCpuInfo
{
	DECLSPEC_ALIGN(PAGE_SIZE) VMCB guestVmcb;
	DECLSPEC_ALIGN(PAGE_SIZE) VMCB hostVmcb;
	DECLSPEC_ALIGN(PAGE_SIZE) UINT8 hostStatus[PAGE_SIZE];
	DECLSPEC_ALIGN(PAGE_SIZE) UINT8 stack[2 * PAGE_SIZE];
	DECLSPEC_ALIGN(PAGE_SIZE) struct 
	{
		UINT32 isInVirtualizaion;
		SVMManager* pSvmManager;
		ULONG cpuIdx;
		PVOID pNptPageTablePa;
	} otherInfo;
	DECLSPEC_ALIGN(PAGE_SIZE) struct
	{
		GenericRegisters genericRegisters1;
		GenericRegisters genericRegisters2;
	} regsBackup;
};


//MSR拦截插件
class IMsrInterceptPlugin
{
public:
	//设置拦截的msr寄存器
	virtual void SetMsrPremissionMap(RTL_BITMAP& bitmap) = 0;
	//处理拦截的msr读取，true代表已经处理，false代表未处理
	virtual bool HandleMsrImterceptRead(VirtCpuInfo* pVirtCpuInfo, GenericRegisters* pGuestRegisters, 
										PVOID pGuestVmcbPhyAddr, PVOID pHostVmcbPhyAddr, 
										UINT32 msrNum) = 0;
	//处理拦截的Mst写入，true代表已经处理，false代表未处理
	virtual bool HandleMsrInterceptWrite(VirtCpuInfo* pVirtCpuInfo, GenericRegisters* pGuestRegisters,
										 PVOID pGuestVmcbPhyAddr, PVOID pHostVmcbPhyAddr, 
										 UINT32 msrNum) = 0;

	#pragma code_seg()
	virtual ~IMsrInterceptPlugin() {}
};

//MSR 备份恢复插件（用于在VMM加载和退出时备份和加载没有在VMCB中存在guest版本的msr）
class IMsrBackupRestorePlugin
{
public:
	//加载和保存guest的MSR
	virtual void LoadGuestMsrForCpu(UINT32 cpuIdx) = 0;
	virtual void SaveGuestMsrForCpu(UINT32 cpuIdx) = 0;

	//加载和保存host的MSR
	virtual void LoadHostMsrForCpu(UINT32 cpuIdx) = 0;
	virtual void SaveHostMsrForCpu(UINT32 cpuIdx) = 0;

	virtual ~IMsrBackupRestorePlugin() {}
};

//CPUID拦截插件
class ICpuidInterceptPlugin
{
public:
	//处理拦截的cpuid指令，true代表已经处理，false代表未处理
	virtual bool HandleCpuid(VirtCpuInfo* pVirtCpuInfo, GenericRegisters* pGuestRegisters,
							 PVOID pGuestVmcbPhyAddr, PVOID pHostVmcbPhyAddr) = 0;
	#pragma code_seg()
	virtual ~ICpuidInterceptPlugin() {}
};

//NPF拦截插件
class INpfInterceptPlugin
{
public:
	//处理拦截的NPF事件，true代表已经处理，false代表未处理
	virtual bool HandleNpf(VirtCpuInfo* pVirtCpuInfo, GenericRegisters* pGuestRegisters,
		PVOID pGuestVmcbPhyAddr, PVOID pHostVmcbPhyAddr) = 0;
	#pragma code_seg()
	virtual ~INpfInterceptPlugin() {}
};

//BP拦截插件
class IBreakprointInterceptPlugin
{
public:
	//处理拦截的BP事件，true代表已经处理，false代表未处理
	virtual bool HandleBreakpoint(VirtCpuInfo* pVirtCpuInfo, GenericRegisters* pGuestRegisters,
		PVOID pGuestVmcbPhyAddr, PVOID pHostVmcbPhyAddr) = 0;
	#pragma code_seg()
	virtual ~IBreakprointInterceptPlugin() {}
};

//UD拦截插件
class IInvalidOpcodeInterceptPlugin
{
public:
	//处理拦截的UD事件，true代表已经处理，false代表未处理
	virtual bool HandleInvalidOpcode(VirtCpuInfo* pVirtCpuInfo, GenericRegisters* pGuestRegisters,
		PVOID pGuestVmcbPhyAddr, PVOID pHostVmcbPhyAddr) = 0;
	#pragma code_seg()
	virtual ~IInvalidOpcodeInterceptPlugin() {}
};

//DE拦截插件
class ISignleStepInterceptPlugin
{
public:
	//处理拦截的DE事件，true代表已经处理，false代表未处理
	virtual bool HandleSignleStep(VirtCpuInfo* pVirtCpuInfo, GenericRegisters* pGuestRegisters, 
		PVOID pGuestVmcbPhyAddr, PVOID pHostVmcbPhyAddr) = 0;
	#pragma code_seg()
	virtual ~ISignleStepInterceptPlugin() {}
};

//NPT页表提供接口
class INCr3Provider
{
public:
	//根据CPUID获取对应的NCR3物理地址
	virtual PVOID GetNCr3ForCore(UINT32 cpuIdx) = 0;
	#pragma code_seg()
	virtual ~INCr3Provider() {}
};

//VMCB的msrpmBasePA指向的内容，全局只需要一份
//这个类负责初始化该资源
class MsrPremissionsMapManager : IManager
{
	PVOID pMsrPremissionsMapVirtAddr;
	PVOID pMsrPremissionsMapPhyAddr;
	IMsrInterceptPlugin* pMsrInterceptPlugin;
public:
	#pragma code_seg()
	MsrPremissionsMapManager()
		: pMsrPremissionsMapVirtAddr(NULL), pMsrPremissionsMapPhyAddr(NULL), pMsrInterceptPlugin(NULL)
	{}
	void SetPlugin(IMsrInterceptPlugin* _pMsrInterceptPlugin) { PAGED_CODE(); pMsrInterceptPlugin = _pMsrInterceptPlugin; }
	virtual NTSTATUS Init() override;
	#pragma code_seg()
	PTR_TYPE GetPhyAddress() const { return (PTR_TYPE)pMsrPremissionsMapPhyAddr; }
	#pragma code_seg()
	bool IsInited() const { return pMsrPremissionsMapVirtAddr != NULL; }
	virtual void Deinit() override;
	#pragma code_seg()
	virtual ~MsrPremissionsMapManager() { MsrPremissionsMapManager::Deinit(); }
};

enum SVMStatus
{
	//初始值，不表示任何信息
	SVMS_UNUSED = 0x0,
	//非AMDCPU
	SVMS_NONAMDCPU = 0x1,
	//CPU支持SVM
	SVMS_SUPPORTED = 0x2,
	//SVM已经启用
	SVMS_ENABLED = 0x4,
	//SVM就绪（未被其他虚拟化软件占用）
	SVMS_READY = 0x8,
	//NPT可用
	SVMS_NPT_ENABLED = 0x10
};

extern "C" void VmExitHandler(VirtCpuInfo* pVirtCpuInfo, GenericRegisters* pGuestRegisters, PVOID pGuestVmcbPhyAddr, PVOID pHostVmcbPhyAddr);

class SVMManager : public IManager
{
	VirtCpuInfo** pVirtCpuInfo;
	UINT32 cpuCnt;
	MsrPremissionsMapManager msrPremissionMap;
	IMsrInterceptPlugin* pMsrInterceptPlugin;
	IMsrBackupRestorePlugin* pMsrBackupRestorePlugin;
	ICpuidInterceptPlugin* pCpuIdInterceptPlugin;
	INpfInterceptPlugin* pNpfInterceptPlugin;
	IBreakprointInterceptPlugin* pBreakpointInterceptPlugin;
	ISignleStepInterceptPlugin* pSingleStepInterceptPlugin;
	INCr3Provider* pNCr3Provider;
	IInvalidOpcodeInterceptPlugin* pInvalidOpcodeInterceptPlugin;
	bool enableSce;
	NTSTATUS EnterVirtualization();
	void LeaveVirtualization();

	friend void VmExitHandler(VirtCpuInfo* pVirtCpuInfo, GenericRegisters* pGuestRegisters, PVOID pGuestVmcbPhyAddr, PVOID pHostVmcbPhyAddr);
	
public:
	//请勿调用该函数，这个函数由VMM自动调用
	void VmExitHandler(VirtCpuInfo* pVirtCpuInfo, GenericRegisters* pGuestRegisters, PVOID pGuestVmcbPhyAddr, PVOID pHostVmcbPhyAddr);
	#pragma code_seg("PAGE")
	SVMManager() : pVirtCpuInfo(NULL), cpuCnt(0), pMsrInterceptPlugin(NULL), pCpuIdInterceptPlugin(NULL), pNpfInterceptPlugin(NULL), pNCr3Provider(NULL), pBreakpointInterceptPlugin(NULL), pInvalidOpcodeInterceptPlugin(NULL), pSingleStepInterceptPlugin(NULL), enableSce(true), pMsrBackupRestorePlugin(NULL) { PAGED_CODE(); }
	#pragma code_seg("PAGE")
	void SetMsrInterceptPlugin(IMsrInterceptPlugin* _pMsrInterceptPlugin) { PAGED_CODE(); pMsrInterceptPlugin = _pMsrInterceptPlugin; }
	#pragma code_seg("PAGE")
	IMsrInterceptPlugin* GetMsrInterceptPlugin() { PAGED_CODE(); return pMsrInterceptPlugin; }
	#pragma code_seg("PAGE")
	void SetCpuIdInterceptPlugin(ICpuidInterceptPlugin* _pCpuIdInterceptPlugin) { PAGED_CODE(); pCpuIdInterceptPlugin = _pCpuIdInterceptPlugin; }
	#pragma code_seg("PAGE")
	ICpuidInterceptPlugin* GetCpuidInterceptPlugin() { PAGED_CODE(); return pCpuIdInterceptPlugin; }
	#pragma code_seg("PAGE")
	void SetNpfInterceptPlugin(INpfInterceptPlugin* _pNpfInterrceptPlugin) { PAGED_CODE(); pNpfInterceptPlugin = _pNpfInterrceptPlugin; }
	#pragma code_seg("PAGE")
	INpfInterceptPlugin* GetNpfnterceptPlugin() { PAGED_CODE(); return pNpfInterceptPlugin; }
	#pragma code_seg("PAGE")
	void SetNCr3Provider(INCr3Provider* _provider) { PAGED_CODE(); pNCr3Provider = _provider; }
	#pragma code_seg("PAGE")
	INCr3Provider* GetCr3Provider() { PAGED_CODE(); return pNCr3Provider; }
	#pragma code_seg("PAGE")
	void SetBreakpointPlugin(IBreakprointInterceptPlugin* _pBreakpointInterceptPlugin) { PAGED_CODE(); pBreakpointInterceptPlugin = _pBreakpointInterceptPlugin; }
	#pragma code_seg("PAGE")
	IBreakprointInterceptPlugin* GetBreakpointPlugin() { PAGED_CODE(); return pBreakpointInterceptPlugin; }
	#pragma code_seg("PAGE")
	void SetInvalidOpcodePlugin(IInvalidOpcodeInterceptPlugin* _pInvalidOpcodeInterceptPlugin) { PAGED_CODE(); pInvalidOpcodeInterceptPlugin = _pInvalidOpcodeInterceptPlugin; }
	#pragma code_seg("PAGE")
	IInvalidOpcodeInterceptPlugin* GetInvalidOpcodePlugin() { PAGED_CODE(); return pInvalidOpcodeInterceptPlugin; }
	#pragma code_seg("PAGE")
	void SetSingleStepPlugin(ISignleStepInterceptPlugin* _pDebugInterceptPlugin) { PAGED_CODE(); pSingleStepInterceptPlugin = _pDebugInterceptPlugin; }
	#pragma code_seg("PAGE")
	ISignleStepInterceptPlugin* GetSingleStepPlugin() { PAGED_CODE(); return pSingleStepInterceptPlugin; }
	#pragma code_seg("PAGE")
	void SetMsrBackupRestorePlugin(IMsrBackupRestorePlugin* _pMsrHookPlugin) { PAGED_CODE(); pMsrBackupRestorePlugin = _pMsrHookPlugin; }
	#pragma code_seg("PAGE")
	IMsrBackupRestorePlugin* GetMsrBackupRestorePlugin() { PAGED_CODE(); return pMsrBackupRestorePlugin; }
	#pragma code_seg("PAGE")
	void EnanbleSce(bool enable) { PAGED_CODE(); enableSce = enable; }
	#pragma code_seg("PAGE")
	bool IsSceEnabled() { PAGED_CODE(); return enableSce; }
	static SVMStatus CheckSVM();	
	virtual NTSTATUS Init() override;
	virtual void Deinit() override;
	#pragma code_seg("PAGE")
	virtual ~SVMManager() { PAGED_CODE(); SVMManager::Deinit(); }
};

//段选择器的attribute
//照抄https://github.com/tandasat/SimpleSvm
typedef struct _SEGMENT_ATTRIBUTE
{
	union
	{
		UINT16 AsUInt16;
		struct
		{
			UINT16 Type : 4;        // [0:3]
			UINT16 System : 1;      // [4]
			UINT16 Dpl : 2;         // [5:6]
			UINT16 Present : 1;     // [7]
			UINT16 Avl : 1;         // [8]
			UINT16 LongMode : 1;    // [9]
			UINT16 DefaultBit : 1;  // [10]
			UINT16 Granularity : 1; // [11]
			UINT16 Reserved1 : 4;   // [12:15]
		} Fields;
	};
} SEGMENT_ATTRIBUTE, * PSEGMENT_ATTRIBUTE;

typedef SEGMENT_ATTRIBUTE SegmentAttribute;

//获取段描述
SegmentAttribute GetSegmentAttribute(_In_ UINT16 SegmentSelector, _In_ ULONG_PTR GdtBase);
//获取段基地址
UINT64 GetSegmentBaseAddress(_In_ UINT16 SegmentSelector, _In_ ULONG_PTR GdtBase);
//获取段limit，后面加一个2是防止和系统函数冲突，可以直接使用系统函数
UINT32 GetSegmentLimit2(_In_ UINT16 SegmentSelector, _In_ ULONG_PTR GdtBase);

#endif

