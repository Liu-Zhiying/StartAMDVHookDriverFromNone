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

struct VirtCpuInfo
{
	DECLSPEC_ALIGN(PAGE_SIZE) VMCB guestVmcb;
	DECLSPEC_ALIGN(PAGE_SIZE) VMCB hostVmcb;
	DECLSPEC_ALIGN(PAGE_SIZE) UINT8 hostStatus[PAGE_SIZE];
	DECLSPEC_ALIGN(PAGE_SIZE) UINT8 stack[KERNEL_STACK_SIZE];
	DECLSPEC_ALIGN(PAGE_SIZE) struct
	{
		UINT32 isInVirtualizaion;
		IMsrInterceptPlugin* pMsrInterceptPlugin;
		ICpuidInterceptPlugin* pCpuIdInterceptPlugin;
		ULONG cpuIdx;
	} otherInfo;
};

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
	virtual ~IMsrInterceptPlugin() {}
};

class ICpuidInterceptPlugin
{
public:
	//处理拦截的cpuid指令，true代表已经处理，false代表未处理
	virtual bool HandleCpuid(VirtCpuInfo* pVirtCpuInfo, GenericRegisters* pGuestRegisters,
							 PVOID pGuestVmcbPhyAddr, PVOID pHostVmcbPhyAddr) = 0;
	virtual ~ICpuidInterceptPlugin() {}
};

//VMCB的msrpmBasePA指向的内容，全局只需要一份
//这个类负责初始化该资源
class MsrPremissionsMapManager : IManager
{
	PVOID pMsrPremissionsMapVirtAddr;
	PVOID pMsrPremissionsMapPhyAddr;
	IMsrInterceptPlugin* pMsrInterceptPlugin;
public:
	#pragma code_seg("PAGE")
	MsrPremissionsMapManager()
		: pMsrPremissionsMapVirtAddr(NULL), pMsrPremissionsMapPhyAddr(NULL), pMsrInterceptPlugin(NULL)
	{ PAGED_CODE(); }
	void SetPlugin(IMsrInterceptPlugin* _pMsrInterceptPlugin) { PAGED_CODE(); pMsrInterceptPlugin = _pMsrInterceptPlugin; }
	virtual NTSTATUS Init() override;
	#pragma code_seg("PAGE")
	PTR_TYPE GetPhyAddress() { PAGED_CODE(); return (PTR_TYPE)pMsrPremissionsMapPhyAddr; }
	#pragma code_seg("PAGE")
	bool IsInited() { PAGED_CODE(); return pMsrPremissionsMapVirtAddr != NULL; }
	virtual void Deinit() override;
	#pragma code_seg("PAGE")
	virtual ~MsrPremissionsMapManager() { PAGED_CODE(); MsrPremissionsMapManager::Deinit(); }
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
};

class SVMManager : public IManager
{
	VirtCpuInfo** pVirtCpuInfo;
	UINT64 cpuCnt;
	MsrPremissionsMapManager msrPremissionMap;
	IMsrInterceptPlugin* pMsrInterceptPlugin;
	ICpuidInterceptPlugin* pCpuIdInterceptPlugin;
	PVOID pNptPageTable;
	NTSTATUS EnterVirtualization();
	void LeaveVirtualization();
public:
	#pragma code_seg("PAGE")
	SVMManager() : pVirtCpuInfo(NULL), cpuCnt(0), pMsrInterceptPlugin(NULL), pCpuIdInterceptPlugin(NULL), pNptPageTable(NULL) { PAGED_CODE(); }
	#pragma code_seg("PAGE")
	void SetMsrInterceptPlugin(IMsrInterceptPlugin* _pMsrInterceptPlugin) { PAGED_CODE(); pMsrInterceptPlugin = _pMsrInterceptPlugin; }
	#pragma code_seg("PAGE")
	void SetCpuIdInterceptPlugin(ICpuidInterceptPlugin* _pCpuIdInterceptPlugin) { PAGED_CODE(); pCpuIdInterceptPlugin = _pCpuIdInterceptPlugin; }
	#pragma code_seg("PAGE")
	void SetNptPageTable(PVOID _pNptPageTable) { PAGED_CODE(); pNptPageTable = _pNptPageTable; }
	static SVMStatus CheckSVM();
	virtual NTSTATUS Init() override;
	virtual void Deinit() override;
	#pragma code_seg("PAGE")
	virtual ~SVMManager() { PAGED_CODE(); SVMManager::Deinit(); }
};

#endif

