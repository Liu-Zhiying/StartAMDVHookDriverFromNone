#ifndef SVM_H
#define SVM_H

#include "Basic.h"
#include "VMCB.h"

struct VirtCpuInfo
{
	DECLSPEC_ALIGN(PAGE_SIZE) VMCB guestVmcb;
	DECLSPEC_ALIGN(PAGE_SIZE) VMCB hostVmcb;
	DECLSPEC_ALIGN(PAGE_SIZE) struct HostStack
	{
		UINT8 stack[KERNEL_STACK_SIZE - 4 * sizeof(PTR_TYPE)];
		PVOID pGuestVmcb;
		PVOID pHostVmcb;
		PVOID pCpuInfo;
		PVOID pRetAddr;
	} hostStack;
	DECLSPEC_ALIGN(PAGE_SIZE) UINT8 HostStateArea[PAGE_SIZE];
	DECLSPEC_ALIGN(PAGE_SIZE) struct
	{
		UINT32 isInVirtualizaion;
	} otherInfo;
};

//VMCB的msrpmBasePA指向的内容，全局只需要一份
//这个类负责初始化该资源
class MsrPremissionsMapManager : IManager
{
	PVOID pMsrPremissionsMapVirtAddr;
	PVOID pMsrPremissionsMapPhyAddr;
public:
	#pragma code_seg("PAGE")
	MsrPremissionsMapManager()
		: pMsrPremissionsMapVirtAddr(NULL), pMsrPremissionsMapPhyAddr(NULL) 
	{ PAGED_CODE(); }
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
	NTSTATUS EnterVirtualization();
	void LeaveVirtualization();
public:
	#pragma code_seg("PAGE")
	SVMManager() : pVirtCpuInfo(NULL), cpuCnt(0) { PAGED_CODE(); }
	static SVMStatus CheckSVM();
	virtual NTSTATUS Init() override;
	virtual void Deinit() override;
	#pragma code_seg("PAGE")
	virtual ~SVMManager() { PAGED_CODE(); SVMManager::Deinit(); }
};

#endif

