#ifndef SVM_H
#define SVM_H

#include "Basic.h"
#include "VMCB.h"

// ���� #VMEXIT �������������ڴ����޸�guest�Ĵ���״̬
// Ҳ���� �������⻯ǰ��ļĴ������ݺͻָ�
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
	} otherInfo;
};

class IMsrInterceptPlugin
{
public:
	//�������ص�msr�Ĵ���
	virtual void SetMsrPremissionMap(RTL_BITMAP& bitmap) = 0;
	//�������ص�msr��ȡ��true�����Ѿ�������false����δ����
	virtual bool HandleMsrImterceptRead(VirtCpuInfo* pVirtCpuInfo, GenericRegisters* pGuestRegisters, 
										PVOID pGuestVmcbPhyAddr, PVOID pHostVmcbPhyAddr, 
										UINT32 msrNum, PULARGE_INTEGER msrValueOut) = 0;
	//�������ص�Mstд�룬true�����Ѿ�������false����δ����
	virtual bool HandleMsrInterceptWrite(VirtCpuInfo* pVirtCpuInfo, GenericRegisters* pGuestRegisters,
										 PVOID pGuestVmcbPhyAddr, PVOID pHostVmcbPhyAddr, 
										 UINT32 msrNum, ULARGE_INTEGER mstValueIn) = 0;
	virtual ~IMsrInterceptPlugin() {}
};

class ICpuidInterceptPlugin
{
public:
	//�������ص�cpuidָ�true�����Ѿ�������false����δ����
	virtual bool HandleCpuid(VirtCpuInfo* pVirtCpuInfo, GenericRegisters* pGuestRegisters,
							 PVOID pGuestVmcbPhyAddr, PVOID pHostVmcbPhyAddr) = 0;
	virtual ~ICpuidInterceptPlugin() {}
};

//VMCB��msrpmBasePAָ������ݣ�ȫ��ֻ��Ҫһ��
//����ฺ���ʼ������Դ
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
	//��ʼֵ������ʾ�κ���Ϣ
	SVMS_UNUSED = 0x0,
	//��AMDCPU
	SVMS_NONAMDCPU = 0x1,
	//CPU֧��SVM
	SVMS_SUPPORTED = 0x2,
	//SVM�Ѿ�����
	SVMS_ENABLED = 0x4,
	//SVM������δ���������⻯����ռ�ã�
	SVMS_READY = 0x8,
};

class SVMManager : public IManager
{
	VirtCpuInfo** pVirtCpuInfo;
	UINT64 cpuCnt;
	MsrPremissionsMapManager msrPremissionMap;
	IMsrInterceptPlugin* pMsrInterceptPlugin;
	ICpuidInterceptPlugin* pCpuIdInterceptPlugin;
	NTSTATUS EnterVirtualization();
	void LeaveVirtualization();
public:
	#pragma code_seg("PAGE")
	SVMManager() : pVirtCpuInfo(NULL), cpuCnt(0), pMsrInterceptPlugin(NULL), pCpuIdInterceptPlugin(NULL) { PAGED_CODE(); }
	#pragma code_seg("PAGE")
	void SetMsrInterceptPlugin(IMsrInterceptPlugin* _pMsrInterceptPlugin) { PAGED_CODE(); pMsrInterceptPlugin = _pMsrInterceptPlugin; }
	#pragma code_seg("PAGE")
	void SetCpuIdInterceptPlugin(ICpuidInterceptPlugin* _pCpuIdInterceptPlugin) { PAGED_CODE(); pCpuIdInterceptPlugin = _pCpuIdInterceptPlugin; }
	static SVMStatus CheckSVM();
	virtual NTSTATUS Init() override;
	virtual void Deinit() override;
	#pragma code_seg("PAGE")
	virtual ~SVMManager() { PAGED_CODE(); SVMManager::Deinit(); }
};

#endif
