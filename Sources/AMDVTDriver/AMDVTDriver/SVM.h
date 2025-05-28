#ifndef SVM_H
#define SVM_H

#include "Basic.h"
#include "VMCB.h"

// ���� #VMEXIT �����������ڴ����޸�guest�Ĵ���״̬
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
class INpfInterceptPlugin;
class SVMManager;

//SVM ÿ�����ĵ����⻯��Ϣ
struct VirtCpuInfo
{
	DECLSPEC_ALIGN(PAGE_SIZE) VMCB guestVmcb;
	DECLSPEC_ALIGN(PAGE_SIZE) VMCB hostVmcb;
	DECLSPEC_ALIGN(PAGE_SIZE) UINT8 hostStatus[PAGE_SIZE];
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
	DECLSPEC_ALIGN(PAGE_SIZE) UINT8 stack1[KERNEL_STACK_SIZE];
	DECLSPEC_ALIGN(PAGE_SIZE) UINT8 stack2[KERNEL_STACK_SIZE];
};

//MSR���ز��
class IMsrInterceptPlugin
{
public:
	//�������ص�msr�Ĵ���
	virtual void SetMsrPremissionMap(RTL_BITMAP& bitmap) = 0;
	//�������ص�msr��ȡ��true�����Ѿ�����false����δ����
	virtual bool HandleMsrImterceptRead(VirtCpuInfo* pVirtCpuInfo, GenericRegisters* pGuestRegisters, 
										PVOID pGuestVmcbPhyAddr, PVOID pHostVmcbPhyAddr, 
										UINT32 msrNum) = 0;
	//�������ص�Mstд�룬true�����Ѿ�����false����δ����
	virtual bool HandleMsrInterceptWrite(VirtCpuInfo* pVirtCpuInfo, GenericRegisters* pGuestRegisters,
										 PVOID pGuestVmcbPhyAddr, PVOID pHostVmcbPhyAddr, 
										 UINT32 msrNum) = 0;

	#pragma code_seg()
	virtual ~IMsrInterceptPlugin() {}
};

//MSR ���ݻָ������������VMM���غ��˳�ʱ���ݺͼ���û����VMCB�д���guest�汾��msr��
class IMsrBackupRestorePlugin
{
public:
	//���غͱ���guest��MSR
	virtual void LoadGuestMsrForCpu(UINT32 cpuIdx) = 0;
	virtual void SaveGuestMsrForCpu(UINT32 cpuIdx) = 0;

	//���غͱ���host��MSR
	virtual void LoadHostMsrForCpu(UINT32 cpuIdx) = 0;
	virtual void SaveHostMsrForCpu(UINT32 cpuIdx) = 0;

	virtual ~IMsrBackupRestorePlugin() {}
};

//CPUID���ز��
class ICpuidInterceptPlugin
{
public:
	//�������ص�cpuidָ�true�����Ѿ�����false����δ����
	virtual bool HandleCpuid(VirtCpuInfo* pVirtCpuInfo, GenericRegisters* pGuestRegisters,
							 PVOID pGuestVmcbPhyAddr, PVOID pHostVmcbPhyAddr) = 0;
	#pragma code_seg()
	virtual ~ICpuidInterceptPlugin() {}
};

//NPF���ز��
class INpfInterceptPlugin
{
public:
	//�������ص�NPF�¼���true�����Ѿ�����false����δ����
	virtual bool HandleNpf(VirtCpuInfo* pVirtCpuInfo, GenericRegisters* pGuestRegisters,
		PVOID pGuestVmcbPhyAddr, PVOID pHostVmcbPhyAddr) = 0;
	#pragma code_seg()
	virtual ~INpfInterceptPlugin() {}
};

//BP���ز��
class IBreakprointInterceptPlugin
{
public:
	//�������ص�BP�¼���true�����Ѿ�����false����δ����
	virtual bool HandleBreakpoint(VirtCpuInfo* pVirtCpuInfo, GenericRegisters* pGuestRegisters,
		PVOID pGuestVmcbPhyAddr, PVOID pHostVmcbPhyAddr) = 0;
	#pragma code_seg()
	virtual ~IBreakprointInterceptPlugin() {}
};

//UD���ز��
class IInvalidOpcodeInterceptPlugin
{
public:
	//�������ص�UD�¼���true�����Ѿ�����false����δ����
	virtual bool HandleInvalidOpcode(VirtCpuInfo* pVirtCpuInfo, GenericRegisters* pGuestRegisters,
		PVOID pGuestVmcbPhyAddr, PVOID pHostVmcbPhyAddr) = 0;
	#pragma code_seg()
	virtual ~IInvalidOpcodeInterceptPlugin() {}
};

//DE���ز��
class ISingleStepInterceptPlugin
{
public:
	//�������ص�DE�¼���true�����Ѿ�����false����δ����
	virtual bool HandleSignleStep(VirtCpuInfo* pVirtCpuInfo, GenericRegisters* pGuestRegisters, 
		PVOID pGuestVmcbPhyAddr, PVOID pHostVmcbPhyAddr) = 0;
	#pragma code_seg()
	virtual ~ISingleStepInterceptPlugin() {}
};

//NPTҳ���ṩ�ӿ�
class INCr3Provider
{
public:
	//����CPUID��ȡ��Ӧ��NCR3�����ַ
	virtual PVOID GetNCr3ForCore(UINT32 cpuIdx) = 0;
	#pragma code_seg()
	virtual ~INCr3Provider() {}
};

//VMCB��msrpmBasePAָ������ݣ�ȫ��ֻ��Ҫһ��
//����ฺ���ʼ������Դ
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
	//��ʼֵ������ʾ�κ���Ϣ
	SVMS_UNUSED = 0x0,
	//��AMDCPU
	SVMS_NONAMDCPU = 0x1,
	//CPU֧��SVM
	SVMS_SUPPORTED = 0x2,
	//SVM�Ѿ�����
	SVMS_ENABLED = 0x4,
	//SVM������δ���������⻯���ռ�ã�
	SVMS_READY = 0x8,
	//NPT����
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
	ISingleStepInterceptPlugin* pSingleStepInterceptPlugin;
	INCr3Provider* pNCr3Provider;
	IInvalidOpcodeInterceptPlugin* pInvalidOpcodeInterceptPlugin;
	bool enableSce;

	friend void VmExitHandler(VirtCpuInfo* pVirtCpuInfo, GenericRegisters* pGuestRegisters, PVOID pGuestVmcbPhyAddr, PVOID pHostVmcbPhyAddr);
	
public:
	NTSTATUS EnterVirtualization();
	void LeaveVirtualization();
	//������øú��������������VMM�Զ�����
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
	void SetSingleStepPlugin(ISingleStepInterceptPlugin* _pDebugInterceptPlugin) { PAGED_CODE(); pSingleStepInterceptPlugin = _pDebugInterceptPlugin; }
	#pragma code_seg("PAGE")
	ISingleStepInterceptPlugin* GetSingleStepPlugin() { PAGED_CODE(); return pSingleStepInterceptPlugin; }
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

//��ѡ������attribute
//�ճ�https://github.com/tandasat/SimpleSvm
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

//��ȡ������
SegmentAttribute GetSegmentAttribute(_In_ UINT16 SegmentSelector, _In_ ULONG_PTR GdtBase);
//��ȡ�λ���ַ
UINT64 GetSegmentBaseAddress(_In_ UINT16 SegmentSelector, _In_ ULONG_PTR GdtBase);
//��ȡ��limit�������һ��2�Ƿ�ֹ��ϵͳ������ͻ������ֱ��ʹ��ϵͳ����
UINT32 GetSegmentLimit2(_In_ UINT16 SegmentSelector, _In_ ULONG_PTR GdtBase);

//һϵ�л�ຯ��
//Դ������SVM_asm.asm����
//��Ҫ���ǼĴ�����ȡ����
extern "C" void _mysgdt(UINT64* pBase, UINT16* pLImit);
extern "C" void _mysidt(UINT64* pBase, UINT16* pLImit);
extern "C" void _mysldt(UINT16* pSelector);
extern "C" void _mystr(UINT16* pSelector);
extern "C" UINT16 _cs_selector();
extern "C" UINT16 _ds_selector();
extern "C" UINT16 _es_selector();
extern "C" UINT16 _fs_selector();
extern "C" UINT16 _gs_selector();
extern "C" UINT16 _ss_selector();

//���ڱ��ݺͻ�ԭ�Ĵ���������
extern "C" void _save_or_load_regs(GenericRegisters* pRegisters);
//ִ��vmrun��ز���
extern "C" void _run_svm_vmrun(VirtCpuInfo* pVirtCpuInfo, PVOID pGuestVmcbPhyAddr, PVOID pHostVmcbPhyAddr, PVOID pStack);

/*
	(virtCpuInfo)->guestVmcb.statusFields.gdtr.base = gdtrBase;
	(virtCpuInfo)->guestVmcb.statusFields.gdtr.limit = gdtrLimit;
	(virtCpuInfo)->guestVmcb.statusFields.idtr.base = idtrBase;
	(virtCpuInfo)->guestVmcb.statusFields.idtr.limit = idtrLimit;

	//X64 ����κ����ݶε�base��limit����Ч�ģ�FS,GS���⣩
	//base ǿ��Ϊ 0��ǿ��ƽ̹�Σ�
	//���ﻹ�Ƕ�ȡ��ԭʼ��base��limit
	(virtCpuInfo)->guestVmcb.statusFields.cs.selector = _cs_selector();
	(virtCpuInfo)->guestVmcb.statusFields.cs.base = GetSegmentBaseAddress(_cs_selector(), gdtrBase);
	(virtCpuInfo)->guestVmcb.statusFields.cs.limit = GetSegmentLimit2(_cs_selector(), gdtrBase);
	(virtCpuInfo)->guestVmcb.statusFields.cs.attrib = GetSegmentAttribute(_cs_selector(), gdtrBase).AsUInt16;

	(virtCpuInfo)->guestVmcb.statusFields.ds.selector = _ds_selector();
	(virtCpuInfo)->guestVmcb.statusFields.ds.base = GetSegmentBaseAddress(_ds_selector(), gdtrBase);
	(virtCpuInfo)->guestVmcb.statusFields.ds.limit = GetSegmentLimit2(_ds_selector(), gdtrBase);
	(virtCpuInfo)->guestVmcb.statusFields.ds.attrib = GetSegmentAttribute(_ds_selector(), gdtrBase).AsUInt16;

	(virtCpuInfo)->guestVmcb.statusFields.es.selector = _es_selector();
	(virtCpuInfo)->guestVmcb.statusFields.es.base = GetSegmentBaseAddress(_es_selector(), gdtrBase);
	(virtCpuInfo)->guestVmcb.statusFields.es.limit = GetSegmentLimit2(_es_selector(), gdtrBase);
	(virtCpuInfo)->guestVmcb.statusFields.es.attrib = GetSegmentAttribute(_es_selector(), gdtrBase).AsUInt16;

	(virtCpuInfo)->guestVmcb.statusFields.ss.selector = _ss_selector();
	(virtCpuInfo)->guestVmcb.statusFields.ss.base = GetSegmentBaseAddress(_ss_selector(), gdtrBase);
	(virtCpuInfo)->guestVmcb.statusFields.ss.limit = GetSegmentLimit2(_ss_selector(), gdtrBase);
	(virtCpuInfo)->guestVmcb.statusFields.ss.attrib = GetSegmentAttribute(_ss_selector(), gdtrBase).AsUInt16;

	//�������һ����Ϣ����ʹ��vmsaveָ��ֱ�ӻ�ȡ
	//����Ϊ���о�ԭ���ֶ���ȡ
	//*************************************** BEGIN ***************************************

	(virtCpuInfo)->guestVmcb.statusFields.fs.selector = _fs_selector();
	(virtCpuInfo)->guestVmcb.statusFields.fs.limit = GetSegmentLimit2(_fs_selector(), gdtrBase);
	(virtCpuInfo)->guestVmcb.statusFields.fs.attrib = GetSegmentAttribute(_fs_selector(), gdtrBase).AsUInt16;

	(virtCpuInfo)->guestVmcb.statusFields.gs.selector = _gs_selector();
	(virtCpuInfo)->guestVmcb.statusFields.gs.limit = GetSegmentLimit2(_gs_selector(), gdtrBase);
	(virtCpuInfo)->guestVmcb.statusFields.gs.attrib = GetSegmentAttribute(_gs_selector(), gdtrBase).AsUInt16;

	//����TR LDTR base limit ��Ȼ��Ч
	(virtCpuInfo)->guestVmcb.statusFields.ldtr.selector = ldtrSelector;
	(virtCpuInfo)->guestVmcb.statusFields.ldtr.base = GetSegmentBaseAddress(ldtrSelector, gdtrBase);
	(virtCpuInfo)->guestVmcb.statusFields.ldtr.limit = GetSegmentLimit2(ldtrSelector, gdtrBase);
	(virtCpuInfo)->guestVmcb.statusFields.ldtr.attrib = GetSegmentAttribute(ldtrSelector, gdtrBase).AsUInt16;

	(virtCpuInfo)->guestVmcb.statusFields.tr.selector = trSelector;
	(virtCpuInfo)->guestVmcb.statusFields.tr.base = GetSegmentBaseAddress(trSelector, gdtrBase);
	(virtCpuInfo)->guestVmcb.statusFields.tr.limit = GetSegmentLimit2(trSelector, gdtrBase);
	(virtCpuInfo)->guestVmcb.statusFields.tr.attrib = GetSegmentAttribute(trSelector, gdtrBase).AsUInt16;

	//FSBase GSBase KenrelGSBase ���Բ�Ϊ0 �����Ƿ���MSR�Ĵ��������
	//IA32_MSR_FS_BASE���±�0xC0000100��
	//IA32_MSR_GS_BASE���±�0xC0000101��
	//IA32_MSR_KERNEL_GS_BASE���±�0xC0000102��

	(virtCpuInfo)->guestVmcb.statusFields.fs.base = __readmsr(IA32_MSR_FS_BASE);
	(virtCpuInfo)->guestVmcb.statusFields.gs.base = __readmsr(IA32_MSR_GS_BASE);
	(virtCpuInfo)->guestVmcb.statusFields.kernelGsBase = __readmsr(IA32_MSR_KERNEL_GS_BASE);

	//����32λϵͳ����Ҫ��� SYSENTER_CS SYSENTER_ESP SYSENTER_EIP

	//(virtCpuInfo)->guestVmcb.statusFields.sysenterCs = __readmsr(IA32_MSR_SYSENTER_CS);
	//(virtCpuInfo)->guestVmcb.statusFields.sysenterEsp = __readmsr(IA32_MSR_SYSENTER_ESP);
	//(virtCpuInfo)->guestVmcb.statusFields.sysenterEip = __readmsr(IA32_MSR_SYSENTER_EIP);

	(virtCpuInfo)->guestVmcb.statusFields.star = __readmsr(IA32_MSR_STAR);
	(virtCpuInfo)->guestVmcb.statusFields.lstar = __readmsr(IA32_MSR_LSTAR);
	(virtCpuInfo)->guestVmcb.statusFields.cstar = __readmsr(IA32_MSR_CSTAR);
	(virtCpuInfo)->guestVmcb.statusFields.sfmask = __readmsr(IA32_MSR_SF_MASK);

	//*************************************** END ***************************************

	//��� VMCB EFER �� EFER ֵ��SVMEλ����Ϊ1������vmrun��ʧ��
	(virtCpuInfo)->guestVmcb.statusFields.efer = __readmsr(IA32_MSR_EFER);

	//��Ҫʱ����syscall��sysret
	if (!enableSce)
	(virtCpuInfo)->guestVmcb.statusFields.efer &= ~(1 << SCE_ENABLE_OFFSET);

	(virtCpuInfo)->guestVmcb.statusFields.cr0 = __readcr0();
	(virtCpuInfo)->guestVmcb.statusFields.cr2 = __readcr2();
	(virtCpuInfo)->guestVmcb.statusFields.cr3 = __readcr3();
	(virtCpuInfo)->guestVmcb.statusFields.cr4 = __readcr4();
	//����raxΪGenericRegisters�ĵ�ַ������__save_or_load_regs����ͨ��rax���ʵ�GenericRegisters���ָ��Ĵ���
	(virtCpuInfo)->guestVmcb.statusFields.rax = (PTR_TYPE)&registerBackup;
	(virtCpuInfo)->guestVmcb.statusFields.rflags = registerBackup.rflags;
	(virtCpuInfo)->guestVmcb.statusFields.rsp = registerBackup.rsp;
	(virtCpuInfo)->guestVmcb.statusFields.rip = registerBackup.rip;
	(virtCpuInfo)->guestVmcb.statusFields.gPat = __readmsr(IA32_MSR_PAT);

	(virtCpuInfo)->guestVmcb.statusFields.cpl = _cs_selector() & 0x3;

	(virtCpuInfo)->hostVmcb.statusFields = (virtCpuInfo)->guestVmcb.statusFields;
*/

#define SAVE_GUEST_STATUS_FROM_REGS(virtCpuInfo, rax_val, rflags_val, rsp_val, rip_val)												\
																																	\
	UINT64 gdtrBase = 0, idtrBase = 0;																								\
	UINT16 gdtrLimit = 0, idtrLimit = 0;																							\
	UINT16 trSelector = 0, ldtrSelector = 0;																						\
	_mysgdt(&gdtrBase, &gdtrLimit);																									\
	_mysidt(&idtrBase, &idtrLimit);																									\
	_mystr(&trSelector);																											\
	_mysldt(&ldtrSelector);																											\
																																	\
	(virtCpuInfo)->guestVmcb.statusFields.gdtr.base = gdtrBase;																		\
	(virtCpuInfo)->guestVmcb.statusFields.gdtr.limit = gdtrLimit;																	\
	(virtCpuInfo)->guestVmcb.statusFields.idtr.base = idtrBase;																		\
	(virtCpuInfo)->guestVmcb.statusFields.idtr.limit = idtrLimit;																	\
																																	\
	(virtCpuInfo)->guestVmcb.statusFields.cs.selector = _cs_selector();																\
	(virtCpuInfo)->guestVmcb.statusFields.cs.base = GetSegmentBaseAddress(_cs_selector(), gdtrBase);								\
	(virtCpuInfo)->guestVmcb.statusFields.cs.limit = GetSegmentLimit2(_cs_selector(), gdtrBase);									\
	(virtCpuInfo)->guestVmcb.statusFields.cs.attrib = GetSegmentAttribute(_cs_selector(), gdtrBase).AsUInt16;						\
																																	\
	(virtCpuInfo)->guestVmcb.statusFields.ds.selector = _ds_selector();																\
	(virtCpuInfo)->guestVmcb.statusFields.ds.base = GetSegmentBaseAddress(_ds_selector(), gdtrBase);								\
	(virtCpuInfo)->guestVmcb.statusFields.ds.limit = GetSegmentLimit2(_ds_selector(), gdtrBase);									\
	(virtCpuInfo)->guestVmcb.statusFields.ds.attrib = GetSegmentAttribute(_ds_selector(), gdtrBase).AsUInt16;						\
																																	\
	(virtCpuInfo)->guestVmcb.statusFields.es.selector = _es_selector();																\
	(virtCpuInfo)->guestVmcb.statusFields.es.base = GetSegmentBaseAddress(_es_selector(), gdtrBase);								\
	(virtCpuInfo)->guestVmcb.statusFields.es.limit = GetSegmentLimit2(_es_selector(), gdtrBase);									\
	(virtCpuInfo)->guestVmcb.statusFields.es.attrib = GetSegmentAttribute(_es_selector(), gdtrBase).AsUInt16;						\
																																	\
	(virtCpuInfo)->guestVmcb.statusFields.ss.selector = _ss_selector();																\
	(virtCpuInfo)->guestVmcb.statusFields.ss.base = GetSegmentBaseAddress(_ss_selector(), gdtrBase);								\
	(virtCpuInfo)->guestVmcb.statusFields.ss.limit = GetSegmentLimit2(_ss_selector(), gdtrBase);									\
	(virtCpuInfo)->guestVmcb.statusFields.ss.attrib = GetSegmentAttribute(_ss_selector(), gdtrBase).AsUInt16;						\
																																	\
	(virtCpuInfo)->guestVmcb.statusFields.fs.selector = _fs_selector();																\
	(virtCpuInfo)->guestVmcb.statusFields.fs.limit = GetSegmentLimit2(_fs_selector(), gdtrBase);									\
	(virtCpuInfo)->guestVmcb.statusFields.fs.attrib = GetSegmentAttribute(_fs_selector(), gdtrBase).AsUInt16;						\
																																	\
	(virtCpuInfo)->guestVmcb.statusFields.gs.selector = _gs_selector();																\
	(virtCpuInfo)->guestVmcb.statusFields.gs.limit = GetSegmentLimit2(_gs_selector(), gdtrBase);									\
	(virtCpuInfo)->guestVmcb.statusFields.gs.attrib = GetSegmentAttribute(_gs_selector(), gdtrBase).AsUInt16;						\
																																	\
	(virtCpuInfo)->guestVmcb.statusFields.ldtr.selector = ldtrSelector;																\
	(virtCpuInfo)->guestVmcb.statusFields.ldtr.base = GetSegmentBaseAddress(ldtrSelector, gdtrBase);								\
	(virtCpuInfo)->guestVmcb.statusFields.ldtr.limit = GetSegmentLimit2(ldtrSelector, gdtrBase);									\
	(virtCpuInfo)->guestVmcb.statusFields.ldtr.attrib = GetSegmentAttribute(ldtrSelector, gdtrBase).AsUInt16;						\
																																	\
	(virtCpuInfo)->guestVmcb.statusFields.tr.selector = trSelector;																	\
	(virtCpuInfo)->guestVmcb.statusFields.tr.base = GetSegmentBaseAddress(trSelector, gdtrBase);									\
	(virtCpuInfo)->guestVmcb.statusFields.tr.limit = GetSegmentLimit2(trSelector, gdtrBase);										\
	(virtCpuInfo)->guestVmcb.statusFields.tr.attrib = GetSegmentAttribute(trSelector, gdtrBase).AsUInt16;							\
																																	\
	(virtCpuInfo)->guestVmcb.statusFields.fs.base = __readmsr(IA32_MSR_FS_BASE);													\
	(virtCpuInfo)->guestVmcb.statusFields.gs.base = __readmsr(IA32_MSR_GS_BASE);													\
	(virtCpuInfo)->guestVmcb.statusFields.kernelGsBase = __readmsr(IA32_MSR_KERNEL_GS_BASE);										\
																																	\
	(virtCpuInfo)->guestVmcb.statusFields.star = __readmsr(IA32_MSR_STAR);															\
	(virtCpuInfo)->guestVmcb.statusFields.lstar = __readmsr(IA32_MSR_LSTAR);														\
	(virtCpuInfo)->guestVmcb.statusFields.cstar = __readmsr(IA32_MSR_CSTAR);														\
	(virtCpuInfo)->guestVmcb.statusFields.sfmask = __readmsr(IA32_MSR_SF_MASK);														\
																																	\
	(virtCpuInfo)->guestVmcb.statusFields.efer = __readmsr(IA32_MSR_EFER);															\
																																	\
	(virtCpuInfo)->guestVmcb.statusFields.cr0 = __readcr0();																		\
	(virtCpuInfo)->guestVmcb.statusFields.cr2 = __readcr2();																		\
	(virtCpuInfo)->guestVmcb.statusFields.cr3 = __readcr3();																		\
	(virtCpuInfo)->guestVmcb.statusFields.cr4 = __readcr4();																		\
																																	\
	(virtCpuInfo)->guestVmcb.statusFields.rax = (UINT64)(rax_val);																	\
	(virtCpuInfo)->guestVmcb.statusFields.rflags = (UINT64)(rflags_val);															\
	(virtCpuInfo)->guestVmcb.statusFields.rsp = (UINT64)(rsp_val);																	\
	(virtCpuInfo)->guestVmcb.statusFields.rip = (UINT64)(rip_val);																	\
	(virtCpuInfo)->guestVmcb.statusFields.gPat = __readmsr(IA32_MSR_PAT);															\
																																	\
	(virtCpuInfo)->guestVmcb.statusFields.cpl = _cs_selector() & 0x3;

#endif
