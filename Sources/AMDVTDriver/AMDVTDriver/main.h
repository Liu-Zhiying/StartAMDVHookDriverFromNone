#ifndef MAIN_H
#define MAIN_H

#include <ntddk.h>
#include <wdm.h>
#include <stdio.h>
#include <intrin.h>
#include "SVM.h"
#include "Hook.h"
#include "PageTable.h"
#include "Basic.h"

//��ѡһȡ��ע�ͣ�������������������
#define TEST_NPT_HOOK
//#define TEST_MSR_HOOK

//�Ƿ����NPT HOOKɾ��
//#define TEST_NPT_HOOK_REMOVE

class GlobalManager : public IManager
{
	SVMManager svmManager;
#if defined(TEST_NPT_HOOK)
	NptHookManager nptHookManager;
	FunctionCallerManager functionCallerManager;
#else
	MsrHookManager<1> msrHookManager;
#endif
public:

#if defined(TEST_NPT_HOOK)
	void HookApi();
#else
	void SetMsrHookParameters();
	void EnableMsrHook();
#endif
	
	virtual NTSTATUS Init() override;
	virtual void Deinit() override;
	virtual ~GlobalManager();
};

#endif
