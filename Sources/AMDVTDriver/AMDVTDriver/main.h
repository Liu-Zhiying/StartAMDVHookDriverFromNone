#ifndef MAIN_H
#define MAIN_H

#include <ntddk.h>
#include <wdm.h>
#include <stdio.h>
#include <intrin.h>
#include "SVM.h"
#include "Hook.h"
#include "PageTable.h"

class GlobalManager : public IManager
{
	PageTableManager ptManager;
	SVMManager svmManager;
	MsrHookManager<1> msrHookManager;
	NptHookManager nptHookManager;
	SimulateSceHookManager simulateSceHookManager;
public:
	void SetMsrHookParameters();
	void SetNptHook();
	void SetNpt();
	void HookApi();
	void EnableMsrHook();
	virtual NTSTATUS Init() override;
	virtual void Deinit() override;
	virtual ~GlobalManager();
};


//��ѡһȡ��ע�ͣ�������������������
#define TEST_NPT_HOOK
//#define TEST_MSR_HOOK

#endif