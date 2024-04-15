#include "SVM.h"
#include <intrin.h>

#pragma code_seg("PAGE")
void CPUString(char* outputString)
{
	PAGED_CODE();
	UINT32 cpuid_result[4] = {};
	__cpuidex((int*)cpuid_result, 0, 0);
	memcpy(outputString, &cpuid_result[1], sizeof(UINT32));
	memcpy(outputString + sizeof(UINT32), &cpuid_result[3], sizeof(UINT32));
	memcpy(outputString + sizeof(UINT32) * 2, &cpuid_result[2], sizeof(UINT32));
	outputString[3 * sizeof(UINT32)] = 0;
}

#pragma code_seg("PAGE")
SVMStatus SVMManager::CheckSVM()
{
	PAGED_CODE();
	char szCpuString[13];
	CPUString(szCpuString);
	if (strcmp(szCpuString, "AuthenticAMD"))
		return SVMS_NONAMDCPU;

	SVMStatus result = SVMS_UNUSED;
	UINT32 cpuid_result[4] = {};

	do
	{
		//查询SMV支持
		__cpuidex((int*)cpuid_result, 0x80000001, 0);

		//ecx 第 1 位 (0 base 下同)
		if (!(cpuid_result[2] & 0x4))
			break;

		result = ((SVMStatus)(result | SVMS_ENABLED));

		//查询SVM启用
		UINT64 msrValue = __readmsr(0xC0010114);

		//eax 第 4 位
		if (msrValue & 0x10)
			break;

		result = ((SVMStatus)(result | SVMS_SUPPORTED));
	} while (false);

	return result;
}

#pragma code_seg("PAGE")
NTSTATUS SVMManager::Init()
{
	PAGED_CODE();
	NTSTATUS result = STATUS_SUCCESS;
	do
	{
		SVMStatus svmStatus = CheckSVM();

		result = STATUS_INSUFFICIENT_RESOURCES;

		if (svmStatus & SVMStatus::SVMS_NONAMDCPU)
		{
			KdPrint(("SVMManager::Init(): Not AMD Processor!\n"));
			break;
		}

		if (!(svmStatus & SVMStatus::SVMS_SUPPORTED))
		{
			KdPrint(("SVMManager::Init(): SVM feature is not supported!\n"));
			break;
		}

		if (!(svmStatus & SVMStatus::SVMS_ENABLED))
		{
			KdPrint(("SVMManager::Init(): SVM feature is not enabled!\n"));
			break;
		}

		result = STATUS_SUCCESS;

	} while (false);
	
	return result;
}

#pragma code_seg("PAGE")
void SVMManager::Deinit()
{
	PAGED_CODE();
}
