.code

SetRegsThenCpuid Proc
	mov eax, ecx
	mov ebx, edx
	mov ecx, r8d
	mov rdx, r9
	cpuid
	ret
SetRegsThenCpuid Endp

End