.code

SetRegsThenCpuid Proc
	;备份寄存器
	push rax
	push rbx
	push rcx
	push rdx
	push r8
	push r9

	mov eax, ecx
	mov ebx, edx
	mov ecx, r8d
	mov rdx, r9
	cpuid
	;还原寄存器
	pop r9
	pop r8
	pop rdx
	pop rcx
	pop rbx
	pop rax
	
	ret
SetRegsThenCpuid Endp

End