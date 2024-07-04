.data

LStarHookCallback QWORD 0
OldLStarEntry QWORD 0

PUBLIC LStarHookCallback, OldLStarEntry

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

LStarHookEntry Proc
	swapgs
	stac
	mov   qword ptr gs:[10h],rsp
	mov   rsp,qword ptr gs:[1A8h]
	push rax
	push rbx
	push rcx
	push rdx
	push rdi
	push rsi
	push rbp
	push r8
	push r9
	push r10
	push r11
	push r12
	push r13
	push r14
	push r15
	pushfq
	
	call [LStarHookCallback]

	popfq
	pop r15
	pop r14
	pop r13
	pop r12
	pop r11
	pop r10
	pop r9
	pop r8
	pop rbp
	pop rsi
	pop rdi
	pop rdx
	pop rcx
	pop rbx
	pop rax
	mov rsp,qword ptr gs:[10h]
	clac
	swapgs

	jmp [OldLStarEntry]

LStarHookEntry Endp
End

End