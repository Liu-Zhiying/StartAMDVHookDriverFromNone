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

	;写入参数
	mov rax, [rcx]
	mov rbx, [rdx]
	mov rcx, [r8]
	mov rdx, [r9]

	cpuid

	;回写参数
	mov r9, [rsp + 18h]
	mov [r9], rax
	mov r9, [rsp + 10h]
	mov [r9], rbx
	mov r9, [rsp + 8h]
	mov [r9], rcx
	mov r9, [rsp + 0h]
	mov [r9], rdx

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
	;允许r0访问r3数据
	stac
	;交换RSP
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
	;还原rsp
	mov rsp,qword ptr gs:[10h]
	;禁止r3访问r0数据
	clac
	swapgs

	jmp [OldLStarEntry]

LStarHookEntry Endp

;允许r0访r3数据
_mystac Proc
stac
ret
_mystac Endp

;静止r0访问r3数据
_myclac Proc
clac
ret
_myclac Endp

End