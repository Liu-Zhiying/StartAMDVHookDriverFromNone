.code
_mysgdt Proc
	;执行存储寄存器数据只需要10个字节，这里方便一点
	sub rsp, 10h
	sgdt [rsp]
	;取limit
	mov ax, [rsp]
	mov word ptr [rdx], ax
	;取base
	mov rax, [rsp + 2]
	mov qword ptr [rcx], rax
	;还原栈
	add rsp, 10h
	ret
_mysgdt Endp

_mysidt Proc
;执行存储寄存器数据只需要10个字节，这里方便一点
	sub rsp, 10h
	sidt [rsp]
	;取limit
	mov ax, [rsp]
	mov word ptr [rdx], ax
	;取base
	mov rax, [rsp + 2]
	mov qword ptr [rcx], rax
	;还原栈
	add rsp, 10h
	ret
_mysidt Endp
	
_mysldt Proc
	sldt ax
	mov word ptr [rcx], ax
	ret
_mysldt Endp

_mystr Proc
	str ax
	mov word ptr [rcx], ax
	ret
_mystr Endp

_cs_selector Proc
	mov ax,cs;
	ret
_cs_selector Endp

_ds_selector Proc
	mov ax,ds
	ret
_ds_selector Endp

_es_selector Proc
	mov ax,es
	ret
_es_selector Endp

_fs_selector Proc
	mov ax,fs
	ret
_fs_selector Endp

_gs_selector Proc
	mov ax,gs
	ret
_gs_selector Endp

_ss_selector Proc
	mov ax,ss
	ret
_ss_selector Endp

_save_rip_rsp_rflags Proc
	;取函数返回之后的第一条地址
	mov rax, [rsp]
	mov [rcx], rax
	;取函数返回之后的rsp，加8抵消call压入的返回地址
	mov rax, rsp
	add rax, 8h
	mov [rdx], rax
	;取当前Rflags
	pushfq
	mov rax, [rsp]
	mov [r8], rax
	popfq

	ret
_save_rip_rsp_rflags Endp

_switch_stack Proc
;把返回地址pop到rdx，不会用原来的栈返回，可以确保栈平衡
;而且切换到新栈时需要返回地址让函数正确返回
pop rdx
;保留旧栈作为返回值
mov rax, rsp
;切换栈
mov rsp, rcx
;push返回地址用于返回
push rdx
ret
_switch_stack Endp

RunVM Proc
;mov rsp, r9
;push r9
;push r8
;push rdx
;push rcx

mov rax, rdx
enter_guest:
vmload rax
;vmrun rax
vmsave rax
;jmp enter_guest
ret

RunVM Endp

End