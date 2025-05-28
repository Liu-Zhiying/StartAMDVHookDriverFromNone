extern VmExitHandler : Proc
extern FillMachineFrame: Proc
extern CompareGenericRegisters: Proc

.code

BACKUP_REGISTERS Macro baseAddrReg
	movaps xmmword ptr [baseAddrReg + 000h], xmm0
	movaps xmmword ptr [baseAddrReg + 010h], xmm1
	movaps xmmword ptr [baseAddrReg + 020h], xmm2
	movaps xmmword ptr [baseAddrReg + 030h], xmm3
	movaps xmmword ptr [baseAddrReg + 040h], xmm4
	movaps xmmword ptr [baseAddrReg + 050h], xmm5
	movaps xmmword ptr [baseAddrReg + 060h], xmm6
	movaps xmmword ptr [baseAddrReg + 070h], xmm7
	movaps xmmword ptr [baseAddrReg + 080h], xmm8
	movaps xmmword ptr [baseAddrReg + 090h], xmm9
	movaps xmmword ptr [baseAddrReg + 0A0h], xmm10
	movaps xmmword ptr [baseAddrReg + 0B0h], xmm11
	movaps xmmword ptr [baseAddrReg + 0C0h], xmm12
	movaps xmmword ptr [baseAddrReg + 0D0h], xmm13
	movaps xmmword ptr [baseAddrReg + 0E0h], xmm14
	movaps xmmword ptr [baseAddrReg + 0F0h], xmm15
	mov [baseAddrReg + 100h], r15
	mov [baseAddrReg + 108h], r14
	mov [baseAddrReg + 110h], r13
	mov [baseAddrReg + 118h], r12
	mov [baseAddrReg + 120h], r11
	mov [baseAddrReg + 128h], r10
	mov [baseAddrReg + 130h], r9
	mov [baseAddrReg + 138h], r8
	mov [baseAddrReg + 140h], rbp
	mov [baseAddrReg + 148h], rsi
	mov [baseAddrReg + 150h], rdi
	mov [baseAddrReg + 158h], rdx
	mov [baseAddrReg + 160h], rcx
	mov [baseAddrReg + 168h], rbx
Endm

RESTORE_REGISTERS Macro baseAddrReg
	movaps xmm0, xmmword ptr [baseAddrReg + 000h]
	movaps xmm1, xmmword ptr [baseAddrReg + 010h]
	movaps xmm2, xmmword ptr [baseAddrReg + 020h]
	movaps xmm3, xmmword ptr [baseAddrReg + 030h]
	movaps xmm4, xmmword ptr [baseAddrReg + 040h]
	movaps xmm5, xmmword ptr [baseAddrReg + 050h]
	movaps xmm6, xmmword ptr [baseAddrReg + 060h]
	movaps xmm7, xmmword ptr [baseAddrReg + 070h]
	movaps xmm8, xmmword ptr [baseAddrReg + 080h]
	movaps xmm9, xmmword ptr [baseAddrReg + 090h]
	movaps xmm10, xmmword ptr [baseAddrReg + 0A0h]
	movaps xmm11, xmmword ptr [baseAddrReg + 0B0h] 
	movaps xmm12, xmmword ptr [baseAddrReg + 0C0h] 
	movaps xmm13, xmmword ptr [baseAddrReg + 0D0h]
	movaps xmm14, xmmword ptr [baseAddrReg + 0E0h]
	movaps xmm15, xmmword ptr [baseAddrReg + 0F0h]
	mov r15, [baseAddrReg + 100h]
	mov r14, [baseAddrReg + 108h]
	mov r13, [baseAddrReg + 110h]
	mov r12, [baseAddrReg + 118h]
	mov r11, [baseAddrReg + 120h]
	mov r10, [baseAddrReg + 128h]
	mov r9, [baseAddrReg + 130h] 
	mov r8, [baseAddrReg + 138h]
	mov rbp, [baseAddrReg + 140h]
	mov rsi, [baseAddrReg + 148h] 
	mov rdi, [baseAddrReg + 150h]
	mov rdx, [baseAddrReg + 158h]
	mov rcx, [baseAddrReg + 160h]
	mov rbx, [baseAddrReg + 168h]
Endm

ALLOC_STACK_AND_CALL Macro functionName, stackSize

sub rsp, stackSize
call functionName
add rsp, stackSize

Endm

_mysgdt Proc
	;ִ�д洢�Ĵ�������ֻ��Ҫ10���ֽڣ����﷽��һ��
	sub rsp, 10h
	sgdt [rsp]
	;ȡlimit
	mov ax, [rsp]
	mov word ptr [rdx], ax
	;ȡbase
	mov rax, [rsp + 2]
	mov qword ptr [rcx], rax
	;��ԭջ
	add rsp, 10h
	ret
_mysgdt Endp

_mysidt Proc
;ִ�д洢�Ĵ�������ֻ��Ҫ10���ֽڣ����﷽��һ��
	sub rsp, 10h
	sidt [rsp]
	;ȡlimit
	mov ax, [rsp]
	mov word ptr [rdx], ax
	;ȡbase
	mov rax, [rsp + 2]
	mov qword ptr [rcx], rax
	;��ԭջ
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
	mov ax,cs
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

_save_or_load_regs Proc	
	BACKUP_REGISTERS rcx
	
	;ȡ��ǰRflags
	pushfq
	mov rax, [rsp]
	mov [rcx + 178h], rax
	popfq

	;��ripָ���ж��Ƿ�load�Ĵ�����λ��
	mov rax, offset if_load_regs
	mov [rcx + 180h], rax
	
	;ȡ��������֮��ĵ�һ����ַ
	;����ǽ������⻯֮��ִ�е�if_load_regsʱ���������Ϊload�Ĵ���֮���ִ�е�ַ
	mov rax, [rsp]
	mov [rcx + 190h], rax

	;ȡ��������֮���rsp����8����callѹ��ķ��ص�ַ
	;����ǽ������⻯֮��ִ�е�if_load_regsʱ���������Ϊ���ԭ��rsp
	mov rax, rsp
	add rax, 8h
	mov [rcx + 188h], rax

	;rax��0������load�Ĵ���
	;����ǽ������⻯֮���ٴ�ִ�е�if_load_regs
	;��Ϊrax�������ã���load�Ĵ���

	mov rax, 0h

if_load_regs:
	test rax, rax
	jz return

	RESTORE_REGISTERS rax

	;rax ����ԭ
	;mov rax, [rcx + 170h]

	;��ԭrflags
	push qword ptr [rcx + 178h]
	popfq
	;��ԭrsp
	mov rsp, [rax + 188h]
	;��ԭrax
	mov rax, [rax + 170h]
	jmp qword ptr [rcx + 190h]

return:
	;��ԭrax
	mov rax, [rcx + 170h]
	ret
_save_or_load_regs Endp

_run_svm_vmrun Proc Frame
;����ԭջָ��
mov rax, rsp

;�л�ջ
mov rsp, r9

;MACHINE_FRAME �ṹ��ռ��40�ֽ�
sub rsp, 28h
;��8�ֽںö��뵽16�ֽ�
sub rsp, 8h

;��ԭ����ջָ��ѹ���ڴ���
;��һ��push��Ϊ��rsp���뵽16
push rax
push rax

;���ݲ���
;pStack ����
push r9
;pHostVmcbPhyAddr ����
push r8
;pGuestVmcbPhyAddr ����
push rdx
;pVirtCpuInfo ����
push rcx

;��proc frame �� .endprolog ���������棬rsp�ܹ��ƶ���0x60
;���� MACHINE_FRAME ռ�� 40 (0x28) �ֽ�
;Ȼ���Ƕ���� 8(0x8) �ֽ� �����ֽ�
;Ȼ��������call�������л�rsp֮ǰ�ľ�rspֵ 16 (0x10) �ֽڣ���������Ϊ��16�ֽڶ��룩
;Ȼ�����ĸ������ı��� 32 (0x20) �ֽ�
;���� 32 (0x20) �ֽ�Ԥ�������������˳���֧����ʱ��ջ
;��ȥ.pushframe �� MACHINE_FRAME ռ�õĿռ� ������ ȫ������Ϊ .allocstack ����ֵ
;��������һЩ���˶�.pushframe .allocstack ����ָ������
;windbg������ �����callָ��ķ��ص�ַ֮�� �ȼ��� .allocstack �� 0x1f8 ���������ⲿ��ָ��Ĵ��������Ű��� .pushframe ��ȡ MACHINE_FRAME �ṹ
;.pushframe .allocstack ����Ҫ�ͻ�������Ӧ
;windbg ֻ�ǵ���������������Щαָ��
;����Ӱ�� windbg �Ե���ջ��ԭ��֮����Щָ�����ݺ�˳��
;����Щָ�������Щ���ָ��֮��û���κι�ϵ
;�����Ұ���Щαָ���д�����ﲢ�� .allocstack ������ �Ƕಽʹ��ջ�ĺ�

.pushframe
.allocstack 38h
.endprolog

enter_guest:

;����guest״̬
mov rax, [rsp + 8h]
vmload rax

;Ϊ�˵��üĴ�����麯�����ݼĴ���
push rcx
push rdx

;�ѵ�ǰ�Ĵ�����������pVirtCpuInfo->regsBackup.genericRegisters2
mov rax, [rsp + 10h]
add rax, 41A0h
BACKUP_REGISTERS rax

;CompareGenericRegisters ����������
;rcx = &pVirtCpuInfo->regsBackup.genericRegisters2
;rdx = &pVirtCpuInfo->regsBackup.genericRegisters1
mov rcx, rax
mov rdx, rcx
sub rdx, 1A0h

;���Ĵ���
ALLOC_STACK_AND_CALL CompareGenericRegisters, 30h

;������ɣ���ԭ�Ĵ���
pop rdx
pop rcx

;����guestģʽ
mov rax, [rsp + 8h]
vmrun rax

;���exitcode�Ƿ��� VMEXIT_INVALID(-1) VMEXIT_BUSY(-2) VMEXIT_IDLE_REQUIRED(-3)
;����ǣ�ת��return��ţ������ŻḺ���л���ԭջָ�벢���أ�����֮��ֱ����������EnterVirtualization�е���RunVM֮��Ĵ��룩
mov rax, [rsp]
mov rax, [rax + 70h]
cmp rax, -1
je return
cmp rax, -2
je return
cmp rax, -3
je return

;����guest״̬
mov rax, [rsp + 8h]
vmsave rax

;����host״̬
mov rax, [rsp + 10h]
vmload rax

;����pVirtCpuInfo->regsBackup.genericRegisters1�ĵ�ַ
mov rax, [rsp]
add rax, 4000h
;����guest�Ĵ���
BACKUP_REGISTERS rax

;machineFrame ����
mov rcx, rsp
add rcx, 38h
;guestRegisters ����
mov rdx, [rsp]
add rdx, 4000h
;virtCpuInfo ����
mov r8, [rsp]
;���ú�����ʼ��MACHINE_FRAME
ALLOC_STACK_AND_CALL FillMachineFrame, 30h

;����exit handler
;pVirtCpuInfo ����
mov rcx, [rsp]
;pGuestRegisters ����
mov rdx, rcx
add rdx, 4000h
;pGuestVmcbPhyAddr ����
mov r8, [rsp + 8h]
;pHostVmcbPhyAddr ����
mov r9, [rsp + 10h]

;����Handler������
ALLOC_STACK_AND_CALL VmExitHandler, 30h

;����pVirtCpuInfo->regsBackup.genericRegisters1�ĵ�ַ
mov rax, [rsp]
add rax, 4000h

;�ָ�guest�Ĵ���
RESTORE_REGISTERS rax

;�ж��Ƿ��Ѿ��˳����⻯����Ҫ��ת��guest����һ��ָ��
mov rax, [rax + 190h]
test rax, rax
;�����ʱ��ת���˳�vmm�ķ�֧rax��ֵ����&pVMMVirtCpuInfo->regsBackup.genericRegisters1
jnz exit_virtualization

;����host״̬
mov rax, [rsp + 10h]
vmsave rax

;����ȥ��ִ��vmrun�ٴν���guest
jmp enter_guest

return:
;����ԭ����ջָ�벢����
mov rax, [rsp + 20h]
mov rsp, rax
ret

exit_virtualization:
;�л����ͻ���ջ
mov rsp, [rax + 188h]
;push �ͻ���nRip
push [rax + 198h]
;push �ͻ���rax
push [rax + 170h]
;push �ͻ���rflags
push [rax + 178h]
;��ԭrflags
popfq
;��ԭrax
pop rax
;���ؿͻ���nRipִ��
ret

_run_svm_vmrun Endp

End