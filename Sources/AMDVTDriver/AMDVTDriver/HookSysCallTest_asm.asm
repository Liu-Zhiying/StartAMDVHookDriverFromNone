.code

extern SysCallHookLog : PROC
extern OldSysCallFunctionAddr : QWORD

SysCallHookEntry Proc
	stac
	sub rsp, 4000h
	push rcx
	push r11
	pushfq
	swapgs
	
	call SysCallHookLog

	swapgs
	popfq
	pop r11
	pop rcx
	add rsp, 4000h
	clac

	jmp [OldSysCallFunctionAddr]

SysCallHookEntry Endp
End