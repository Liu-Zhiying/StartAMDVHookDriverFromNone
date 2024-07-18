#include <stdio.h>
#include <stdlib.h>
#include <windows.h>
//typedef unsigned int ULONG32;

ULONG32 __declspec(naked) NBPCall (ULONG32 knock) {
	__asm { 
	push 	ebp
	mov	ebp, esp
	push	ebx
	push	ecx
	push	edx
	cpuid
	pop	edx
	pop	ecx
	pop	ebx
	mov	esp, ebp
	pop	ebp
	ret
	}
}
int __cdecl main(int argc, char **argv) {
	ULONG32 knock;
	if (argc != 2) {
		printf ("bpknock <magic knock>\n");
		return 0;
	}
	knock = strtoul (argv[1], 0, 0);

	__try {
		printf ("knock answer: %#x\n", NBPCall (knock));
	} __except (EXCEPTION_EXECUTE_HANDLER) {
		printf ("CPUDID caused exception");
		return 0;
	}
	
	return 0;

}
