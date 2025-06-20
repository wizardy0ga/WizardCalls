;
; Generated with wizardcalls v-2.0.0
; Template version: 2.0.0
; Commandline: .\wizardcalls.py --apicalls NtOpenProcess NtWriteVirtualMemory NtCreateThreadEx NtProtectVirtualMemory NtFreeVirtualMemory --outdir .\example-output\position-independent\
; ID: bb7837bf-0a12-4824-8779-1da5a580b80c
;

.code
	; Set non-volatile register to address of SYSCALL structure pointer
	SetSyscallPointer proc
		xor r15, r15			; r15 = 0
		mov r15, rcx			; move to SYSCALL structure to non-volatile register
		ret
	SetSyscallPointer endp

	; Resolve SSN & syscall instruction address from SYSCALL structure to execute system call
	SystemCall proc
		mov r10, rcx			; move parameters to r10 register
		mov eax, [r15]			; eax = pSyscall->SSN
		jmp qword ptr [r15 + 8]	; jump to syscall address @ pSyscall->JumpAddress
	SystemCall endp

end