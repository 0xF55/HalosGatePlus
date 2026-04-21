
.data

	GateSSN DWORD 000h

.code
	

	GateInit proc

		mov GateSSN, 000h
		mov GateSSN, ecx
		ret

	GateInit endp

	GateSyscall proc

		mov r10,rcx
		mov eax,GateSSN
		jmp scall
		nop
		nop
		nop
		nop
	scall:
		syscall
		ret


	GateSyscall endp
end