#include <stdio.h>
#include "HalosGatePlus.h"

int main() {

	GateCallCtx* ctx = GateNewCtx();

	if (ctx == NULL) {
		printf("[!] Gate Init Error\n");
		return -1;
	}
	
	SIZE_T RegionSize = 0x140;

	PVOID baseAddress1 = NULL;
	PVOID baseAddress2 = NULL;
	
	GateInitCall(ctx, hashNtAllocateVirtualMemory); // initialize ssn
	
	NTSTATUS status = GateSyscall((HANDLE)-1, &baseAddress1, 0, (PSIZE_T)&RegionSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	
	printf("[+] Allocated 1: %p %d\n", baseAddress1, status);

	status = GateSyscall(GetCurrentProcess(), &baseAddress2, 0, &RegionSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

	printf("[+] Allocated 2: %p %d\n", baseAddress2, status);

	return 0;
}