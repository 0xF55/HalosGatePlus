
## What is new ?

1. HalosGate+ provides an abstraction layer for eaiser usage
2. Simple Caching Added
3. Ready to use
4. Provides all ntdll function hashes
- just type `hashFunctionName` for example:
1. `hashNtAllocateVirtualMemory`
2. `hashNtAllocateVirtualMemoryEx`
3. `NtCreateFile`, etc

### Steps to use

1. `#include "HalosGatePlus.h"`
2. `GateCallCtx* ctx = GateNewCtx();` Creates a new HalosGate+ context
3. `GateInitCall(ctx, hashFuncName)`
4. `GateSyscall(args...)`
## Usage

- Example:

```C
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

	GateInitCall(ctx, hashNtAllocateVirtualMemory);
	NTSTATUS status = GateSyscall((HANDLE)-1, &baseAddress1, 0, &RegionSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

	status = GateSyscall((HANDLE)-1, &baseAddress2, 0, &RegionSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

	printf("[+] Allocated 1: %p %d\n", baseAddress1, status);
	printf("[+] Allocated 2: %p %d\n", baseAddress2,status);

	return 0;
}

```

```C
[+] Allocated 1: 0000024104710000 0
[+] Allocated 2: 0000024104980000 0

H:\HalosGate+\HalosGate+\x64\Release\HalosGate+.exe (process 1216) exited with code 0 (0x0).
Press any key to close this window . . .
```

* if you want to change fnva hash,prime base: 
1. use apihash.py dllname
2. replace *NtdllHash.h* with new one
3. change fnva hash,prime in `HalosGate+.c`

## Credits / References

@boku7 impelementation of Halos Gate  

Reenz0h from @SEKTOR7net (Creator of the HalosGate technique )

@smelly__vx & @am0nsec ( Creators/Publishers of the Hells Gate technique )
