#pragma once
#include <Windows.h>
#include <winternl.h>
#include "NtdllHash.h"

extern __stdcall GateInit(WORD ssn);
extern __stdcall GateSyscall();

#define MAX_CALLS_CACHE 32 // change it if needed

typedef struct {

	UINT32 hash;
	WORD ssn;

} SyscallCache;


typedef struct {

	WORD wSSN;
	BYTE* dllBase;
	DWORD Cached; // number of hashed calls
	SyscallCache Cache[MAX_CALLS_CACHE]; // cache max
	PIMAGE_EXPORT_DIRECTORY exportDir;

} GateCallCtx;

GateCallCtx* GateNewCtx();
VOID GateInitCall(GateCallCtx* ctx, UINT32 funcHash);