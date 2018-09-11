#pragma once
#include "windows.h"
#include "..\VMP.h"

typedef struct {
	char *pFuncName;
	PVOID pNewFunc;
	PVOID pOrigFunc;
}PEHOOK_FUNCTABLE;

typedef struct {
	HMODULE hModule;
	UINT FuncCount;
	char *targetLibName;
	PEHOOK_FUNCTABLE FuncTable[1];
}PEHOOK_HOOKTABLE;

void PEHook_IATHook(PEHOOK_HOOKTABLE *HookTable);
//void PEHook_EATHook(HOOKTABLE *HookTable);