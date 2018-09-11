#pragma once
#include "windows.h"
#include "..\VMP.h"
#include "MemOp.h"

typedef struct
{
	LPVOID func;
	LPVOID proxy;	//new
	LPVOID original;	//old
	DWORD length;
} INLINEHOOK_HOOKTABLE;

void CommitHook(INLINEHOOK_HOOKTABLE *HookTable, int sizeOfHookArray);
void CommitUnhook(INLINEHOOK_HOOKTABLE *HookTable, int sizeOfHookArray);
