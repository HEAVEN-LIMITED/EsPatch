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

void InlineHook_CommitHook(INLINEHOOK_HOOKTABLE *HookTable, int sizeOfTable);
void InlineHook_CommitUnhook(INLINEHOOK_HOOKTABLE *HookTable, int sizeOfTable);
