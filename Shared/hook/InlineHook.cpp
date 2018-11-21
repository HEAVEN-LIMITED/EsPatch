#include "InlineHook.h"
#include "..\hde32\hde32.h"

LPVOID OriginalMemArea;


void SafeMemcpyPadded(LPVOID destination, LPVOID source, DWORD size)
{
	BYTE SourceBuffer[8];
	if (size > 8)
		return;
	memcpy(SourceBuffer, (UCHAR*)destination, 8);
	memcpy(SourceBuffer, (UCHAR*)source, size);
#ifndef NO_INLINE_ASM
	__asm
	{
		lea esi, SourceBuffer;
		mov edi, destination;

		mov eax, [edi];
		mov edx, [edi + 4];
		mov ebx, [esi];
		mov ecx, [esi + 4];

		lock cmpxchg8b[edi];
	}
#else
	_InterlockedCompareExchange64((LONGLONG *)destination, *(LONGLONG *)SourceBuffer, *(LONGLONG *)destination);
#endif
}


BOOL HookFunction(LPVOID func, LPVOID proxy, LPVOID original, PDWORD length)
{
	VMP_BEGIN
		LPVOID FunctionAddress = func;
	DWORD TrampolineLength = 0, OriginalProtection;
	hde32s disam;
	BYTE Jump[5] = { 0xE9, 0x00, 0x00, 0x00, 0x00 };
	if (!FunctionAddress)
		return FALSE;
	while (TrampolineLength < 5)
	{
		LPVOID InstPointer = (LPVOID)((DWORD)FunctionAddress + TrampolineLength);
		TrampolineLength += hde32_disasm(InstPointer, &disam);
	}
	memcpy((UCHAR*)original, (UCHAR*)FunctionAddress, TrampolineLength);
	*(DWORD *)(Jump + 1) = ((DWORD)FunctionAddress + TrampolineLength) - ((DWORD)original + TrampolineLength + 5);
	memcpy((UCHAR*)((DWORD)original + TrampolineLength), Jump, 5);
	if (!VirtualProtect(FunctionAddress, TrampolineLength, PAGE_EXECUTE_READWRITE, &OriginalProtection))
		return FALSE;
	*(DWORD *)(Jump + 1) = (DWORD)proxy - (DWORD)FunctionAddress - 5;
	SafeMemcpyPadded(FunctionAddress, Jump, 5);
	VirtualProtect(FunctionAddress, TrampolineLength, OriginalProtection, &OriginalProtection);
	FlushInstructionCache(GetCurrentProcess(), FunctionAddress, TrampolineLength);
	*length = TrampolineLength;
	return TRUE;
	VMP_END
}

BOOL UnhookFunction(LPVOID func, LPVOID original, DWORD length)
{
	VMP_BEGIN
		LPVOID FunctionAddress = func;
	DWORD OriginalProtection;
	if (!FunctionAddress)
		return FALSE;
	if (!VirtualProtect(FunctionAddress, length, PAGE_EXECUTE_READWRITE, &OriginalProtection))
		return FALSE;
	SafeMemcpyPadded(FunctionAddress, original, length);
	VirtualProtect(FunctionAddress, length, PAGE_EXECUTE_READWRITE, &OriginalProtection);
	FlushInstructionCache(GetCurrentProcess(), FunctionAddress, length);
	return TRUE;
	VMP_END
}


void InlineHook_CommitHook(INLINEHOOK_HOOKTABLE *HookTable, int sizeOfTable)
{
	VMP_BEGIN
	int i, NumEntries = sizeOfTable / sizeof(INLINEHOOK_HOOKTABLE);
	OriginalMemArea = VirtualAlloc(NULL, 25 * NumEntries, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
	if (!OriginalMemArea)
		return;
	for (i = 0; i < NumEntries; i++)
	{
		*(LPVOID *)HookTable[i].original = (LPVOID)((DWORD)OriginalMemArea + (i * 25));
		HookFunction(HookTable[i].func, HookTable[i].proxy, *(LPVOID *)HookTable[i].original, &HookTable[i].length);
	}
	VMP_END
}

void InlineHook_CommitUnhook(INLINEHOOK_HOOKTABLE *HookTable, int sizeOfTable)
{
	VMP_BEGIN
	int i, NumEntries = sizeOfTable / sizeof(INLINEHOOK_HOOKTABLE);
	for (i = 0; i < NumEntries; i++)
		UnhookFunction(HookTable[i].func, *(LPVOID *)HookTable[i].original, HookTable[i].length);
	VirtualFree(OriginalMemArea, 0, MEM_RELEASE);
	VMP_END
}
