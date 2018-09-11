#include "PEHook.h"

void PEHook_IATHook(PEHOOK_HOOKTABLE *HookTable)
{
	VMP_BEGIN
	HMODULE hModule = HookTable->hModule;
	char *targetLibName = HookTable->targetLibName;
	if (!hModule) return;
	IMAGE_DOS_HEADER *pImageDosHearder = (IMAGE_DOS_HEADER*)hModule;
	IMAGE_OPTIONAL_HEADER *pImageOptionalHeader = (IMAGE_OPTIONAL_HEADER*)((CHAR*)hModule + pImageDosHearder->e_lfanew + 24);
	IMAGE_IMPORT_DESCRIPTOR *pImageImportDescriptor = (IMAGE_IMPORT_DESCRIPTOR*)((CHAR*)hModule + pImageOptionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);
	IMAGE_THUNK_DATA *pImageThunkData = NULL;
	IMAGE_THUNK_DATA *pImageOrigThunkData = NULL;

	while (pImageImportDescriptor->Characteristics != 0)
	{
		char *libName = (CHAR*)((DWORD)hModule + pImageImportDescriptor->Name);
		if (lstrcmpi(libName, targetLibName) == 0)
		{
			pImageThunkData = (IMAGE_THUNK_DATA*)((DWORD)hModule + pImageImportDescriptor->FirstThunk);
			pImageOrigThunkData = (IMAGE_THUNK_DATA*)((DWORD)hModule + pImageImportDescriptor->OriginalFirstThunk);
			break;
		}
		pImageImportDescriptor++;
	}
	if (pImageThunkData == NULL) return;
	if (pImageOrigThunkData == NULL) return;
	while (pImageThunkData->u1.Function)
	{
		SIZE_T dwSize = sizeof(DWORD);
		DWORD dwOldProtect = 0;
		DWORD dwNewProtect = 0;
		IMAGE_IMPORT_BY_NAME *pImpByName = pImageOrigThunkData->u1.AddressOfData;
		DWORD *FuncAddr = (DWORD)&(pImageThunkData->u1.Function);
		char *funName = (CHAR*)((DWORD)hModule + pImpByName->Name);
		if (!(pImageOrigThunkData->u1.Ordinal & IMAGE_ORDINAL_FLAG)) {
			for (int i = 0; i < HookTable->FuncCount; i++) {
				PVOID pNewFunc = HookTable->FuncTable[i].pNewFunc;
				if (!lstrcmp(funName, HookTable->FuncTable[i].pFuncName))
				{
					if (VirtualProtect(FuncAddr, dwSize, PAGE_READWRITE, &dwOldProtect)) {
						HookTable->FuncTable[i].pOrigFunc = *FuncAddr;
						if(pNewFunc)
							*FuncAddr = pNewFunc;
						VirtualProtect(FuncAddr, dwSize, dwOldProtect, &dwNewProtect);
					}
					break;
				}
			}
		}
		pImageThunkData++;
		pImageOrigThunkData++;
	}
	return;
	VMP_END
}

/*
void PEHook_EATHook(PEHOOK_HOOKTABLE *HookTable)
{
	HMODULE hModule = HookTable->hModule;
	if (!hModule) return;
	IMAGE_DOS_HEADER *pImageDosHearder = (IMAGE_DOS_HEADER*)hModule;
	IMAGE_OPTIONAL_HEADER *pImageOptionalHeader = (IMAGE_OPTIONAL_HEADER*)((UCHAR*)hModule + pImageDosHearder->e_lfanew + 24);
	IMAGE_EXPORT_DIRECTORY *pImageExportDirectory = (IMAGE_EXPORT_DIRECTORY*)((UCHAR*)hModule + pImageOptionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);
	DWORD dwOldProtect = 0, dwNewProtect = 0;
	PUSHORT funcOrd = (USHORT*)((UCHAR*)hModule + pImageExportDirectory->AddressOfNameOrdinals);
	PULONG funcAddr = (ULONG*)((UCHAR*)hModule + pImageExportDirectory->AddressOfFunctions);
	PULONG funcNames = (ULONG*)((UCHAR*)hModule + pImageExportDirectory->AddressOfNames);
	SIZE_T dwSize = sizeof(DWORD);
	for (int i = 0; i < HookTable->FuncCount; i++) {
		PVOID pNewFunc = HookTable->FuncTable[i].pNewFunc;
		if (((DWORD)pNewFunc - (DWORD)hModule) > 0xFFFFFFFF) {
			return;
		}
	}
	for (int i = 0; i < pImageExportDirectory->NumberOfNames; i++)
	{
		for (int j = 0; j < HookTable->FuncCount; j++) {
			PVOID pFunc = HookTable->FuncTable[i].pFunc;
			PVOID pNewFunc = HookTable->FuncTable[i].pNewFunc;
			DWORD dwAddr = ((DWORD)pNewFunc - (DWORD)hModule);
			if ((UCHAR*)hModule + funcAddr[funcOrd[i]] == (DWORD)pFunc)
			{
				if (VirtualProtect(&funcAddr[funcOrd[i]], dwSize, PAGE_READWRITE, &dwOldProtect)) {
					funcAddr[funcOrd[i]] = (ULONG)dwAddr;
					VirtualProtect(&funcAddr[funcOrd[i]], dwSize, dwOldProtect, &dwNewProtect);
					HookTable->FuncTable[i].bStatus = TRUE;
				}
			}
		}
	}
	return;
}
*/