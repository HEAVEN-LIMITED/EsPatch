#include "EsPatchLoader.h"

typedef BOOL(APIENTRY* pfnDllMain)(HINSTANCE hMod, ULONG ulAct, PVOID p);
void exchangeHookProc(PVOID *a);

/*
void WINAPI dbgFunc() {
	if (GetModuleHandle(NULL) == GetModuleHandle("ESurfingSvr.exe")) {
		Sleep(8000);
		LoadLibrary("C:\\Program Files\\rohitab.com\\API Monitor\\apimonitor-drv-x86.sys");
	}
}
*/

BOOL APIENTRY DLLMain(HINSTANCE hMod, ULONG ulAct, PVOID p)
{
	if (ulAct == DLL_PROCESS_ATTACH)
	{
		//CreateThread(NULL,NULL, (LPTHREAD_START_ROUTINE)dbgFunc,NULL,NULL,NULL);
		flmInitFuncs();
		HMODULE hModule = LoadLibrary("EsPatch.dll");
		DbgOut("hModule=%08X, gle=%d", hModule, GetLastError());
		if (hModule) {
			pfnDllMain espDllMain;
			IMAGE_DOS_HEADER *pImageDosHearder = (IMAGE_DOS_HEADER*)hModule;
			IMAGE_OPTIONAL_HEADER *pImageOptionalHeader = (IMAGE_OPTIONAL_HEADER*)((CHAR*)hModule + pImageDosHearder->e_lfanew + 24);
			espDllMain = (DWORD)hModule + pImageOptionalHeader->AddressOfEntryPoint;
			DbgOut("esp-dllEntry=%08X", espDllMain);
			espDllMain(0x2B2B2B2B, 0x20170330, exchangeHookProc);
			DbgOut("exec espDllMain ok");
		}
		else {
			if (GetModuleHandle(NULL) == GetModuleHandle("ESurfingClient.exe")) {
				MessageBox(0, "无法加载EsPatch.dll！请重试或检查配置。", MSG_TITLE, MB_ICONERROR);
			}
		}
	}
	return TRUE;
}
