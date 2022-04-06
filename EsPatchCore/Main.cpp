#include "EsPatchCore.h"
#include "TlHelp32.h"
#include "../Shared/hook/MinHook.h"


BOOL InitHooks();
extern IPDATA *gIpData;
extern BOOLEAN HookEnabled;

int HostType = 0;

void killEsSvr() {
	VMP_BEGIN
	HANDLE hSnap=CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (hSnap == INVALID_HANDLE_VALUE)
		return;
	PROCESSENTRY32 pe;
	pe.dwSize = sizeof(pe);
	BOOL bContinue = Process32First(hSnap, &pe);
	while (bContinue) {
		if (!lstrcmpi(pe.szExeFile, "ESurfingSvr.exe")) {
			HANDLE hProc = OpenProcess(PROCESS_TERMINATE, FALSE, pe.th32ProcessID);
			if (hProc) {
				TerminateProcess(hProc, 1);
				CloseHandle(hProc);
			}
		}
		bContinue = Process32Next(hSnap, &pe);
	}
	CloseHandle(hSnap);
	VMP_END
}

void WINAPI InitEnv() {
	VMP_BEGIN
	DbgOut("InitEnv");
	gIpData = (IPDATA*)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(IPDATA));
	if (!gIpData) {
		DbgOut("HeapAlloc gIpData failed!");
		goto _cleanup;
	}
	if (!InitHooks()) {
		DbgOut("InitHooks failed!");
		goto _cleanup;
	}
	return;
_cleanup:
	if (gIpData)
		HeapFree(GetProcessHeap(), 0, gIpData);
//	ExitProcess(0);
	VMP_END
}

void initHostType() {
	VMP_BEGIN
	HMODULE hmHost;
	hmHost = GetModuleHandle((LPCSTR)NULL);
	HostType = hmHost == GetModuleHandle("ESurfingClient.exe") ? 1 : hmHost == GetModuleHandle("ESurfingSvr.exe") ? 2 : 0;
	VMP_END
}

BOOL APIENTRY DllMain(HINSTANCE hMod, ULONG ulAct, PVOID p)
{
	if (ulAct == DLL_PROCESS_ATTACH) {
		OutputDebugStringA("test");
		DbgOut("DLL_PROCESS_ATTACH dllEntry=%08X",DllMain);
		initHostType();
		if (HostType) {
			if (HostType == 1) {
//				killEsSvr();
				MessageBox(0, "Test构建日期：2022-04-5\n\n主页：https://4fk.me/proj-EsPatch\n邮箱：a@4fk.me", MSG_TITLE, MB_ICONINFORMATION);
			}
    			CreateThread(NULL, NULL, (LPTHREAD_START_ROUTINE)InitEnv, NULL, NULL, NULL);
		}
	}
	else if (ulAct == DLL_PROCESS_DETACH)
	{
//	L("a");
//		ExitProcess(1);
	}
	return TRUE;
}

void WINAPI Dummy() {

	OutputDebugStringA("Dummy");
	//do notning..
}
