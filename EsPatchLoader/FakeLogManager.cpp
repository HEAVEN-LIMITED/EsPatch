#include "EsPatchLoader.h"

typedef int(__thiscall *_Init)(void *a1, int a2, int a3, int a4);
typedef int(__cdecl *_GetLogManager)();
typedef int(__cdecl *_GetErrSurvey)();

_Init pfnInit;
_GetLogManager pfnGetLogManager;
_GetErrSurvey pfnGetErrSurvey;

extern "C" BOOL flmInitFuncs() {
	HMODULE hmLogManager;
	if (!(hmLogManager = LoadLibrary("LogManager2.dll")))
		return FALSE;
	pfnInit = (_Init)GetProcAddress(hmLogManager, "Init");
	pfnGetLogManager = (_GetLogManager)GetProcAddress(hmLogManager, "GetLogManager");
	pfnGetErrSurvey = (_GetErrSurvey)GetProcAddress(hmLogManager, "GetErrSurvey");
	return TRUE;
}

int __fastcall Init(void *a1, void *dummy, int a2, int a3, int a4){
	return pfnInit(a1, a2, a3, a4);
}

int __cdecl GetLogManager() {
	return pfnGetLogManager();
}

int __cdecl GetErrSurvey() {
	return pfnGetErrSurvey();
}
