#include "EsPatchCore.h"

char *cfgDir = NULL;
ULONG ulLastAddr = 0;

BOOLEAN getCfgDir() {
	VMP_BEGIN
		if (cfgDir)
			return TRUE;
	if (!(cfgDir = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, MAX_PATH)))
		return FALSE;
	if (!GetModuleFileName(GetModuleHandle(NULL), cfgDir, MAX_PATH)) {
		HeapFree(GetProcessHeap(), 0, cfgDir);
		cfgDir = NULL;
		return FALSE;
	}
	int len = lstrlen(cfgDir);
	while (cfgDir[--len] != '\\');
	cfgDir[++len] = 0;
	lstrcat(cfgDir, "Config\\ConnectSetting.ini");
	return TRUE;
	VMP_END
}

BOOLEAN cfgLoadFakeIp(IPDATA *p) {
	VMP_BEGIN
	if (getCfgDir()) {
		DbgOut("cfgDir=%s", cfgDir);
		GetPrivateProfileString("portal", "wlanuserip", "0.0.0.0", p->ipAddr, 16, cfgDir);
	}
	if (p->ipAddr[0] == '\0') {
		lstrcpy(p->ipAddr, "0.0.0.0");
	}
	DbgOut("portal.wlanuserip=%s", p->ipAddr);
	p->ipAddrUL = inet_addr(p->ipAddr);
	return p->ipAddrUL;
	VMP_END
}

