#include "EsPatchCore.h"
#include "Hook.h"
#include "mswsock.h"
#include <Ws2spi.h>


#pragma comment(lib,"ws2_32.lib")
#pragma comment(lib,"iphlpapi.lib")

int _stdcall MyIoctl(SOCKET s,
	DWORD dwIoControlCode,
	LPVOID lpvInBuffer,
	DWORD cbInBuffer,
	LPVOID lpvOutBuffer,
	DWORD cbOutBuffer,
	LPDWORD lpcbBytesReturned,
	LPWSAOVERLAPPED lpOverlapped,
	LPWSAOVERLAPPED_COMPLETION_ROUTINE lpCompletionRoutine,
	LPVOID a1,
	LPDWORD ErrCode);
typedef ULONG(WINAPI* _GetAdaptersInfo)(PIP_ADAPTER_INFO AdapterInfo, PULONG SizePointer);
typedef ULONG(WINAPI* _GetAdaptersAddresses)(ULONG Family, ULONG Flags, PVOID Reserved, PIP_ADAPTER_ADDRESSES AdapterAddresses, PULONG SizePointer);
typedef ULONG(WINAPI* _GetIpAddrTable)(PMIB_IPADDRTABLE pIpAddrTable, PULONG pdwSize, BOOL bOrder);
typedef FARPROC(WINAPI* _GetProcAddress)(HMODULE hModule, LPCSTR lpProcName);

_GetAdaptersInfo OrigGetAdaptersInfo;
_GetAdaptersAddresses OrigGetAdaptersAddresses;
_GetIpAddrTable OrigGetIpAddrTable;
_GetProcAddress OrigGetProcAddress;

IPDATA *gIpData;
BOOLEAN cfgLoadFakeIp(IPDATA *p);
extern int HostType;

ULONG WINAPI MyGetAdaptersInfo(PIP_ADAPTER_INFO AdapterInfo, PULONG SizePointer)
{
	VMP_BEGIN
		ULONG Ret = OrigGetAdaptersInfo(AdapterInfo, SizePointer);
	PIP_ADAPTER_INFO pAdapter = NULL;
	if (Ret == NO_ERROR && cfgLoadFakeIp(gIpData)) {
		pAdapter = AdapterInfo;
		while (pAdapter) {
			DbgOut("IpAddressList: %s -> %s", pAdapter->IpAddressList.IpAddress.String, gIpData->ipAddr);
			lstrcpy(pAdapter->IpAddressList.IpAddress.String, gIpData->ipAddr);
			pAdapter = pAdapter->Next;
		}
	}
	return Ret;
	VMP_END
}


ULONG WINAPI MyGetAdaptersAddresses(ULONG Family, ULONG Flags, PVOID Reserved, PIP_ADAPTER_ADDRESSES AdapterAddresses, PULONG SizePointer)
{
	VMP_BEGIN
		ULONG r = OrigGetAdaptersAddresses(Family, Flags, Reserved, AdapterAddresses, SizePointer);
	if (r == NO_ERROR && cfgLoadFakeIp(gIpData)) {
		PIP_ADAPTER_ADDRESSES p = AdapterAddresses;
		while (p) {
			PIP_ADAPTER_UNICAST_ADDRESS pUa = p->FirstUnicastAddress;
			PIP_ADAPTER_GATEWAY_ADDRESS	pGw = p->FirstGatewayAddress;
			while (pUa) {
				if (pUa->Address.lpSockaddr->sa_family == AF_INET) {
					struct sockaddr_in *sai = pUa->Address.lpSockaddr;
					DbgOut("Unicast: %08X -> %08X", sai->sin_addr.S_un.S_addr, gIpData->ipAddrUL);
					sai->sin_addr.S_un.S_addr = gIpData->ipAddrUL;
				}
				pUa = pUa->Next;
			}
			p = p->Next;
		}
	}
	return r;
	VMP_END
}

ULONG WINAPI MyGetIpAddrTable(PMIB_IPADDRTABLE pIpAddrTable, PULONG pdwSize, BOOL bOrder) {
	VMP_BEGIN
		ULONG r = OrigGetIpAddrTable(pIpAddrTable, pdwSize, bOrder);
	if (r == NO_ERROR && cfgLoadFakeIp(gIpData)) {
		for (int i = 0; i < (int)pIpAddrTable->dwNumEntries; i++) {
			DbgOut("Addr: %08X -> %08X", pIpAddrTable->table[i].dwAddr, gIpData->ipAddrUL);
			pIpAddrTable->table[i].dwAddr = gIpData->ipAddrUL;
		}
	}
	return r;
	VMP_END
}

FARPROC WINAPI MyGetProcAddress(HMODULE hModule, LPCSTR lpProcName) {
	VMP_BEGIN
	if (lpProcName>0xFFFF) {
		if (!lstrcmp(lpProcName, "GetIpAddrTable")) {
			DbgOut("GetIpAddrTable -> %08X", MyGetIpAddrTable);
			return MyGetIpAddrTable;
		}
		else if (!lstrcmp(lpProcName, "GetAdaptersAddresses")) {
			DbgOut("GetAdaptersAddresses -> %08X", MyGetAdaptersAddresses);
			return MyGetAdaptersAddresses;
		}
		else if (!lstrcmp(lpProcName, "GetAdaptersInfo")) {
			DbgOut("GetAdaptersInfo -> %08X", MyGetAdaptersInfo);
			return MyGetAdaptersInfo;
		}
	}
	return OrigGetProcAddress(hModule, lpProcName);
	VMP_END
}

typedef int(WINAPI* _Ioctl)(
	SOCKET s,
	DWORD dwIoControlCode,
	LPVOID lpvInBuffer,
	DWORD cbInBuffer,
	LPVOID lpvOutBuffer,
	DWORD cbOutBuffer,
	LPDWORD lpcbBytesReturned,
	LPWSAOVERLAPPED lpOverlapped,
	LPWSAOVERLAPPED_COMPLETION_ROUTINE lpCompletionRoutine,
	LPVOID a1,
	LPDWORD ErrCode);

_Ioctl OrigIoctl;

int WINAPI MyIoctl(SOCKET s,
	DWORD dwIoControlCode,
	LPVOID lpvInBuffer,
	DWORD cbInBuffer,
	LPVOID lpvOutBuffer,
	DWORD cbOutBuffer,
	LPDWORD lpcbBytesReturned,
	LPWSAOVERLAPPED lpOverlapped,
	LPWSAOVERLAPPED_COMPLETION_ROUTINE lpCompletionRoutine,
	LPVOID a1,
	LPDWORD ErrCode) {
	VMP_BEGIN
	int r = OrigIoctl(s,
		dwIoControlCode,
		lpvInBuffer,
		cbInBuffer,
		lpvOutBuffer,
		cbOutBuffer,
		lpcbBytesReturned,
		lpOverlapped,
		lpCompletionRoutine,
		a1,
		ErrCode);
	if (dwIoControlCode == SIO_ADDRESS_LIST_QUERY) {
		if (cfgLoadFakeIp(gIpData)) {
			SOCKET_ADDRESS_LIST *pAddr = lpvOutBuffer;
			for (int i = 0; i < pAddr->iAddressCount; i++)
			{
				DbgOut("Patched!!");
				((struct sockaddr_in*)pAddr->Address[i].lpSockaddr)->sin_addr.S_un.S_addr = gIpData->ipAddrUL;
			}
		}
	}
	else if (dwIoControlCode == SIO_ROUTING_INTERFACE_QUERY) {
		SOCKADDR_IN *pIn = lpvInBuffer;
		DbgOut("SIO_ROUTING_INTERFACE_QUERY");
		DbgOut("in addr=%08X", pIn->sin_addr.S_un.S_addr);
		if (cfgLoadFakeIp(gIpData)) {
			((struct sockaddr_in*)lpvOutBuffer)->sin_addr.S_un.S_addr = gIpData->ipAddrUL;
		}

	}
	VMP_END
	return r;
}

INLINEHOOK_HOOKTABLE WspStartHT[1];

LPWSPSTARTUP OrigWSPStartup;

int WSPAPI MyWSPStartup(
	WORD wVersionRequested,
	LPWSPDATA lpWSPData,
	LPWSAPROTOCOL_INFOW lpProtocolInfo,
	WSPUPCALLTABLE UpcallTable,
	LPWSPPROC_TABLE lpProcTable
	){
	VMP_BEGIN
	int r = OrigWSPStartup(wVersionRequested, lpWSPData, lpProtocolInfo, UpcallTable, lpProcTable);
	if (!r) {
		INLINEHOOK_HOOKTABLE HT[] = { { lpProcTable->lpWSPIoctl, (LPVOID)&MyIoctl, &OrigIoctl, 0 } };
		InlineHook_CommitUnhook(WspStartHT, sizeof(WspStartHT));
		InlineHook_CommitHook(HT, sizeof(HT));
	}
	return r;
	VMP_END
}

void HookIoctl() {
	VMP_BEGIN
	DWORD dwAddr=0;
	WSADATA wsaData;
	WSAStartup(MAKEWORD(2, 2), &wsaData);
	LPWSAPROTOCOL_INFOW protoInfo = NULL;
	DWORD dwLen;
	WSAEnumProtocolsW(NULL, protoInfo, &dwLen);
	if (dwLen <= 0)
		goto _cleanup;
	if (!(protoInfo = (LPWSAPROTOCOL_INFOW)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, dwLen)))
		goto _cleanup;
	if (WSAEnumProtocolsW(NULL, protoInfo, &dwLen) != SOCKET_ERROR)
	{
		int nLen = MAX_PATH;
		WCHAR wchPath[MAX_PATH];
		int err;
		if (WSCGetProviderPath(&protoInfo[0].ProviderId, wchPath, &nLen, &err))
			goto _cleanup;
		ExpandEnvironmentStringsW(wchPath, wchPath, nLen);
		WspStartHT[0].func = GetProcAddress(LoadLibraryW(wchPath), "WSPStartup");
		WspStartHT[0].proxy = (LPVOID)&MyWSPStartup;
		WspStartHT[0].original = &OrigWSPStartup;
		WspStartHT[0].length = 0;
		InlineHook_CommitHook(WspStartHT, sizeof(WspStartHT));
	}
_cleanup:
	if (protoInfo)
		HeapFree(GetProcessHeap(), 0, protoInfo);
	WSACleanup();
	return dwAddr;
	VMP_END
}
BOOL InitHooks()
{
	VMP_BEGIN
	if (HostType != 2) return;
	HMODULE hIphlpapi = LoadLibrary("iphlpapi.dll");

	OrigGetIpAddrTable = GetProcAddress(hIphlpapi, "GetIpAddrTable");
	OrigGetAdaptersInfo = GetProcAddress(hIphlpapi, "GetAdaptersInfo");
	OrigGetAdaptersAddresses = GetProcAddress(hIphlpapi, "GetAdaptersAddresses");

	INLINEHOOK_HOOKTABLE GpaHT[1];
	GpaHT[0].func = GetProcAddress(GetModuleHandle("kernel32.dll"), "GetProcAddress");
	GpaHT[0].proxy = (LPVOID)&MyGetProcAddress;
	GpaHT[0].original = &OrigGetProcAddress;
	GpaHT[0].length = 0;
	InlineHook_CommitHook(GpaHT, sizeof(GpaHT));
	HookIoctl();
	return TRUE;
	VMP_END
}
