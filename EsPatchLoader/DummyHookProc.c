#include "EsPatchLoader.h"

typedef ULONG(WINAPI* _GetAdaptersInfo)(PVOID AdapterInfo, PULONG SizePointer);
typedef ULONG(WINAPI* _GetAdaptersAddresses)(ULONG Family, ULONG Flags, PVOID Reserved, PVOID AdapterAddresses, PULONG SizePointer);
typedef ULONG(WINAPI* _GetIpAddrTable)(PVOID pIpAddrTable, PULONG pdwSize, BOOL bOrder);
typedef FARPROC(WINAPI* _GetProcAddress)(HMODULE hModule, LPCSTR lpProcName);


_GetAdaptersInfo OrigGetAdaptersInfo;
_GetAdaptersAddresses OrigGetAdaptersAddresses;
_GetIpAddrTable OrigGetIpAddrTable;
_GetProcAddress OrigGetProcAddress;

ULONG WINAPI MyGetAdaptersInfo(PVOID AdapterInfo, PULONG SizePointer)
{
	VMP_BEGIN
	return OrigGetAdaptersInfo(AdapterInfo, SizePointer);
	VMP_END
}

ULONG WINAPI MyGetAdaptersAddresses(ULONG Family, ULONG Flags, PVOID Reserved, PVOID AdapterAddresses, PULONG SizePointer)
{
	VMP_BEGIN
	return OrigGetAdaptersAddresses(Family, Flags, Reserved, AdapterAddresses, SizePointer);
	VMP_END
}

ULONG WINAPI MyGetIpAddrTable(PVOID pIpAddrTable, PULONG pdwSize, BOOL bOrder) {
	VMP_BEGIN
	return OrigGetIpAddrTable(pIpAddrTable, pdwSize, bOrder);
	VMP_END
}

FARPROC WINAPI MyGetProcAddress(HMODULE hModule, LPCSTR lpProcName) {
	VMP_BEGIN
	return OrigGetProcAddress(hModule, lpProcName);
	VMP_END
}

void exchangeHookProc(PVOID *a) {
	VMP_BEGIN
	OrigGetAdaptersInfo = a[0];
	OrigGetAdaptersAddresses = a[1];
	OrigGetIpAddrTable = a[2];
	OrigGetProcAddress = a[3];
	a[0] = MyGetAdaptersInfo;
	a[1] = MyGetAdaptersAddresses;
	a[2] = MyGetIpAddrTable;
	a[3] = MyGetProcAddress;
	VMP_END
}
