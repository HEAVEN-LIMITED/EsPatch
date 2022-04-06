
#include <iostream>
#include "EsPatchCore.h"
#include "Hook.h"
#include "mswsock.h"
#include <Ws2spi.h>
#include "../Shared/hook/MinHook.h"
#include <wlanapi.h>
#include <NetCon.h>
#include <winreg.h>
#include <wtsapi32.h>
#include <setupapi.h>

#pragma once

#pragma comment (lib, "ws2_32.lib")
#pragma comment (lib, "iphlpapi.lib")
#pragma comment (lib, "Wtsapi32.lib")
#pragma comment (lib, "setupapi.lib")

#pragma comment(lib,"../libMinHook-x86-v141-mt.lib")

#define _T(x)       __T(x)
#define _TEXT(x)    __T(x)

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

IPDATA* gIpData;
BOOLEAN cfgLoadFakeIp(IPDATA* p);
extern int HostType;
INLINEHOOK_HOOKTABLE GpaHT[1];



typedef DWORD(WINAPI* OldGetBestInterfaceEX)(struct sockaddr*, PDWORD);
typedef DWORD(WINAPI* OldGetBestInterface)(IPAddr, PDWORD);
typedef DWORD(WINAPI* OldWlanOpenHandle)(DWORD, PVOID, PDWORD, PHANDLE);
typedef DWORD(WINAPI* OldWlanHostedNetworkStartUsing)(HANDLE, PWLAN_HOSTED_NETWORK_REASON, PVOID);
typedef HRESULT (WINAPI* OldCoCreateInstance)( REFCLSID,  LPUNKNOWN ,  DWORD  , REFIID  , LPVOID* );
typedef DWORD(WINAPI* OldWlanHostedNetworkQueryProperty)(HANDLE ,   WLAN_HOSTED_NETWORK_OPCODE , PDWORD,  PVOID*,    PWLAN_OPCODE_VALUE_TYPE  , PVOID );
typedef LSTATUS (WINAPI* OldRegQueryValueExW)( HKEY hKey,LPCWSTR lpValueName,LPDWORD lpReserved,LPDWORD lpType, LPBYTE  lpData, LPDWORD lpcbData);

OldGetBestInterfaceEX iGetBestInterfaceEX = NULL;
OldGetBestInterface iGetBestInterface = NULL;
OldWlanOpenHandle iWlanOpenHandle = NULL;
OldWlanHostedNetworkStartUsing iWlanHostedNetworkStartUsing = NULL;
OldCoCreateInstance iCoCreateInstance = NULL;
OldWlanHostedNetworkQueryProperty iWlanHostedNetworkQueryProperty = NULL;
OldRegQueryValueExW iRegQueryValueExW;

typedef struct _KEY_NAME_INFORMATION {
	ULONG NameLength;
	WCHAR Name[1];
} KEY_NAME_INFORMATION, * PKEY_NAME_INFORMATION;
//NTSYSAPI NTSTATUS NTAPI NtQueryKey(IN HANDLE KeyHandle, IN DWORD KeyInformationClass, OUT PVOID KeyInformation, IN ULONG Length, OUT PULONG ResultLength);


typedef BOOL(WINAPI* mySetupDiGetDeviceRegistryPropertyW)(
	HDEVINFO         DeviceInfoSet,
	PSP_DEVINFO_DATA DeviceInfoData,
	DWORD            Property,
	PDWORD           PropertyRegDataType,
	PBYTE            PropertyBuffer,
	DWORD            PropertyBufferSize,
	PDWORD           RequiredSize
	);

typedef LONG NTSTATUS;

#ifndef STATUS_SUCCESS
#define STATUS_SUCCESS ((NTSTATUS)0x00000000L)
#endif

#ifndef STATUS_BUFFER_TOO_SMALL
#define STATUS_BUFFER_TOO_SMALL ((NTSTATUS)0xC0000023L)
#endif


LPVOID VMTHookMethod(_In_ LPVOID lpVirtualTable, _In_ PVOID pHookMethod,
	_In_opt_ uintptr_t dwOffset)
{
	uintptr_t dwVTable = *((uintptr_t*)lpVirtualTable);
	uintptr_t dwEntry = dwVTable + dwOffset;
	uintptr_t dwOrig = *((uintptr_t*)dwEntry);

	DWORD dwOldProtection;
	::VirtualProtect((LPVOID)dwEntry, sizeof(dwEntry),
		PAGE_EXECUTE_READWRITE, &dwOldProtection);

	*((uintptr_t*)dwEntry) = (uintptr_t)pHookMethod;

	::VirtualProtect((LPVOID)dwEntry, sizeof(dwEntry),
		dwOldProtection, &dwOldProtection);

	return (LPVOID)dwOrig;
}

std::wstring GetKeyPathFromKKEY(HKEY key)
{
	std::wstring keyPath;
	if (key != NULL)
	{
		HMODULE dll = LoadLibrary("ntdll.dll");
		if (dll != NULL) {
			typedef DWORD(__stdcall* NtQueryKeyType)(
				HANDLE  KeyHandle,
				int KeyInformationClass,
				PVOID  KeyInformation,
				ULONG  Length,
				PULONG  ResultLength);

			NtQueryKeyType func = reinterpret_cast<NtQueryKeyType>(::GetProcAddress(dll, "NtQueryKey"));

			if (func != NULL) {
				DWORD size = 0;
				DWORD result = 0;
				result = func(key, 3, 0, 0, &size);
				if (result == STATUS_BUFFER_TOO_SMALL)
				{
					size = size + 2;
					wchar_t* buffer = new (std::nothrow) wchar_t[size / sizeof(wchar_t)]; // size is in bytes
					if (buffer != NULL)
					{
						result = func(key, 3, buffer, size, &size);
						if (result == STATUS_SUCCESS)
						{
							buffer[size / sizeof(wchar_t)] = L'\0';
							keyPath = std::wstring(buffer + 2);
						}

						delete[] buffer;
					}
				}
			}

			FreeLibrary(dll);
		}
	}
	return keyPath;
}

static WCHAR* GlobalS = NULL;

//RegQueryValueEx
LSTATUS WINAPI myRegQueryValueExW(HKEY hKey, LPCWSTR lpValueName, LPDWORD lpReserved, LPDWORD lpType, LPBYTE  lpData, LPDWORD lpcbData) {
	const char* p = "{B2CA9232-B462-430C-9653-4B91CAAB24F3}";
	WCHAR* pwcsName;

	int size = MultiByteToWideChar(CP_ACP, 0, p, -1, NULL, 0);
	pwcsName = new WCHAR[50];
	MultiByteToWideChar(CP_ACP, 0, p, -1, (LPWSTR)pwcsName, size);

	auto ret = iRegQueryValueExW(hKey, lpValueName, lpReserved, lpType, lpData, lpcbData);


	if (ERROR_SUCCESS == ret)
	{
		if (lpValueName) {
			OutputDebugStringW(GetKeyPathFromKKEY(hKey).c_str());
			OutputDebugStringW(lpValueName);

			if (wcsstr(lpValueName, L"NetCfgInstanceId") != 0) {

				if (GlobalS == NULL) {
					OutputDebugStringA("Init..");

					wchar_t* linkCopy = (wchar_t*)malloc(wcslen(reinterpret_cast<LPWSTR>(lpData)) + 1);
					/* Note that strncpy is unnecessary here since you know both the size
					 * of the source and destination buffers
					 */
					wcscpy(linkCopy, reinterpret_cast<LPWSTR>(lpData));
					GlobalS = linkCopy;
				}
				else {
					OutputDebugStringA("Returned first NetCfgInstanceId");
					OutputDebugStringW(GlobalS);

					//	WCHAR* pwcsName2 = L"";

					lpData = reinterpret_cast<BYTE*>(GlobalS);
				}

			}
		}
	}

	delete[] pwcsName;

	return ret;
}

DWORD WINAPI myWlanHostedNetworkQueryProperty(HANDLE hClientHandle, WLAN_HOSTED_NETWORK_OPCODE  OpCode, PDWORD pdwDataSize, PVOID* ppvData, PWLAN_OPCODE_VALUE_TYPE     pWlanOpcodeValueType, PVOID    pvReserved) {
	OutputDebugStringA("myWlanHostedNetworkQueryProperty");
	return iWlanHostedNetworkQueryProperty(hClientHandle, OpCode, pdwDataSize,ppvData,pWlanOpcodeValueType, pvReserved);
}

/*
void doHook(INetSharingManager* pNSM) {
	INetSharingEveryConnectionCollection* pNSECC = NULL;
	HRESULT hr = pNSM->get_EnumEveryConnection(&pNSECC);
	if (!pNSECC)
		wprintf(L"failed to get EveryConnectionCollection!\r\n");
	else {


		// enumerate connections
		IEnumVARIANT* pEV = NULL;
		IUnknown* pUnk = NULL;
		hr = pNSECC->get__NewEnum(&pUnk);
		if (pUnk) {
			hr = pUnk->QueryInterface(__uuidof(IEnumVARIANT),
				(void**)&pEV);
			pUnk->Release();
		}
		if (pEV) {
			VARIANT v;
			VariantInit(&v);
			while (S_OK == pEV->Next(1, &v, NULL)) {
				if (V_VT(&v) == VT_UNKNOWN) {
					INetConnection* pNC = NULL;
					V_UNKNOWN(&v)->QueryInterface(__uuidof(INetConnection),
						(void**)&pNC);
					if (pNC) {
						INetConnectionProps* pNCP = NULL;
						pNSM->get_NetConnectionProps(pNC, &pNCP);
						if (!pNCP)
							wprintf(L"failed to get NetConnectionProps!\r\n");
						else
						{
							BSTR  strName, strDeviceName, strGuid;
							NETCON_MEDIATYPE mediaType;
							pNCP->get_Guid(&strGuid);
							pNCP->get_Name(&strName);
							pNCP->get_DeviceName(&strDeviceName);
							pNCP->get_MediaType(&mediaType);

								// check properties for firewalled or shared connection
								DWORD dwCharacteristics = 0;
								pNCP->get_Characteristics(&dwCharacteristics);

								m_strPublicAdapterName = strDeviceName;

								NETCON_MEDIATYPE MediaType = NCM_NONE;
								pNCP->get_MediaType(&MediaType);
								if ((MediaType != NCM_SHAREDACCESSHOST_LAN) &&
									(MediaType != NCM_SHAREDACCESSHOST_RAS))
								{
									// got a shared/firewalled connection
									INetSharingConfiguration* pNSC = NULL;
									NETCON_STATUS Status;
									pNCP->get_Status(&Status);

									hr = pNSM->get_INetSharingConfigurationForINetConnection(pNC, &pNSC);
									if (!pNSC)
										wprintf(L"can't make INetSharingConfiguration object!\r\n");
									else
									{
										pNSC->EnableSharing(ICSSHARINGTYPE_PUBLIC);
										pNCP->get_Characteristics(&dwCharacteristics);
										pNSC->Release();
									}
								}
							
							pNCP->Release();
						}
						pNC->Release();
					}
				}
				VariantClear(&v);
			}
			pEV->Release();
		}
		pNSECC->Release();
	}
}
*/



typedef HRESULT (STDMETHODCALLTYPE* Oldget_EnumEveryConnection)(__RPC__in_opt INetConnection* pNetConnection, __RPC__deref_out_opt INetConnectionProps** ppProps);

Oldget_EnumEveryConnection iget_EnumEveryConnection;

HRESULT STDMETHODCALLTYPE myget_EnumEveryConnection(__RPC__in_opt INetConnection* pNetConnection, __RPC__deref_out_opt INetConnectionProps** ppProps) {
//	OutputDebugStringA("hoooked");
	auto ret= iget_EnumEveryConnection(pNetConnection, ppProps);

	INetConnectionProps* pNCP = *ppProps;

	if (pNCP) {
		BSTR  strName, strDeviceName;
		pNCP->get_Name(&strName);
		pNCP->get_DeviceName(&strDeviceName);
		OutputDebugStringW(strName);
		OutputDebugStringW(strDeviceName);
	}
	return ret;
}

typedef BOOL (WINAPI* OldSetupDiEnumDeviceInfo)(HDEVINFO DeviceInfoSet, DWORD MemberIndex, PSP_DEVINFO_DATA DeviceInfoData);

OldSetupDiEnumDeviceInfo iSetupDiEnumDeviceInfo;

BOOL WINAPI mySetupDiEnumDeviceInfo(HDEVINFO DeviceInfoSet, DWORD MemberIndex, PSP_DEVINFO_DATA DeviceInfoData) {
	OutputDebugStringA("Hooked SetupDiEnumDeviceInfo");
	return false;
}

HRESULT WINAPI myCoCreateInstance(REFCLSID  rclsid, LPUNKNOWN pUnkOuter, DWORD     dwClsContext, REFIID    riid, LPVOID* ppv) {
	GUID* guid = &(GUID)rclsid;
	char guid_string[37];
	snprintf(
		guid_string, sizeof(guid_string),
		"%08x-%04x-%04x-%02x%02x-%02x%02x%02x%02x%02x%02x",
		guid->Data1, guid->Data2, guid->Data3, //  
		guid->Data4[0], guid->Data4[1], guid->Data4[2],
		guid->Data4[3], guid->Data4[4], guid->Data4[5],
		guid->Data4[6], guid->Data4[7]);
	OutputDebugStringA(guid_string);



	/*

		LPSTR lpszTitle = "test";
		LPSTR lpszText = "Hooked";

		DWORD dwSession = WTSGetActiveConsoleSessionId();
		DWORD dwResponse;
		WTSSendMessage(WTS_CURRENT_SERVER_HANDLE, dwSession, lpszTitle,
			4,
			lpszText, 6,
			MB_YESNO | MB_ICONINFORMATION, 0, &dwResponse, TRUE);
	*/

	HRESULT ret = iCoCreateInstance(rclsid, pUnkOuter, dwClsContext, riid, ppv);

		// 46C166AA-3108-11D4-9348-00C04F8EEB71     CLSID_HNetCfgMgr
		// 46C166AB-3108-11D4-9348-00C04F8EEB71     CLSID_NetSharingManager
		// 46C166AC-3108-11D4-9348-00C04F8EEB71		CLSID_SharingManagerEnumPublicConnection
		// 46C166AD-3108-11D4-9348-00C04F8EEB71		CLSID_SharingManagerEnumPrivateConnection
		// 46C166AE-3108-11D4-9348-00C04F8EEB71		CLSID_SharingManagerEnumApplicationDefinition
		// 46C166AF-3108-11D4-9348-00C04F8EEB71		CLSID_SharingManagerEnumPortMapping
		// 46C166B0-3108-11D4-9348-00C04F8EEB71     CLSID_NetSharingApplicationDefinition
		// 46C166B1-3108-11D4-9348-00C04F8EEB71		CLSID_NetSharingConfiguration
	
	if (!strcmp(guid_string, "46c166ab-3108-11d4-9348-00c04f8eeb71")) {

		

		INetSharingManager* pNSM = reinterpret_cast<INetSharingManager*>(*ppv);

		iget_EnumEveryConnection = reinterpret_cast<Oldget_EnumEveryConnection>(VMTHookMethod(pNSM, myget_EnumEveryConnection, 4));

	//	pNSM->get_EnumEveryConnection = &myget_EnumEveryConnection;
	}
	else if (!strcmp(guid_string, "46c166aa-3108-11d4-9348-00c04f8eeb71")) {
		
	}


	return ret;
}

DWORD WINAPI myWlanHostedNetworkStartUsing(HANDLE  hClientHandle, PWLAN_HOSTED_NETWORK_REASON     pFailReason, PVOID    pvReserved) {
	OutputDebugStringA("WlanHostedNetworkStartUsing");
	return iWlanHostedNetworkStartUsing(hClientHandle, pFailReason, pvReserved);
}

DWORD WINAPI myWlanOpenHandle(DWORD dwClientVersion, PVOID pReserved, PDWORD pdwNegotiatedVersion, PHANDLE phClientHandle) 
{
	OutputDebugStringA("WlanOpenHandle");
	return iWlanOpenHandle(dwClientVersion, pReserved, pdwNegotiatedVersion, phClientHandle);
}

DWORD WINAPI MyGetBestInterfaceEx(struct sockaddr* pDestAddr, PDWORD pdwBestIfIndex)
{
	DWORD ret = iGetBestInterfaceEX(pDestAddr, pdwBestIfIndex);
	return ret;
}

DWORD WINAPI MyGetBestInterface(IPAddr IPin, PDWORD pdwBestIfIndex)
{
	DWORD ret = iGetBestInterface(IPin, pdwBestIfIndex);
	return ret;
}

int fnStat[3] = { 0,0,0 };
void UnhookGpa(int fn) {
	if (fnStat[0] && fnStat[1] && fnStat[2]) {
		InlineHook_CommitUnhook(GpaHT, sizeof(GpaHT));
	}
	if (fn >= 0 && fn <= 2) fnStat[fn] = 1;
}

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
					struct sockaddr_in* sai = (struct sockaddr_in*)pUa->Address.lpSockaddr;
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
		if ((DWORD)lpProcName > 0xFFFF) {
			if (!lstrcmp(lpProcName, "GetIpAddrTable")) {
				UnhookGpa(0);
				DbgOut("GetIpAddrTable -> %08X", MyGetIpAddrTable);
				return (FARPROC)MyGetIpAddrTable;
			}
			else if (!lstrcmp(lpProcName, "GetAdaptersAddresses")) {
				UnhookGpa(1);
				DbgOut("GetAdaptersAddresses -> %08X", MyGetAdaptersAddresses);
				return (FARPROC)MyGetAdaptersAddresses;
			}
			else if (!lstrcmp(lpProcName, "GetAdaptersInfo")) {
				UnhookGpa(2);
				DbgOut("GetAdaptersInfo -> %08X", MyGetAdaptersInfo);
				return (FARPROC)MyGetAdaptersInfo;
			}else if (!lstrcmp(lpProcName, "GetBestInterfaceEx")) {
				OutputDebugStringA("GetBestInterfaceEx -> ");
				return (FARPROC)MyGetBestInterfaceEx;
			}else if (!lstrcmp(lpProcName, "GetBestInterface")) {
				OutputDebugStringA("GetBestInterface -> ");
				return (FARPROC)MyGetBestInterface;
			}else if (!lstrcmp(lpProcName, "WlanOpenHandle")) {
				OutputDebugStringA("WlanOpenHandle -> ");
				return (FARPROC)myWlanOpenHandle;
			}else if (!lstrcmp(lpProcName, "WlanHostedNetworkStartUsing")) {
				OutputDebugStringA("WlanHostedNetworkStartUsing -> ");
				return (FARPROC)myWlanHostedNetworkStartUsing;
			}else if (!lstrcmp(lpProcName, "CoCreateInstance")) {
				OutputDebugStringA("CoCreateInstance -> ");
				return (FARPROC)myCoCreateInstance;
			}else if (!lstrcmp(lpProcName, "WlanHostedNetworkQueryProperty")) {
				OutputDebugStringA("WlanHostedNetworkQueryProperty -> ");
				return (FARPROC)myWlanHostedNetworkQueryProperty;
			}else if (!lstrcmp(lpProcName, "RegQueryValueExW")) {
				OutputDebugStringA("RegQueryValueExW -> ");
				return (FARPROC)myRegQueryValueExW;
			}else if (!lstrcmp(lpProcName, "SetupDiEnumDeviceInfo")) {
				OutputDebugStringA("SetupDiEnumDeviceInfo -> ");
				return (FARPROC)mySetupDiEnumDeviceInfo;


			}
		}
	UnhookGpa(-1);
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
			SOCKET_ADDRESS_LIST* pAddr = (SOCKET_ADDRESS_LIST*)lpvOutBuffer;
			for (int i = 0; i < pAddr->iAddressCount; i++)
			{
				DbgOut("Patched!!");
				((struct sockaddr_in*)pAddr->Address[i].lpSockaddr)->sin_addr.S_un.S_addr = gIpData->ipAddrUL;
			}
		}
	}
	else if (dwIoControlCode == SIO_ROUTING_INTERFACE_QUERY) {
		SOCKADDR_IN* pIn = (SOCKADDR_IN*)lpvInBuffer;
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
) {
	VMP_BEGIN
		int r = OrigWSPStartup(wVersionRequested, lpWSPData, lpProtocolInfo, UpcallTable, lpProcTable);
	if (!r) {
		OrigIoctl = (_Ioctl)lpProcTable->lpWSPIoctl;
		lpProcTable->lpWSPIoctl = (LPWSPIOCTL)MyIoctl;
		//INLINEHOOK_HOOKTABLE HT[] = { { lpProcTable->lpWSPIoctl, (LPVOID)&MyIoctl, &OrigIoctl, 0 } };
		InlineHook_CommitUnhook(WspStartHT, sizeof(WspStartHT));
		//InlineHook_CommitHook(HT, sizeof(HT));
	}
	return r;
	VMP_END
}

void HookIoctl() {
	VMP_BEGIN
		DWORD dwAddr = 0;
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
	return;
	VMP_END
}

typedef int(__cdecl* Oldwcsicmp)(const wchar_t*, const wchar_t*);

Oldwcsicmp iWcsicmp = NULL;

int WINAPI Mywcsicmp(const wchar_t* in, const wchar_t* in2)
{
//	MessageBox(0, "22Test构建日期：2018-09-11\n\n主页：https://4fk.me/proj-EsPatch\n邮箱：a@4fk.me", "EsPatch by ChiL.", MB_ICONINFORMATION);
	return iWcsicmp(in, in2);
}


BOOL InitHooks()
{
	VMP_BEGIN

	HMODULE hIphlpapi = LoadLibrary("iphlpapi.dll");
	HMODULE wlanapi = LoadLibrary("wlanapi.dll");
	HMODULE ole32 = LoadLibrary("ole32.dll");
	HMODULE advapi32 = LoadLibrary("advapi32.dll");
	HMODULE setupapi = LoadLibrary("setupapi.dll");

	OutputDebugStringA("Hook");


	INLINEHOOK_HOOKTABLE GpaHT2[1];

	GpaHT2[0].func = GetProcAddress(hIphlpapi, "GetBestInterfaceEx");
	GpaHT2[0].proxy = (LPVOID)&MyGetBestInterfaceEx;
	GpaHT2[0].original = &iGetBestInterfaceEX;
	GpaHT2[0].length = 0;


	InlineHook_CommitHook(GpaHT2, sizeof(GpaHT2));

	GpaHT2[0].func = GetProcAddress(hIphlpapi, "GetBestInterface");
	GpaHT2[0].proxy = (LPVOID)&MyGetBestInterface;
	GpaHT2[0].original = &iGetBestInterface;
	GpaHT2[0].length = 0;


	InlineHook_CommitHook(GpaHT2, sizeof(GpaHT2));

	GpaHT2[0].func = GetProcAddress(wlanapi, "WlanOpenHandle");
	GpaHT2[0].proxy = (LPVOID)&myWlanOpenHandle;
	GpaHT2[0].original = &iWlanOpenHandle;
	GpaHT2[0].length = 0;


	InlineHook_CommitHook(GpaHT2, sizeof(GpaHT2));

	GpaHT2[0].func = GetProcAddress(wlanapi, "WlanHostedNetworkStartUsing");
	GpaHT2[0].proxy = (LPVOID)&myWlanHostedNetworkStartUsing;
	GpaHT2[0].original = &iWlanHostedNetworkStartUsing;
	GpaHT2[0].length = 0;


	InlineHook_CommitHook(GpaHT2, sizeof(GpaHT2));



	GpaHT2[0].func = GetProcAddress(ole32, "CoCreateInstance");
	GpaHT2[0].proxy = (LPVOID)&myCoCreateInstance;
	GpaHT2[0].original = &iCoCreateInstance;
	GpaHT2[0].length = 0;


	InlineHook_CommitHook(GpaHT2, sizeof(GpaHT2));

	GpaHT2[0].func = GetProcAddress(wlanapi, "WlanHostedNetworkQueryProperty");
	GpaHT2[0].proxy = (LPVOID)&myWlanHostedNetworkQueryProperty;
	GpaHT2[0].original = &iWlanHostedNetworkQueryProperty;
	GpaHT2[0].length = 0;


	InlineHook_CommitHook(GpaHT2, sizeof(GpaHT2));

	GpaHT2[0].func = GetProcAddress(advapi32, "RegQueryValueExW");
	GpaHT2[0].proxy = (LPVOID)&myRegQueryValueExW;
	GpaHT2[0].original = &iRegQueryValueExW;
	GpaHT2[0].length = 0;


	InlineHook_CommitHook(GpaHT2, sizeof(GpaHT2));

	GpaHT2[0].func = GetProcAddress(setupapi, "SetupDiEnumDeviceInfo");
	GpaHT2[0].proxy = (LPVOID)&mySetupDiEnumDeviceInfo;
	GpaHT2[0].original = &iSetupDiEnumDeviceInfo;
	GpaHT2[0].length = 0;


	InlineHook_CommitHook(GpaHT2, sizeof(GpaHT2));


	//WlanHostedNetworkStartUsing

		if (HostType != 2) return FALSE;


	OrigGetIpAddrTable = (_GetIpAddrTable)GetProcAddress(hIphlpapi, "GetIpAddrTable");
	OrigGetAdaptersInfo = (_GetAdaptersInfo)GetProcAddress(hIphlpapi, "GetAdaptersInfo");
	OrigGetAdaptersAddresses = (_GetAdaptersAddresses)GetProcAddress(hIphlpapi, "GetAdaptersAddresses");

	GpaHT[0].func = GetProcAddress(GetModuleHandle("kernel32.dll"), "GetProcAddress");
	GpaHT[0].proxy = (LPVOID)&MyGetProcAddress;
	GpaHT[0].original = &OrigGetProcAddress;
	GpaHT[0].length = 0;
	InlineHook_CommitHook(GpaHT, sizeof(GpaHT));
	HookIoctl();
	return TRUE;
	VMP_END
}
