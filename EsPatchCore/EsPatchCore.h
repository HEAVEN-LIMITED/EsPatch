#pragma once
#include <WinSock2.h>
#include <Iphlpapi.h>
#include "lazy_imp_fix.h"
#include "..\Shared\VMP.h"
#include "..\Shared\dbgout.h"

typedef struct {
	char ipAddr[16];
	DWORD ipAddrUL;
}IPDATA;

#define MSG_TITLE "EsPatch by ChiL."
