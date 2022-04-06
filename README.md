# EsPatch
# 1. 过 移动热点 检测功能
 ```
	DWORD required_size = 0;
	for (i = 0; SetupDiEnumDeviceInfo(hDevInfo, i, &DeviceInfoData); i++)
	{
		DWORD DataT;
		char friendly_name[2048] = { 0 };
		DWORD buffersize = 2048;
		DWORD req_bufsize = 0;

		// get device description information
		if (!SetupDiGetDeviceRegistryPropertyA(hDevInfo, &DeviceInfoData, SPDRP_DEVICEDESC, &DataT, (LPBYTE)friendly_name, buffersize, &req_bufsize))
		{
			res = GetLastError();
			continue;
		}
      
     DoSomething();.....
	}
 ```
# 2. 过 路由器检测 (旧功能)
# 3. 网卡选择 (还没做， 已经有初步原型 -> Hook GetBestInterfaceEX ， 可以实现验证流量转发)
# 4. 虚拟环境 -> 补全 \REGISTRY\MACHINE\SYSTEM\ControlSet001\Control\Class\{GUID}\(index) -> NetCfgInstanceId (REG_SZ)
