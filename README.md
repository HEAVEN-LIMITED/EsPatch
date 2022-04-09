# EsPatch 22/4/7 更新
# 1. 过 移动热点 检测功能 (已修复崩溃，改为字符串替换方式)
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
# 2. 过 路由器检测 (旧功能)(已修复)
# 3. ~~网卡选择~~ 改为代理客户端功能 -> 设置系统环境变量 cdc_custom_proxy -> http=127.0.0.1:10808
![](https://github.com/githuu5y5u/EsPatch/blob/master/%E4%BB%A3%E7%90%86%E5%AE%A2%E6%88%B7%E7%AB%AF.PNG?raw=true)
# 4. 虚拟环境(请自己搞定，这里虚拟环境指Windows SandBox等特殊环境) -> 补全 \REGISTRY\MACHINE\SYSTEM\ControlSet001\Control\Class\{GUID}\(index) -> NetCfgInstanceId (REG_SZ)
必须替换 zlib.dll 和 NetHelper.dll 来唤起程序<br>
本项目仅供学习研究, 使用请自己负责
