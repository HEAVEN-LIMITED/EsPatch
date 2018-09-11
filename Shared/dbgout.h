
//#define DEF_DEBUG

#ifdef DEF_DEBUG
#define DEF_DBGMSG_HDR	"EsPatch"
char _dbg_msg[256];
#define DbgOut(format,...) do	{ \
	wsprintf (_dbg_msg,"[%s] (%d)%s %s: "format"\n\0",DEF_DBGMSG_HDR,GetCurrentThreadId(),__FILE__,__FUNCTION__, ##__VA_ARGS__); \
	OutputDebugString(_dbg_msg); \
}while(0)
#else
#define DbgOut(format,...)
#endif
