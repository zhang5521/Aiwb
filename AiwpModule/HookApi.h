#include <stdio.h>
#include <windows.h>
#include <stlport\map>
#pragma comment(lib,"stlport.5.2.lib")
using namespace std;

typedef struct _HOOKAPI_INFO{
	int nSizeOfResume;
	BYTE ResumeByte[128];
	LPVOID lpOldFunctionAddress;
}HOOKAPI_INFO,*PHOOKAPI_INFO;

class CApiHookEngine
{
public:
	CApiHookEngine();
	~CApiHookEngine();
public:
	map<DWORD,HOOKAPI_INFO> m_HookList;
	HANDLE m_hProc;
	VOID  RemoveAllHook();
	BOOL RemoveHook(WCHAR *szLibDllModuleName, CHAR *szApiName);
	BOOL StartHook(WCHAR *szLibDllModuleName, CHAR *szApiName,DWORD NewFunctionAddress);
private:
	BOOL HookOnOrOff(LPVOID lpfFunctionAddress, UCHAR *ucFunctionJmpCode, DWORD dwModifyLen);
};
