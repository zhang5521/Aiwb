#include "stdafx.h"
#include <stdio.h>
#include <windows.h>
#include "HookApi.h"
BOOL EnableDebugPrivilege()
{
	HANDLE hToken = NULL;
	TOKEN_PRIVILEGES tp;
	BOOL bRet = FALSE;
	bRet = ::OpenProcessToken(::GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES|TOKEN_QUERY, &hToken);
	if (!bRet || hToken == NULL)
		return FALSE;
	if (!::LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &tp.Privileges[0].Luid))
	{
		::CloseHandle(hToken);
		return FALSE;
	}
	tp.PrivilegeCount = 1;
	tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
	if (!::AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(TOKEN_PRIVILEGES), NULL, NULL))
	{
		::CloseHandle(hToken);
		return FALSE;
	}
	::CloseHandle(hToken);
	return TRUE;
}

CApiHookEngine::CApiHookEngine(){
	DWORD dwCurrentPid;
	EnableDebugPrivilege();
	dwCurrentPid = ::GetCurrentProcessId();
	m_hProc = ::OpenProcess(PROCESS_VM_OPERATION | PROCESS_VM_WRITE, FALSE, dwCurrentPid);
}

CApiHookEngine::~CApiHookEngine(){
	CloseHandle(m_hProc);
}
BOOL CApiHookEngine::RemoveHook( WCHAR *szLibDllModuleName, CHAR *szApiName )
{
	HOOKAPI_INFO api_hook;
	HMODULE hMod = ::GetModuleHandle(szLibDllModuleName);
	DWORD dwApiAddress = 0;
	if(!hMod){
		hMod = ::LoadLibrary(szLibDllModuleName);
		if(!hMod)
			return FALSE;
	}
	dwApiAddress = (DWORD)::GetProcAddress(hMod,szApiName);
	map<DWORD,HOOKAPI_INFO>::iterator it = m_HookList.find(dwApiAddress);

	if(it != m_HookList.end()){
		api_hook = it->second;
		m_HookList.erase(it);
	}
	else return FALSE;

	return HookOnOrOff(api_hook.lpOldFunctionAddress,(UCHAR*)&api_hook.ResumeByte,\
		api_hook.nSizeOfResume);
}

BOOL CApiHookEngine::HookOnOrOff(LPVOID lpfFunctionAddress, UCHAR *ucFunctionJmpCode, DWORD dwModifyLen)
{
	DWORD dwOldProtect;
	char szDebug[255] = {0};
	if(!m_hProc){
		wsprintfA(szDebug,"CApiHookEngine::HookOnOrOff -- OpenProcess() ErrorCode: %d",GetLastError());
		OutputDebugStringA(szDebug);
		return FALSE;
	}
	if (!::VirtualProtectEx(m_hProc, lpfFunctionAddress, dwModifyLen, \
		PAGE_READWRITE, &dwOldProtect))
		OutputDebugString(L"CApiHookEngine::HookOnOrOff -- VirtualProtectEx Error");

	if (!::WriteProcessMemory(m_hProc, lpfFunctionAddress, \
		ucFunctionJmpCode, dwModifyLen, NULL))
		OutputDebugString(L"CApiHookEngine::HookOnOrOff -- WriteProcessMemory Error");

	if (!::VirtualProtectEx(m_hProc, lpfFunctionAddress, dwModifyLen, \
		dwOldProtect, &dwOldProtect))
		OutputDebugString(L"CApiHookEngine::HookOnOrOff -- VirtualProtectEx Error");
	return TRUE;
}

BOOL CApiHookEngine::StartHook( WCHAR *szLibDllModuleName, CHAR *szApiName,DWORD NewFunctionAddress )
{
	HMODULE hMod = NULL;
	FARPROC fpApiAddress = NULL;
	UCHAR OldApiMachineCode[5];
	UCHAR NewJmpMachineCode[5];	
	HOOKAPI_INFO api_hook = {0};
	hMod = ::GetModuleHandle(szLibDllModuleName);
	if(!hMod){
		hMod = ::LoadLibrary(szLibDllModuleName);
		if(!hMod)
			return FALSE;
	}
	fpApiAddress = ::GetProcAddress(hMod, szApiName);
	if(!fpApiAddress)
		return FALSE;

	__asm{
		lea edi, OldApiMachineCode ;
		mov esi, fpApiAddress ;
		cld ;
		movsd ;
		movsb ;

		mov byte ptr [NewJmpMachineCode], 0E9h ;

		mov eax, NewFunctionAddress ;
		mov ebx, fpApiAddress ;
		sub eax, ebx ;
		sub eax, 5 ;
		mov dword ptr [NewJmpMachineCode+1], eax ;
	}
	if(!HookOnOrOff(fpApiAddress, NewJmpMachineCode, 5))
		return FALSE;

	api_hook.lpOldFunctionAddress = fpApiAddress;
	api_hook.nSizeOfResume = 5;
	memcpy(api_hook.ResumeByte,OldApiMachineCode,api_hook.nSizeOfResume);
	m_HookList.insert(pair<DWORD,HOOKAPI_INFO>((DWORD)fpApiAddress,api_hook));
	return TRUE;
}
VOID CApiHookEngine::RemoveAllHook()
{
	map<DWORD,HOOKAPI_INFO>::iterator it = m_HookList.begin();
	while(it != m_HookList.end())
		HookOnOrOff(it->second.lpOldFunctionAddress,it->second.ResumeByte,it->second.nSizeOfResume);
	m_HookList.clear();
}