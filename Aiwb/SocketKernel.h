#pragma once
#include <WinSock.h>
#include <windows.h>
#include <MSTcpIP.h>
#pragma comment( lib, "ws2_32.lib" )
#define _in
#define _out

class CSocketKernel
{
	public:
		CSocketKernel();
		~CSocketKernel();
		BOOL InitConnect(_in const char* szAddress,_in int nPort);
		BOOL SendData(_in char* lpBuffer,_in size_t nSize);
		BOOL RecvData(_out char* lpBuffer,_in size_t nSize);
	public:
		SOCKET m_sClient;
		WSAData m_wsa;
		char *m_lpBuffer;
		BOOL m_bConnect;
	protected:
		static int m_nPort;
		static DWORD dwAddr;
	private:
		long Ascii2ToAddr(_in const char *szAddress);
		void SetCheckTimeout(_in const SOCKET S,_in const int CheckTime);
};