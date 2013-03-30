#include "stdafx.h"
#include "SocketKernel.h"
CSocketKernel::CSocketKernel()
{
	m_bConnect = FALSE;
	WSAStartup(MAKEWORD(2,2),&m_wsa);
}
CSocketKernel::~CSocketKernel()
{
	if (m_bConnect) closesocket(m_sClient);
}
long CSocketKernel::Ascii2ToAddr(_in const char *szAddress)
{
	long lAddr;
	struct hostent *stHe;

	if((lAddr=(long)inet_addr(szAddress))<0)
		if((stHe=(struct hostent*)gethostbyname(szAddress))==NULL)	
			return(0);
		else
			return(*(unsigned long *)stHe->h_addr);

	return lAddr;
}
BOOL CSocketKernel::RecvData( _out char* lpBuffer,_in size_t nSize )
{
	int nError = 0;
	int nIndex = 0;
	DWORD dwErr = 0;
	while (nSize != 0)
	{
		nError = recv(m_sClient,lpBuffer+nIndex,nSize,0); 
		if (nError == SOCKET_ERROR){ 
			dwErr = GetLastError();
			return FALSE;
		}
		else if (nError == 0) break;
		nSize -= nError;
		nIndex += nError;
	}
//	m_HttpEngine.DeHttpPacket(lpBuffer,nSize);
	return TRUE;
}
BOOL CSocketKernel::SendData( _in char* lpBuffer,_in size_t nSize )
{
//	m_HttpEngine.EnHttpPacket(lpBuffer,nSize);
    int nError = 0;
    int nIndex = 0;
	DWORD dwErr = 0;
    while (nSize != 0)
    {
        if (nSize > 4096)
        {
            nError = send(m_sClient,lpBuffer+nIndex,4096,0);
			if (nError == SOCKET_ERROR){ 
				dwErr = WSAGetLastError();
				break;
			}
        }
        else
        {
            nError = send(m_sClient,lpBuffer+nIndex,nSize,0);
			if (nError == SOCKET_ERROR){ 
				dwErr = WSAGetLastError();
				break;
			}
        }   
        if (nError == SOCKET_ERROR) break;
        else if (nError == 0) break;
        nSize -= nError;
        nIndex += nError;
    }
    return nSize == 0;
}
BOOL CSocketKernel::InitConnect( _in const char* szAddress,_in int nPort )
{
	if(szAddress == NULL || nPort == 0){
		OutputDebugStringA("InitConnect() Fail!");
		return FALSE;
	}

	struct sockaddr_in LocalAddr;
	LocalAddr.sin_family=AF_INET;
	LocalAddr.sin_port=htons(nPort);
	LocalAddr.sin_addr.S_un.S_addr = Ascii2ToAddr(szAddress);

	m_sClient = socket(AF_INET, SOCK_STREAM,IPPROTO_TCP);

	while(TRUE){
		if(connect(m_sClient,(PSOCKADDR)&LocalAddr,sizeof(LocalAddr)) == SOCKET_ERROR){
			printf("CSocketKernel::InitConnect -- connect() Error!\n");
			return FALSE;
		}
		else break;
	}
	m_bConnect = TRUE;
	return TRUE;
}