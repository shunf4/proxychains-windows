#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#define _WINSOCK_DEPRECATED_NO_WARNINGS

#include <WinSock2.h>
#include <WS2tcpip.h>
#include <iphlpapi.h>
#include <locale.h>
#include <strsafe.h>
#include <iostream>

DWORD WINAPI ThreadFunc(LPVOID lpVoid)
{
    HeapLock(GetProcessHeap());
    printf("in thread");
    HeapUnlock(GetProcessHeap());
    return 0;
}

void PrintHostent(struct hostent* pHostent)
{
    WCHAR szIpStrWBuf[100];

    wprintf(L"gethostbyname(): addrtype=%hx name=%S(%hu)\n", pHostent->h_addrtype, pHostent->h_name, pHostent->h_length);
    wprintf(L" aliases:\n");
    for (char** pszAlias = pHostent->h_aliases; *pszAlias; pszAlias++) {
        wprintf(L"   %S\n", *pszAlias);
    }
    wprintf(L" addrs:\n");
    for (char** pszAlias = pHostent->h_addr_list; *pszAlias; pszAlias++) {
        //WSAAddressToStringW((LPSOCKADDR)*pszAlias, sizeof(SOCKADDR), NULL, szIp, &cchIp);
        InetNtopW(AF_INET, *pszAlias, szIpStrWBuf, _countof(szIpStrWBuf));
        wprintf(L"   %ls\n", szIpStrWBuf);
    }
}

void GetAndPrintAddrInfo(PCWSTR pNodeName, PCWSTR pServiceName, const ADDRINFOW* pHints)
{
    WCHAR szIpStrWBuf[100];
    int iReturn;
    DWORD dwLen;
    int i;
    PADDRINFOW arrAddrResults;

    iReturn = GetAddrInfoW(pNodeName, pServiceName, pHints, &arrAddrResults);

    if (iReturn != 0) {
        fwprintf(stderr, L"getaddrinfo failed: %d\n", iReturn);
    }

    i = 0;
    for (ADDRINFOW* pAddrInfoW = arrAddrResults; pAddrInfoW; pAddrInfoW = pAddrInfoW->ai_next, i++) {
        dwLen = _countof(szIpStrWBuf);
        WSAAddressToStringW(pAddrInfoW->ai_addr, (DWORD)pAddrInfoW->ai_addrlen, NULL, szIpStrWBuf, &dwLen);

        wprintf(L"addrs[%d]\naddr: %ls\naddrlen: %u\ncanonname: %ls\nfamily: %d\nflags: %d\nprotocol: %d\nsocktype: %d\n\n", i, szIpStrWBuf, (unsigned)pAddrInfoW->ai_addrlen, pAddrInfoW->ai_canonname, pAddrInfoW->ai_family, pAddrInfoW->ai_flags, pAddrInfoW->ai_protocol, pAddrInfoW->ai_socktype);
    }
}

#pragma comment(lib, "Ws2_32.lib")
int main()
{
    setlocale(LC_ALL, "");

    printf("WriteFile: %p\n", WriteFile);

    char szIpStrNarrowBuf[100];
    char szIpStrNarrowBuf2[100];
    WCHAR szIpStrWBuf[100];

    DWORD dwLen;
    int iLen;
    int i;


    WSADATA wsaData;

    if (0)
    {
        // Get function address test
        wprintf(L"Function address test of OutputDebugStringA: %p\n", OutputDebugStringA);
    }

    int iReturn;
    iReturn = WSAStartup(MAKEWORD(2, 2), &wsaData);     // Initialize Winsock 2.2
    if (iReturn != 0) {
        fwprintf(stderr, L"WSAStartup() failed: %d\n", iReturn);
        return 1;
    }

    if (0)
    {
        //  WSA String <-> Address conversion test
        
        dwLen = _countof(szIpStrNarrowBuf2);
        struct sockaddr_storage s;
        ADDRINFOW RequeryAddrInfoHints;
        ADDRINFOW* pRequeryAddrInfo = NULL;

        ZeroMemory(&RequeryAddrInfoHints, sizeof(RequeryAddrInfoHints));
        RequeryAddrInfoHints.ai_family = AF_UNSPEC;
        RequeryAddrInfoHints.ai_protocol = IPPROTO_TCP;
        RequeryAddrInfoHints.ai_socktype = SOCK_STREAM;
        RequeryAddrInfoHints.ai_flags = AI_NUMERICHOST;

        iLen = sizeof(s);

        sprintf_s(szIpStrNarrowBuf, "[2005::1]:1");

        wprintf(L"%d\n", WSAStringToAddressA(szIpStrNarrowBuf, AF_INET6, NULL, (LPSOCKADDR)&s, &iLen));
        wprintf(L"%d\n", WSAAddressToStringA((LPSOCKADDR)&s, iLen, NULL, szIpStrNarrowBuf2, &dwLen));
        wprintf(L"%S\n", szIpStrNarrowBuf2);
    }

    if (1)
    {
        // Test Hostent
        PrintHostent(gethostbyname("192.168.1.1"));
        PrintHostent(gethostbyname("www.baidu.com"));
        PrintHostent(gethostbyname("openwrt.reserved"));
        //PrintHostent(gethostbyname("registry.npmjs.org"));
    }

    if (1)
    {
        // Test GetAddrInfo
        GetAndPrintAddrInfo(L"192.168.1.1", L"443", NULL);
        GetAndPrintAddrInfo(L"t.cn", L"443", NULL);
        GetAndPrintAddrInfo(L"openwrt.reserved", L"80", NULL);
        //GetAndPrintAddrInfo(L"registry.npmjs.org", L"80", NULL);
    }

    if (0)
    {
        // Test Connection
        struct addrinfo hints;
        ::ZeroMemory(&hints, sizeof(hints));

        hints.ai_family = PF_INET;
        hints.ai_socktype = SOCK_STREAM;
        hints.ai_protocol = IPPROTO_TCP;

        ADDRINFOW* arrAddrResults;
        iReturn = GetAddrInfoW(L"ip.sb", L"80", NULL, &arrAddrResults);
        if (iReturn != 0) {
            fprintf(stderr, "getaddrinfo failed: %d\n", iReturn);
            WSACleanup();
            return 1;
        }

        dwLen = _countof(szIpStrWBuf);
        i = 0;
        for (ADDRINFOW* pAddrInfoW = arrAddrResults; pAddrInfoW; pAddrInfoW = pAddrInfoW->ai_next, i++) {
            WSAAddressToStringW(pAddrInfoW->ai_addr, (DWORD)pAddrInfoW->ai_addrlen, NULL, szIpStrWBuf, &dwLen);

            wprintf(L"addrs[%d]\naddr: %ls\naddrlen: %u\ncanonname: %ls\nfamily: %d\nflags: %d\nprotocol: %d\nsocktype: %d\n\n", i, szIpStrWBuf, (unsigned)pAddrInfoW->ai_addrlen, pAddrInfoW->ai_canonname, pAddrInfoW->ai_family, pAddrInfoW->ai_flags, pAddrInfoW->ai_protocol, pAddrInfoW->ai_socktype);
        }

        SOCKET ConnectSocket = INVALID_SOCKET;
        ADDRINFOW& firstAddr = arrAddrResults[0];
        ConnectSocket = socket(firstAddr.ai_family, firstAddr.ai_socktype, firstAddr.ai_protocol);
        if (ConnectSocket == INVALID_SOCKET) {
            fprintf(stderr, "Error at socket(): %ld\n", WSAGetLastError());
            FreeAddrInfoW(arrAddrResults);
            WSACleanup();
            return 1;
        }

        iReturn = connect(ConnectSocket, firstAddr.ai_addr, (int)firstAddr.ai_addrlen);
        printf("%d %u %u\n", iReturn, WSAGetLastError(), GetLastError());
        if (iReturn == SOCKET_ERROR) {
            closesocket(ConnectSocket);
            ConnectSocket = INVALID_SOCKET;
        }


        fd_set fds;
        FD_ZERO(&fds);
        FD_SET(ConnectSocket, &fds);

        printf("Waiting...\n");
        iReturn = select(-1, NULL, &fds, NULL, NULL);
        printf("Waiting done. %d, %u\n", iReturn, WSAGetLastError());

        FreeAddrInfoW(arrAddrResults);

        if (ConnectSocket == INVALID_SOCKET) {
            fprintf(stderr, "Unable to connect to server!\n");
            WSACleanup();
            return 1;
        }

        char httpReqBuf[] = "GET / HTTP/1.1\r\nHost: ip.sb\r\nUser-Agent: curl/7.66.0\r\nAccept: */*\r\n\r\n";
        const int RECEIVE_CSTR_LEN = 1024;
        char httpRespBuf[RECEIVE_CSTR_LEN + 1];

        iReturn = send(ConnectSocket, httpReqBuf, sizeof(httpReqBuf) - sizeof(char), 0);
        if (iReturn == SOCKET_ERROR) {
            fprintf(stderr, "send() failed: %ld\n", WSAGetLastError());
            closesocket(ConnectSocket);
            WSACleanup();
            return 1;
        }

        fprintf(stderr, "Bytes sent: %ld\n", iReturn);

        iReturn = shutdown(ConnectSocket, SD_SEND);
        if (iReturn == SOCKET_ERROR) {
            fprintf(stderr, "shutdown() failed: %ld\n", WSAGetLastError());
            closesocket(ConnectSocket);
            WSACleanup();
            return 1;
        }

        do {
            iReturn = recv(ConnectSocket, httpRespBuf, RECEIVE_CSTR_LEN, 0);
            if (iReturn > 0) {
                fprintf(stderr, "Bytes received: %ld\n", iReturn);
                httpRespBuf[iReturn] = '\0';
                printf(httpRespBuf);
                fflush(stdout);
            }
            else if (iReturn == 0)
                fprintf(stderr, "Connection closed\n");
            else
                fprintf(stderr, "recv() failed: %ld\n", WSAGetLastError());
        } while (iReturn > 0);

        iReturn = shutdown(ConnectSocket, SD_RECEIVE);
        if (iReturn == SOCKET_ERROR) {
            fprintf(stderr, "shutdown() failed: %ld\n", WSAGetLastError());
            closesocket(ConnectSocket);
            WSACleanup();
            return 1;
        }

        closesocket(ConnectSocket);
    }
    WSACleanup();

    return 0;

}
