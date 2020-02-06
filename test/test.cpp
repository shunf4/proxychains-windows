#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#define _WINSOCK_DEPRECATED_NO_WARNINGS

#include <WinSock2.h>
#include <WS2tcpip.h>
#include <iphlpapi.h>
#include <strsafe.h>
#include <iostream>

typedef char XXX[5];

void AAA(XXX a)
{
    a[1] = 'z';
}

#pragma comment(lib, "Ws2_32.lib")
int main()
{
    XXX a = "abcd";
    AAA(a);
    printf("%s\n", a);
    return 0;

    WSADATA wsaData;

    int iResult;
    iResult = WSAStartup(MAKEWORD(2, 2), &wsaData);     // Initialize Winsock 2.2
    if (iResult != 0) {
        fprintf(stderr, "WSAStartup() failed: %d\n", iResult);
        return 1;
    }

    struct addrinfo hints;
    ::ZeroMemory(&hints, sizeof(hints));
    
    hints.ai_family = PF_INET;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;

    struct addrinfo* addrsResult;
    iResult = getaddrinfo("ip.sb", "9993", NULL, &addrsResult);
    if (iResult != 0) {
        fprintf(stderr, "getaddrinfo failed: %d\n", iResult);
        WSACleanup();
        return 1;
    }

    char ipstrbuf[100];
    DWORD ipstrbuflen = _countof(ipstrbuf);
    int iaddr = 0;
    for (struct addrinfo* a = addrsResult; a; a = a->ai_next, iaddr++) {
        WSAAddressToStringA(a->ai_addr, (DWORD)a->ai_addrlen, NULL, ipstrbuf, &ipstrbuflen);
        printf("addrs[%d]\naddr: %s\naddrlen: %llu\ncanonname: %s\nfamily: %d\nflags: %d\nprotocol: %d\nsocktype: %d\n\n", iaddr, ipstrbuf, a->ai_addrlen, a->ai_canonname, a->ai_family, a->ai_flags, a->ai_protocol, a->ai_socktype);
    }

    return 0;

    SOCKET ConnectSocket = INVALID_SOCKET;
    struct addrinfo& firstAddr = addrsResult[0];
    ConnectSocket = socket(firstAddr.ai_family, firstAddr.ai_socktype, firstAddr.ai_protocol);
    if (ConnectSocket == INVALID_SOCKET) {
        fprintf(stderr, "Error at socket(): %ld\n", WSAGetLastError());
        freeaddrinfo(addrsResult);
        WSACleanup();
        return 1;
    }

    iResult = connect(ConnectSocket, firstAddr.ai_addr, (int)firstAddr.ai_addrlen);
    printf("%d %u %u\n", iResult, WSAGetLastError(), GetLastError());
    if (iResult == SOCKET_ERROR) {
        closesocket(ConnectSocket);
        ConnectSocket = INVALID_SOCKET;
    }

    Sleep(1000);

    fd_set fds;
    FD_ZERO(&fds);
    FD_SET(ConnectSocket, &fds);

    printf("Waiting...\n");
    iResult = select(-1, NULL, &fds, NULL, NULL);
    printf("Waiting done. %d, %u\n", iResult, WSAGetLastError());

    freeaddrinfo(addrsResult);

    if (ConnectSocket == INVALID_SOCKET) {
        fprintf(stderr, "Unable to connect to server!\n");
        WSACleanup();
        return 1;
    }

    char httpReqBuf[] = "GET / HTTP/1.1\r\nHost: ip.sb\r\nUser-Agent: curl/7.66.0\r\nAccept: */*\r\n\r\n";
    const int RECEIVE_CSTR_LEN = 1024;
    char httpRespBuf[RECEIVE_CSTR_LEN + 1];

    iResult = send(ConnectSocket, httpReqBuf, sizeof(httpReqBuf) - sizeof(char), 0);
    if (iResult == SOCKET_ERROR) {
        fprintf(stderr, "send() failed: %ld\n", WSAGetLastError());
        closesocket(ConnectSocket);
        WSACleanup();
        return 1;
    }

    fprintf(stderr, "Bytes sent: %ld\n", iResult);

    iResult = shutdown(ConnectSocket, SD_SEND);
    if (iResult == SOCKET_ERROR) {
        fprintf(stderr, "shutdown() failed: %ld\n", WSAGetLastError());
        closesocket(ConnectSocket);
        WSACleanup();
        return 1;
    }

    do {
        iResult = recv(ConnectSocket, httpRespBuf, RECEIVE_CSTR_LEN, 0);
        if (iResult > 0) {
            fprintf(stderr, "Bytes received: %ld\n", iResult);
            httpRespBuf[iResult] = '\0';
            printf(httpRespBuf);
            fflush(stdout);
        }
        else if (iResult == 0)
            fprintf(stderr, "Connection closed\n");
        else
            fprintf(stderr, "recv() failed: %ld\n", WSAGetLastError());
    } while (iResult > 0);

    iResult = shutdown(ConnectSocket, SD_RECEIVE);
    if (iResult == SOCKET_ERROR) {
        fprintf(stderr, "shutdown() failed: %ld\n", WSAGetLastError());
        closesocket(ConnectSocket);
        WSACleanup();
        return 1;
    }

    closesocket(ConnectSocket);
    WSACleanup();
    return 0;
}
