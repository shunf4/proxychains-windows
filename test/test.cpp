#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif

#include <WinSock2.h>
#include <WS2tcpip.h>
#include <iphlpapi.h>
#include <strsafe.h>
#include <iostream>

#pragma comment(lib, "Ws2_32.lib")
int main()
{
    WSADATA wsaData;
    HMODULE hDll;
    LPVOID fpConnect;

    const char* pstr = "\xe5\x86\xaf\xe8\x88\x9c";
    WCHAR xxx[100];
    setlocale(LC_ALL, "");
    printf(pstr);
    printf("\n");
    StringCchPrintfW(xxx, 100, L"%S", pstr);
    printf("%#02x\n", xxx[0]);

    exit(0);
    printf("哈哈哈\n");
    printf("connect(): %p\n", connect);

    hDll = GetModuleHandleW(L"Ws2_32.dll");
    fpConnect = GetProcAddress(hDll, "connect");

    printf("connect(): %p\n", connect);
    printf("GetProcAddress(connect): %p\n", fpConnect);

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
    iResult = getaddrinfo("ip.sb", "80", &hints, &addrsResult);
    if (iResult != 0) {
        fprintf(stderr, "getaddrinfo failed: %d\n", iResult);
        WSACleanup();
        return 1;
    }

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
    if (iResult == SOCKET_ERROR) {
        closesocket(ConnectSocket);
        ConnectSocket = INVALID_SOCKET;
    }

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
