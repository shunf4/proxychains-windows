#define _CRT_SECURE_NO_WARNINGS
#include "defines_win32.h"
#include "log_win32.h"
#include "common_win32.h"
#include <stdlib.h>
#include <stdio.h>
#include <ShlObj.h>

static FILE* fPxchConfig;
static unsigned long long ullLineNum;

PXCH_UINT32 OpenConfigurationFile(PROXYCHAINS_CONFIG* pPxchConfig)
{
	char szTempConfigPath[MAX_CONFIG_FILE_PATH_BUFSIZE * 2];
#ifndef __CYGWIN__
	char szTempConfigPathUserProfile[MAX_CONFIG_FILE_PATH_BUFSIZE * 2];
	char szTempConfigPathRoaming[MAX_CONFIG_FILE_PATH_BUFSIZE * 2];
	char szTempConfigPathProgramData[MAX_CONFIG_FILE_PATH_BUFSIZE * 2];
#endif
    char* szEnvConfigPath;
    char* szHomePath;
    const size_t cchTempConfigPathCapacity = _countof(szTempConfigPath);
    const char* szConfigPathOptions[4];
    int i;
    int iReturn;
    DWORD dwLastError;

    CloseConfigurationFile();

	// Get configuration path from argv(already set in pPxchConfig), env or default

	if (pPxchConfig->szConfigPath[0]) {
        iReturn = snprintf(szTempConfigPath, cchTempConfigPathCapacity, "%ls", pPxchConfig->szConfigPath);
		if (iReturn < 0 || (size_t)iReturn >= cchTempConfigPathCapacity) goto err_bufovf;
        i = 0;
        szConfigPathOptions[i++] = szTempConfigPath;
        szConfigPathOptions[i++] = NULL;
        goto validate_config_path;
	}

    szEnvConfigPath = getenv("PROXYCHAINS_CONF_FILE");
	
    if (szEnvConfigPath) {
        iReturn = snprintf(szTempConfigPath, cchTempConfigPathCapacity, "%s", szEnvConfigPath);
        if (iReturn < 0 || (size_t)iReturn >= cchTempConfigPathCapacity) goto err_bufovf;
        i = 0;
        szConfigPathOptions[i++] = szTempConfigPath;
        szConfigPathOptions[i++] = NULL;
        goto validate_config_path;
    }

    i = 0;
#ifdef __CYGWIN__
    szHomePath = getenv("HOME");
    if (szHomePath) {
        iReturn = snprintf(szTempConfigPath, cchTempConfigPathCapacity, "%s/.proxychains/proxychains.conf", szHomePath);
        if (iReturn < 0 || (size_t)iReturn >= cchTempConfigPathCapacity) goto err_bufovf;
        szConfigPathOptions[i++] = szTempConfigPath;
    }
    szConfigPathOptions[i++] = SYSCONFDIR "/proxychains.conf";
    szConfigPathOptions[i++] = "/etc/proxychains.conf";
    szConfigPathOptions[i++] = NULL;
#else
	SHGetFolderPathAndSubDirA(NULL, CSIDL_PROFILE, NULL, 0, ".proxychains", szTempConfigPathUserProfile);
	if (FAILED(StringCchCatA(szTempConfigPathUserProfile, _countof(szTempConfigPathUserProfile), "\\proxychains.conf"))) goto err_general;
    SHGetFolderPathAndSubDirA(NULL, CSIDL_APPDATA, NULL, 0, "Proxychains", szTempConfigPathRoaming);
	if (FAILED(StringCchCatA(szTempConfigPathRoaming, _countof(szTempConfigPathRoaming), "\\proxychains.conf"))) goto err_general;
    SHGetFolderPathAndSubDirA(NULL, CSIDL_COMMON_APPDATA, NULL, 0, "Proxychains", szTempConfigPathProgramData);
	if (FAILED(StringCchCatA(szTempConfigPathProgramData, _countof(szTempConfigPathProgramData), "\\proxychains.conf"))) goto err_general;

    szConfigPathOptions[i++] = szTempConfigPathUserProfile;
    szConfigPathOptions[i++] = szTempConfigPathRoaming;
    szConfigPathOptions[i++] = szTempConfigPathProgramData;
    szConfigPathOptions[i++] = NULL;
#endif

validate_config_path:
    for (i = 0; i < _countof(szConfigPathOptions) && szConfigPathOptions[i]; i++) {
        if ((fPxchConfig = fopen(szConfigPathOptions[i], "r")) != NULL) {
            break;
        }
    }

    if (!fPxchConfig) goto err_not_found;

    StringCchPrintfW(pPxchConfig->szConfigPath, _countof(pPxchConfig->szConfigPath), L"%S", szConfigPathOptions[i]);
    LOGI(L"Configuration file: %ls", pPxchConfig->szConfigPath);
    ullLineNum = 0;
    return NO_ERROR;

err_not_found:
    LOGE(L"No configuration file found");
    return ERROR_FILE_NOT_FOUND;
err_bufovf:
    LOGE(L"Buffer overflow while seeking configuration file");
    return ERROR_INSUFFICIENT_BUFFER;
#ifndef __CYGWIN__
err_general:
#endif
    dwLastError = GetLastError();
    LOGE(L"Error while seeking configuration file: %ls", FormatErrorToStr(dwLastError));
    return dwLastError;
}

PXCH_UINT32 ConfigurationFileReadLine(unsigned long long* pullLineNum, wchar_t* chBuf, size_t cbBufSize)
{
    wchar_t* pBuf;

    if (!fPxchConfig) goto err_file_not_open;

    if (feof(fPxchConfig)) goto err_eof;

    ullLineNum++;
    *pullLineNum = ullLineNum;
    pBuf = fgetws(chBuf, cbBufSize, fPxchConfig);

    if (pBuf == NULL) {
        if (feof(fPxchConfig)) {
            goto err_eof;
        } else {
            goto err_read;
        }
    }
    pBuf = wcschr(chBuf, L'\n');
    if (!feof(fPxchConfig) && (pBuf == NULL || *(pBuf + 1) != L'\0')) goto err_bufovf;

    return NO_ERROR;

err_bufovf:
    LOGE(L"Line %llu too long that it exceeds the buffer size", ullLineNum);
    return ERROR_INSUFFICIENT_BUFFER;

err_read:
    return ERROR_READ_FAULT;

err_eof:
    return ERROR_END_OF_MEDIA;

err_file_not_open:
    return ERROR_NOT_READY;
}

PXCH_UINT32 CloseConfigurationFile()
{
    if (fPxchConfig) {
        fclose(fPxchConfig);
    }
    return NO_ERROR;
}

FILE* GetConfigurationFile()
{
    return fPxchConfig;
}