// SPDX-License-Identifier: GPL-2.0-or-later
/* stdlib_config_reader.c
 * Copyright (C) 2020 Feng Shun.
 *
 *   This program is free software: you can redistribute it and/or modify
 *   it under the terms of the GNU General Public License version 2 as 
 *   published by the Free Software Foundation, either version 3 of the
 *   License, or (at your option) any later version.
 *
 *   This program is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *   GNU General Public License version 2 for more details.
 *
 *   You should have received a copy of the GNU General Public License
 *   version 2 along with this program. If not, see
 *   <http://www.gnu.org/licenses/>.
 */
#define _CRT_SECURE_NO_WARNINGS
#include "defines_win32.h"
#include "log_win32.h"
#include "hookdll_util_win32.h"
#include <stdlib.h>
#include <stdio.h>
#include <ShlObj.h>

static FILE* fPxchConfig;
static FILE* fHosts;
static unsigned long long ullConfigurationLineNum;
static unsigned long long ullHostsLineNum;

// stdlib_config_reader.c
PXCH_UINT32 OpenConfigurationFile(PROXYCHAINS_CONFIG* pPxchConfig);
PXCH_UINT32 OpenHostsFile(const WCHAR* szHostsFilePath);
PXCH_UINT32 ConfigurationFileReadLine(unsigned long long* pullLineNum, wchar_t* chBuf, size_t cbBufSize);
PXCH_UINT32 HostsFileReadLine(unsigned long long* pullHostsLineNum, wchar_t* chBuf, size_t cbBufSize);
PXCH_UINT32 CloseConfigurationFile();
PXCH_UINT32 CloseHostsFile();
long ConfigurationTellPos();
void ConfigurationRewind();
long HostsTellPos();
void HostsRewind();

PXCH_UINT32 OpenConfigurationFile(PROXYCHAINS_CONFIG* pPxchConfig)
{
	char szTempConfigPath[PXCH_MAX_CONFIG_FILE_PATH_BUFSIZE * 2];
#ifndef __CYGWIN__
	char szTempConfigPathUserProfile[PXCH_MAX_CONFIG_FILE_PATH_BUFSIZE * 2];
	char szTempConfigPathRoaming[PXCH_MAX_CONFIG_FILE_PATH_BUFSIZE * 2];
	char szTempConfigPathProgramData[PXCH_MAX_CONFIG_FILE_PATH_BUFSIZE * 2];
#endif
	char* szEnvConfigPath;
#ifdef __CYGWIN__
	char* szHomePath;
#endif
	const size_t cchTempConfigPathCapacity = _countof(szTempConfigPath);
	const char* szConfigPathOptions[4];
	int i;
	int iReturn;
	DWORD dwLastError;
	wint_t chFirst;

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
	if (szTempConfigPathUserProfile[0]) if (FAILED(StringCchCatA(szTempConfigPathUserProfile, _countof(szTempConfigPathUserProfile), "\\proxychains.conf"))) goto err_general;
	SHGetFolderPathAndSubDirA(NULL, CSIDL_APPDATA, NULL, 0, "Proxychains", szTempConfigPathRoaming);
	if (szTempConfigPathRoaming[0]) if (FAILED(StringCchCatA(szTempConfigPathRoaming, _countof(szTempConfigPathRoaming), "\\proxychains.conf"))) goto err_general;
	SHGetFolderPathAndSubDirA(NULL, CSIDL_COMMON_APPDATA, NULL, 0, "Proxychains", szTempConfigPathProgramData);
	if (szTempConfigPathProgramData[0]) if (FAILED(StringCchCatA(szTempConfigPathProgramData, _countof(szTempConfigPathProgramData), "\\proxychains.conf"))) goto err_general;

	if (szTempConfigPathUserProfile[0]) szConfigPathOptions[i++] = szTempConfigPathUserProfile;
	if (szTempConfigPathRoaming[0]) szConfigPathOptions[i++] = szTempConfigPathRoaming;
	if (szTempConfigPathProgramData[0]) szConfigPathOptions[i++] = szTempConfigPathProgramData;
	szConfigPathOptions[i++] = NULL;
#endif

validate_config_path:
	for (i = 0; i < _countof(szConfigPathOptions) && szConfigPathOptions[i]; i++) {
		if ((fPxchConfig = fopen(szConfigPathOptions[i], "r,ccs=UTF-8")) != NULL) {
			break;
		}
	}

	if (!fPxchConfig) goto err_not_found;

	chFirst = fgetwc(fPxchConfig);
	if (chFirst != WEOF && chFirst != 0xFEFF /* Unicode/UTF-16 BOM */) {
		ungetwc(chFirst, fPxchConfig);
	}

	StringCchPrintfW(pPxchConfig->szConfigPath, _countof(pPxchConfig->szConfigPath), L"%S", szConfigPathOptions[i]);
	LOGI(L"Configuration file: %ls", pPxchConfig->szConfigPath);
	ullConfigurationLineNum = 0;
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

PXCH_UINT32 OpenHostsFile(const WCHAR* szHostsFilePath)
{
	char szHostsFilePathNarrow[MAX_PATH * 2];
	wint_t chFirst;

	if (FAILED(StringCchPrintfA(szHostsFilePathNarrow, _countof(szHostsFilePathNarrow), "%ls", szHostsFilePath))) goto err_bufovf;

	CloseHostsFile();

	// ccs=UTF-8 seems only work under Windows. Under cygwin, everything is assumed to be UTF-8
	if ((fHosts = fopen(szHostsFilePathNarrow, "r,ccs=UTF-8")) == NULL) goto err_not_found;
	chFirst = fgetwc(fHosts);
	if (chFirst != WEOF && chFirst != 0xFEFF /* Unicode/UTF-16 BOM */) {
		ungetwc(chFirst, fHosts);
	}
	return NO_ERROR;

err_not_found:
	LOGE(L"No hosts file found");
	return ERROR_FILE_NOT_FOUND;
err_bufovf:
	LOGE(L"Buffer overflow while seeking configuration file");
	return ERROR_INSUFFICIENT_BUFFER;
}

PXCH_UINT32 ConfigurationFileReadLine(unsigned long long* pullConfigurationLineNum, wchar_t* chBuf, size_t cbBufSize)
{
	wchar_t* pBuf;

	if (!fPxchConfig) goto err_file_not_open;

	if (feof(fPxchConfig)) goto err_eof;

	ullConfigurationLineNum++;
	*pullConfigurationLineNum = ullConfigurationLineNum;
	pBuf = fgetws(chBuf, (int)cbBufSize, fPxchConfig);

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
	LOGE(L"Line %llu too long that it exceeds the buffer size", ullConfigurationLineNum);
	return ERROR_INSUFFICIENT_BUFFER;

err_read:
	return ERROR_READ_FAULT;

err_eof:
	return ERROR_END_OF_MEDIA;

err_file_not_open:
	return ERROR_NOT_READY;
}

PXCH_UINT32 HostsFileReadLine(unsigned long long* pullHostsLineNum, wchar_t* chBuf, size_t cbBufSize)
{
	wchar_t* pBuf;

	if (!fHosts) goto err_file_not_open;

	if (feof(fHosts)) goto err_eof;

	ullHostsLineNum++;
	*pullHostsLineNum = ullHostsLineNum;

	pBuf = fgetws(chBuf, (int)cbBufSize, fHosts);

	if (pBuf == NULL) {
		if (feof(fHosts)) {
			goto err_eof;
		} else {
			goto err_read;
		}
	}
	pBuf = wcschr(chBuf, L'\n');
	if (!feof(fHosts) && (pBuf == NULL || *(pBuf + 1) != L'\0')) goto err_bufovf;

	return NO_ERROR;

err_bufovf:
	LOGE(L"Line %llu too long that it exceeds the buffer size", ullHostsLineNum);
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

PXCH_UINT32 CloseHostsFile()
{
	if (fHosts) {
		fclose(fHosts);
	}
	return NO_ERROR;
}

long ConfigurationTellPos()
{
	return ftell(fPxchConfig);
}

void ConfigurationRewind()
{
	wint_t chFirst;

	rewind(fPxchConfig);

	chFirst = fgetwc(fPxchConfig);
	if (chFirst != WEOF && chFirst != 0xFEFF /* Unicode/UTF-16 BOM */) {
		ungetwc(chFirst, fPxchConfig);
	}
	ullConfigurationLineNum = 0;
}

long HostsTellPos()
{
	return ftell(fHosts);
}

void HostsRewind()
{
	wint_t chFirst;

	rewind(fHosts);

	chFirst = fgetwc(fHosts);
	if (chFirst != WEOF && chFirst != 0xFEFF /* Unicode/UTF-16 BOM */) {
		ungetwc(chFirst, fHosts);
	}
	ullHostsLineNum = 0;
}