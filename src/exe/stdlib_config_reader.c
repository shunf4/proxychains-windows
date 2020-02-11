#include "defines_win32.h"
#include "log_win32.h"
#include <stdlib.h>
#include <stdio.h>
#include <ShlObj.h>

static FILE* fPxchConfig;

PXCH_UINT32 OpenConfigurationFile()
{
//	char szConfigPath[MAX_CONFIG_FILE_PATH_BUFSIZE * 2];
//	// Get configuration path from argv(already set in g_pPxchConfig), env or default
//	if (g_pPxchConfig->szConfigPath[0]) {
//		snprintf(szConfigPath, _countof(szConfigPath), "%ls", g_pPxchConfig->szConfigPath);
//	}
//	
//	snprintf(szConfigPath, _countof(szConfigPath), "%s", getenv("PROXYCHAINS_CONF_FILE"));
//
//#ifdef __CYGWIN__
//	snprintf(szConfigPath, _countof(szConfigPath), "/etc/proxychains.conf");
//#else
//	SHGetFolderPathAndSubDirA(NULL, CSIDL_PROFILE, NULL, 0, ".proxychains", szConfigPath);
//	StringCchCatA(szConfigPath, _countof(szConfigPath), "\\proxychains.conf");
//#endif
//
//	if ((fPxchConfig = fopen(szConfigPath, "r")) == NULL) {
//
//	}
}

PXCH_UINT32 ConfigurationFileReadLine(wchar_t* chBuf, size_t cbBufSize)
{
	
}