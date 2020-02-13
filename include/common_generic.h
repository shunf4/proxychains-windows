#pragma once

#include "defines_generic.h"

extern const wchar_t* g_szRuleTargetDesc[3];

const wchar_t* FormatHostPortToStr(const void* pHostPort, int iAddrLen);
void IndexToIp(const PROXYCHAINS_CONFIG* pPxchConfig, PXCH_IP_ADDRESS* pIp, PXCH_UINT32 iIndex);
void IpToIndex(const PROXYCHAINS_CONFIG* pPxchConfig, PXCH_UINT32* piIndex, const PXCH_IP_ADDRESS* pIp);
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