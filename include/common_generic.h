#pragma once

#include "defines_generic.h"

const wchar_t* FormatHostPortToStr(const void* pHostPort, int iAddrLen);
void IndexToIp(const PROXYCHAINS_CONFIG* pPxchConfig, PXCH_IP_ADDRESS* pIp, PXCH_UINT32 iIndex);
void IpToIndex(const PROXYCHAINS_CONFIG* pPxchConfig, PXCH_UINT32* piIndex, const PXCH_IP_ADDRESS* pIp);