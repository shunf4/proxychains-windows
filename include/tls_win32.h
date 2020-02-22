// SPDX-License-Identifier: GPL-2.0-or-later
/* tls_win32.h
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
#include "defines_win32.h"
#include "tls_generic.h"

#define PXCH_TLS_PTR_W32HOSTENT_BY_BASE(base) ((struct hostent*)((char*)base + PXCH_TLS_OFFSET_W32HOSTENT))
#define PXCH_TLS_PTR_W32HOSTENT_IP_PTR_LIST_BY_BASE(base) ((PXCH_UINT32**)((char*)base + PXCH_TLS_OFFSET_W32HOSTENT_IP_PTR_LIST))
#define PXCH_TLS_PTR_W32HOSTENT_IP_PTR_LIST_AS_PPCHAR_BY_BASE(base) ((char**)((char*)base + PXCH_TLS_OFFSET_W32HOSTENT_IP_PTR_LIST))
#define PXCH_TLS_PTR_W32HOSTENT_IP_BUF_BY_BASE(base) ((PXCH_UINT32*)((char*)base + PXCH_TLS_OFFSET_W32HOSTENT_IP_BUF))
#define PXCH_TLS_PTR_W32HOSTENT_ALIAS_PTR_LIST_BY_BASE(base) ((char(**)[PXCH_TLS_W32HOSTENT_ALIAS_BUFSIZE])((char*)base + PXCH_TLS_OFFSET_W32HOSTENT_ALIAS_PTR_LIST))
#define PXCH_TLS_PTR_W32HOSTENT_ALIAS_BUF_BY_BASE(base) ((char(*)[PXCH_TLS_W32HOSTENT_ALIAS_BUFSIZE])((char*)base + PXCH_TLS_OFFSET_W32HOSTENT_ALIAS_BUF))
#define PXCH_TLS_PTR_W32HOSTENT_HOSTNAME_BUF_BY_BASE(base) ((char(*)[PXCH_MAX_HOSTNAME_BUFSIZE])((char*)base + PXCH_TLS_OFFSET_W32HOSTENT_HOSTNAME_BUF))
#define PXCH_TLS_PTR_LOG_TIME_BY_BASE(base) ((SYSTEMTIME*)((char*)base + PXCH_TLS_OFFSET_LOG_TIME))


#define PXCH_TLS_PTR_W32HOSTENT(dwTlsIndex) PXCH_TLS_PTR_W32HOSTENT_BY_BASE(TlsGetValue(dwTlsIndex))
#define PXCH_TLS_PTR_W32HOSTENT_IP_PTR_LIST(dwTlsIndex) PXCH_TLS_PTR_W32HOSTENT_IP_PTR_LIST_BY_BASE(TlsGetValue(dwTlsIndex))
#define PXCH_TLS_PTR_W32HOSTENT_IP_PTR_LIST_AS_PPCHAR(dwTlsIndex) PXCH_TLS_PTR_W32HOSTENT_IP_PTR_LIST_AS_PPCHAR_BY_BASE(TlsGetValue(dwTlsIndex))
#define PXCH_TLS_PTR_W32HOSTENT_IP_BUF(dwTlsIndex) PXCH_TLS_PTR_W32HOSTENT_IP_BUF_BY_BASE(TlsGetValue(dwTlsIndex))
#define PXCH_TLS_PTR_W32HOSTENT_ALIAS_PTR_LIST(dwTlsIndex) PXCH_TLS_PTR_W32HOSTENT_ALIAS_PTR_LIST_BY_BASE(TlsGetValue(dwTlsIndex))
#define PXCH_TLS_PTR_W32HOSTENT_ALIAS_BUF(dwTlsIndex) PXCH_TLS_PTR_W32HOSTENT_ALIAS_BUF_BY_BASE(TlsGetValue(dwTlsIndex))
#define PXCH_TLS_PTR_W32HOSTENT_HOSTNAME_BUF(dwTlsIndex) PXCH_TLS_PTR_W32HOSTENT_HOSTNAME_BUF_BY_BASE(TlsGetValue(dwTlsIndex))
#define PXCH_TLS_PTR_LOG_TIME(dwTlsIndex) PXCH_TLS_PTR_LOG_TIME_BY_BASE(TlsGetValue(dwTlsIndex))

