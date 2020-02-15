// SPDX-License-Identifier: GPL-2.0-or-later
/* log.c
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
#include "log_win32.h"

SYSTEMTIME log_time_early;
wchar_t log_szLogLine_early[PXCH_MAXFWPRINTF_BUFSIZE] = { 0 };
SYSTEMTIME log_time_early;
PXCH_IPC_MSGBUF log_msg_early;
PXCH_IPC_MSGBUF log_respMsg_early;
PXCH_UINT32 log_cbMsgSize_early;
PXCH_UINT32 log_cbRespMsgSize_early;
PXCH_UINT32 log_pid_early;
PXCH_UINT32 log_tid_early;
wchar_t log_ods_buf_early[PXCH_LOG_ODS_BUFSIZE];

#ifdef __CYGWIN__
PXCH_UINT32 log_cygpid_early;
#endif