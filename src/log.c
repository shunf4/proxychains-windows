#include "log_win32.h"

#if PXCHLOG_LEVEL >= PXCHLOG_LEVEL_CRITICAL
SYSTEMTIME log_time;
WCHAR log_szLogLine[PXCHLOG_IPC_BUFSIZE] = { 0 };
SYSTEMTIME log_time;
IPC_MSGBUF log_msg;
IPC_MSGBUF log_respMsg;
DWORD log_cbMsgSize;
DWORD log_cbRespMsgSize;
DWORD log_pid;
wchar_t log_ods_buf[PXCHLOG_ODS_BUFSIZE];

#ifdef __CYGWIN__
pid_t log_cyg_pid;
#endif

#endif
