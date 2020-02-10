#include "log_win32.h"

SYSTEMTIME log_time_early;
wchar_t log_szLogLine_early[MAX_FWPRINTF_BUFSIZE] = { 0 };
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