#include "hookdll_cygwin.h"
#include "log_generic.h"

#include <sys/socket.h>

PROXY_FUNC2(Cygwin1, connect)
{
	FUNCIPCLOGI(L"cygwin1.dll connect() called");
	return orig_fpCygwin1_connect(socket, addr, socklen);
}