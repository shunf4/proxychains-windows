#include "hookdll_generic.h"

FP_ORIGINAL_FUNC2(Cygwin1, connect) = NULL;

PROXY_FUNC2(Cygwin1, connect)
{
	return orig_fpCygwin1_connect(socket, addr, socklen);
}