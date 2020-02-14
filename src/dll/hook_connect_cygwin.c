// SPDX-License-Identifier: GPL-2.0-or-later
/* hook_connect_cygwin.c
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
 *   GNU General Public License for more details.
 *
 *   You should have received a copy of the GNU General Public License
 *   along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */
#include "hookdll_cygwin.h"
#include "log_generic.h"

#include <sys/socket.h>

PROXY_FUNC2(Cygwin1, connect)
{
	FUNCIPCLOGI(L"cygwin1.dll connect() called");
	return orig_fpCygwin1_connect(socket, addr, socklen);
}

