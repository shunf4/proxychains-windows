// SPDX-License-Identifier: GPL-2.0-or-later
/* hook_cygwin_msvcstub.c
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
#include "hookdll_generic.h"

FP_ORIGINAL_FUNC2(Cygwin1, connect) = NULL;

PROXY_FUNC2(Cygwin1, connect)
{
	return orig_fpCygwin1_connect(socket, addr, socklen);
}