// SPDX-License-Identifier: GPL-2.0-or-later
/* hookdll_util_log_cygwin.c
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
#include "includes_generic.h"
#include "defines_generic.h"
#include <unistd.h>

#include "log_generic.h"
#include "tls_generic.h"
#include "hookdll_generic.h"
#include "hookdll_util_generic.h"

void pxch_cygwin_write(int fd, const void *buf, size_t nbyte)
{
	write(fd, buf, nbyte);
}