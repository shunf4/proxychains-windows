// SPDX-License-Identifier: GPL-2.0-or-later
/* proxy_core.h
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
#pragma once
#include "defines_generic.h"
#include "ut_helpers.h"

typedef struct _PXCH_CHAIN_NODE {
	PXCH_PROXY_DATA* pProxy;
	struct _PXCH_CHAIN_NODE* prev;
	struct _PXCH_CHAIN_NODE* next;
} PXCH_CHAIN_NODE;

typedef PXCH_CHAIN_NODE* PXCH_CHAIN;
typedef PXCH_CHAIN_NODE** PPXCH_CHAIN;


