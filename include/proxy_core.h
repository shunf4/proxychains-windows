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


