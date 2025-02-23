/*
 * Copyright 2025
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */

#pragma once

#include <api/failures.h>
#include <arch/types.h>
#include <object/structures.h>
#include <arch/machine/fpu.h>

typedef struct tcb tcb_t;

/* Syscall register handler flags */
#define UINTR_HANDLER_FLAG_WAITING_NONE		0x0
#define UINTR_HANDLER_FLAG_WAITING_RECEIVER	0x1000
#define UINTR_HANDLER_FLAG_WAITING_SENDER	0x2000
#define UINTR_HANDLER_FLAG_WAITING_ANY		(UINTR_HANDLER_FLAG_WAITING_SENDER | \
						UINTR_HANDLER_FLAG_WAITING_RECEIVER)
#define BIT_ULL(nr)                   (1ULL << (nr))

#define MSR_IA32_UINTR_HANDLER		0x986
#define MSR_IA32_UINTR_STACKADJUST	0x987
#define MSR_IA32_UINTR_MISC		0x988	/* 39:32-UINV, 31:0-UITTSZ */
#define MSR_IA32_UINTR_PD		0x989
#define UINTR_NOTIFICATION_VECTOR       0xec


exception_t handle_SysUintrRegisterHandler(void);
exception_t handle_SysUintrUnRegisterHandler(void);
exception_t handle_SysUintrVectorFd(void);
exception_t handle_SysUintrRegisterSender(void);
exception_t handle_SysUintrUnRegisterSender(void);
exception_t handle_SysUintrWait(void);
exception_t handle_SysUintrRegisterSelf(void);
exception_t handle_SysUintrAltStack(void);
exception_t handle_SysUintrIpiFd(void);

inline bool_t is_uintr_receiver(tcb_t *t)
{
	return t->upid_activated;
}

/* TODO: UPID needs to be allocated by a KPTI compatible allocator */
static void alloc_upid(tcb_t *t)
{
	struct uintr_upid_ctx *upid_ctx = &t->upid_ctx;
	memset(upid_ctx, 0, sizeof(struct uintr_upid_ctx));

	// TODOWJX: change to atomic operation
	// refcount_set(&upid_ctx->refs, 1);
	upid_ctx->refs = 1;
	upid_ctx->task = NODE_STATE(ksCurThread);;
	upid_ctx->receiver_active = true;
	upid_ctx->waiting = false;
}