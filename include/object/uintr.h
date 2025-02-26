/*
 * Copyright 2025
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */

#pragma once

#include <api/failures.h>
#include <arch/types.h>
#include <object/structures.h>
#include <object/tcb.h>
#include <arch/machine/fpu.h>

typedef struct tcb tcb_t;

/* UPID Notification control status bits */
#define UINTR_UPID_STATUS_ON		0x0	/* Outstanding notification */
#define UINTR_UPID_STATUS_SN		0x1	/* Suppressed notification */
#define UINTR_UPID_STATUS_BLKD		0x7	/* Blocked waiting for kernel */

/* Syscall register handler flags */
#define UINTR_HANDLER_FLAG_WAITING_NONE		0x0
#define UINTR_HANDLER_FLAG_WAITING_RECEIVER	0x1000
#define UINTR_HANDLER_FLAG_WAITING_SENDER	0x2000
#define UINTR_HANDLER_FLAG_WAITING_ANY		(UINTR_HANDLER_FLAG_WAITING_SENDER | \
						UINTR_HANDLER_FLAG_WAITING_RECEIVER)
#define BIT_ULL(nr)                   (1ULL << (nr))

#define MSR_IA32_UINTR_RR		0x985
#define MSR_IA32_UINTR_HANDLER		0x986
#define MSR_IA32_UINTR_STACKADJUST	0x987
#define MSR_IA32_UINTR_MISC		0x988	/* 39:32-UINV, 31:0-UITTSZ */
#define MSR_IA32_UINTR_PD		0x989
#define MSR_IA32_UINTR_TT		0x98a
#define UINTR_NOTIFICATION_VECTOR       0xec
#define UINTR_MASK_1 0xFFFFFF00FFFFFFFF
#define UINTR_MASK_2 0xFFFFFFFF00000000

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

inline bool_t is_uintr_sender(tcb_t *t)
{
	return t->uitt_activated;
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

static inline void set_bit(int32_t nr, void *addr)
{
	asm("btsl %1,%0" : "+m" (*(uint32_t *)addr) : "Ir" (nr));
}

static void alloc_uitt(tcb_t *t)
{
	struct uintr_uitt_ctx *uitt_ctx = &t->uitt_ctx;
	memset(uitt_ctx, 0, sizeof(struct uintr_uitt_ctx));

	// TODOWJX: change to atomic operation
	// refcount_set(&upid_ctx->refs, 1);
	uitt_ctx->refs = 1;
}

static int32_t find_first_zero_bit(const uint64_t *addr, uint64_t size)
{
	uint64_t total_words = (size + 63) / 64;
    uint64_t word_index = 0;
    uint64_t bit_index = 0;
    for (word_index = 0; word_index < total_words; word_index++) {
        uint64_t word = addr[word_index];
        for (bit_index = 0; bit_index < 64; bit_index++) {
            if ((word & (1ULL << bit_index)) == 0) {
                uint64_t position = word_index * 64 + bit_index;
                if (position < size) {
                	return position;
                } else {
                    return 256;
                }
            }
        }
    }
    return 256;
}
