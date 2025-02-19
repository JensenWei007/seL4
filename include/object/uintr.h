/*
 * Copyright 2025
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */

#pragma once

#include <api/failures.h>
#include <arch/types.h>
//#include <arch/model/statedata.h>
// TODOWJX: 可能引不到，需要引的是arch外边的那个
#include <object/structures.h>

typedef struct tcb tcb_t;

#define __aligned(x) __attribute__((aligned(x)))
#define __packed    __attribute__((packed))

/* Syscall register handler flags */
#define UINTR_HANDLER_FLAG_WAITING_NONE		0x0
#define UINTR_HANDLER_FLAG_WAITING_RECEIVER	0x1000
#define UINTR_HANDLER_FLAG_WAITING_SENDER	0x2000
#define UINTR_HANDLER_FLAG_WAITING_ANY		(UINTR_HANDLER_FLAG_WAITING_SENDER | \
						UINTR_HANDLER_FLAG_WAITING_RECEIVER)

/* User Posted Interrupt Descriptor (UPID) */
struct uintr_upid {
	struct {
		uint8_t status;	/* bit 0: ON, bit 1: SN, bit 2-7: reserved */
		uint8_t reserved1;	/* Reserved */
		uint8_t nv;		/* Notification vector */
		uint8_t reserved2;	/* Reserved */
		uint32_t ndst;	/* Notification destination */
	} nc __packed;		/* Notification control */
	uint64_t puir;		/* Posted user interrupt requests */
} __aligned(64);


struct uintr_upid_ctx {
	struct list_head node;
	// TODOWJX: 可能引不到
	tcb_t *task;	/* Receiver task */
	uint64_t uvec_mask;			/* track registered vectors per bit */
	struct uintr_upid *upid;
	/* TODO: Change to kernel kref api */
	uint64_t refs;
	bool_t receiver_active;		/* Flag for UPID being mapped to a receiver */
	bool_t waiting;			/* Flag for UPID blocked in the kernel */
	uint32_t waiting_cost;	/* Flags for who pays the waiting cost */
};

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
	return !!t->upid_activated;
}

/* TODO: UPID needs to be allocated by a KPTI compatible allocator */
/*
static struct uintr_upid_ctx *alloc_upid(void)
{
	struct uintr_upid_ctx *upid_ctx;
	struct uintr_upid *upid;

	//upid_ctx = malloc(sizeof(*upid_ctx));
	if (!upid_ctx)
		return NULL;

	//upid = malloc(sizeof(*upid));

	if (!upid) {
		//free(upid_ctx);
		return NULL;
	}

	upid_ctx->upid = upid;
	upid_ctx->refs = 1;
	// TODOWJX: change to atomic operation
	//refcount_set(&upid_ctx->refs, 1);
	//upid_ctx->task = NODE_STATE(ksCurThread);;
	upid_ctx->receiver_active = true;
	upid_ctx->waiting = false;

	return upid_ctx;
}
*/
