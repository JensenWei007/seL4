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

static uint32_t xfeature_get_offset(u64 xcomp_bv, int xfeature)
{
	uint32_t offs, i;

	/*
	 * Non-compacted format and legacy features use the cached fixed
	 * offsets.
	 */
	//if (!cpu_feature_enabled(X86_FEATURE_XCOMPACTED))
		//return xstate_offsets[xfeature];

	/*
	 * Compacted format offsets depend on the actual content of the
	 * compacted xsave area which is determined by the xcomp_bv header
	 * field.
	 */
	offs = 512 + 64;
	for_each_extended_xfeature(i, xcomp_bv) {
		if (xfeature_is_aligned64(i))
			offs = ALIGN(offs, 64);
		if (i == xfeature)
			break;
		offs += xstate_sizes[i];
	}
	return offs;
}

/*
 * Given an xstate feature nr, calculate where in the xsave
 * buffer the state is.  Callers should ensure that the buffer
 * is valid.
 */
static void *__raw_xsave_addr(xsave_state_t *xsave, int xfeature_nr)
{
	uint64_t xcomp_bv = xsave->header.xcomp_bv;

	return (void *)xsave + xfeature_get_offset(xcomp_bv, xfeature_nr);
}

void *get_xsave_addr(xsave_state_t *xsave, int32_t xfeature_nr)
{
	/*
	 * This assumes the last 'xsave*' instruction to
	 * have requested that 'xfeature_nr' be saved.
	 * If it did not, we might be seeing and old value
	 * of the field in the buffer.
	 *
	 * This can happen because the last 'xsave' did not
	 * request that this feature be saved (unlikely)
	 * or because the "init optimization" caused it
	 * to not be saved.
	 */
	if (!(xsave->header.xfeatures & BIT_ULL(xfeature_nr)))
		return NULL;

	return __raw_xsave_addr(xsave, xfeature_nr);
}

/*
 * Return a pointer to the xstate for the feature if it should be used, or NULL
 * if the MSRs should be written to directly. To do this safely using the
 * associated read/write helpers are required.
 */
void *start_update_xsave_msrs(int32_t xfeature_nr)
{
	void *xstate;

	// TODOWJX: here should disable premption and irq.
	//fpregs_lock();

	xstate = get_xsave_addr(&current->thread.fpu.fpstate->regs.xsave, xfeature_nr);

	/*
	 * If regs are in the init state, they can't be retrieved from
	 * init_fpstate due to the init optimization, but are not nessarily
	 * zero. The only option is to restore to make everything live and
	 * operate on registers. This will clear TIF_NEED_FPU_LOAD.
	 *
	 * Otherwise, if not in the init state but TIF_NEED_FPU_LOAD is set,
	 * operate on the buffer. The registers will be restored before going
	 * to userspace in any case, but the task might get preempted before
	 * then, so this possibly saves an xsave.
	 */
	if (!xstate)
		userError("xstate is null!");
		//fpregs_restore_userregs();
	return xstate;
}
