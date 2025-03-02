/*
 * Copyright 2025
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */

#include <stdint.h>
#include <object/uintr.h>
#include <api/syscall.h>
#include <arch/machine.h>
#include <arch/model/smp.h>
#include <machine/registerset.h>

static exception_t do_uintr_register_vector(uint64_t uvec)
{
	struct uintr_upid_ctx *upid_ctx;
	tcb_t* cur = NODE_STATE(ksCurThread);

	/*
	 * A vector should only be registered by a task that
	 * has an interrupt handler registered.
	 */
	if (!is_uintr_receiver(cur))
		return EXCEPTION_SYSCALL_ERROR;

	if (uvec >= 64)
		return EXCEPTION_SYSCALL_ERROR;

	upid_ctx = &cur->upid_ctx;

	/* Vectors once registered always stay registered */
	if (!(upid_ctx->uvec_mask & BIT_ULL(uvec)))
		upid_ctx->uvec_mask |= BIT_ULL(uvec);

	/* uvecfd_upid_ctx should be passed only when an FD is being created */
	upid_ctx->refs += 1;

    printf("call vectorfd, ret: %lu \n", (unsigned long)cur->id);
    setRegister(cur, badgeRegister, cur->id);

	return EXCEPTION_NONE;
}


exception_t handle_SysUintrRegisterHandler(void)
{
    uint64_t handler = getSyscallArg(0, NULL);
    uint32_t flags = getSyscallArg(1, NULL);

    printf("recv, handler: %lx, flag: %u \n",(unsigned long)handler, flags);

    if (flags & ~UINTR_HANDLER_FLAG_WAITING_ANY)
        return EXCEPTION_SYSCALL_ERROR;

    if (!handler)
        return EXCEPTION_SYSCALL_ERROR;

    tcb_t* cur = NODE_STATE(ksCurThread);
    if (is_uintr_receiver(cur))
        return EXCEPTION_SYSCALL_ERROR;
    
    if (!cur->upid_is_alloced) {
		alloc_upid(cur);
        cur->upid_is_alloced = 1;
	}

    // Here need to disable preemption
    // fpregs_lock();
    struct uintr_upid_ctx *upid_ctx = &cur->upid_ctx;
    upid_ctx->refs += 1;
    struct uintr_upid *upid = &upid_ctx->upid;
    upid->nc.nv = UINTR_NOTIFICATION_VECTOR;

#ifdef ENABLE_SMP_SUPPORT
#ifdef CONFIG_USE_LOGICAL_IDS
    upid->nc.ndst = (uint32_t)getCurrentLOGID();
#else
    upid->nc.ndst = (uint32_t)getCurrentCPUID();
#endif
#else
#ifdef CONFIG_USE_LOGICAL_IDS
    upid->nc.ndst = (uint32_t)apic_get_logical_id();
#else
    upid->nc.ndst = 0;
#endif
#endif
    printf("register hanl, upid: %lx \n",(unsigned long)upid);

    x86_wrmsr(MSR_IA32_UINTR_HANDLER, handler);
    x86_wrmsr(MSR_IA32_UINTR_PD, (uint64_t)upid);
    x86_wrmsr(MSR_IA32_UINTR_STACKADJUST, 128);
    uint64_t misc_msr = x86_rdmsr(MSR_IA32_UINTR_MISC);
    misc_msr |= (uint64_t)UINTR_NOTIFICATION_VECTOR << 32;
    x86_wrmsr(MSR_IA32_UINTR_MISC, misc_msr);

	cur->upid_activated = true;

    // Here we enable preemption
	// fpregs_unlock();

    return EXCEPTION_NONE;
}

exception_t handle_SysUintrUnRegisterHandler(void)
{
    uint32_t flags = getSyscallArg(0, NULL);

    if (flags)
        return EXCEPTION_SYSCALL_ERROR;

    tcb_t* cur = NODE_STATE(ksCurThread);
    struct uintr_upid_ctx *upid_ctx = &cur->upid_ctx;

    if (is_uintr_receiver(cur))
        return EXCEPTION_SYSCALL_ERROR;

    // Here need to disable preemption
    // fpregs_lock();

    uint64_t misc_msr = x86_rdmsr(MSR_IA32_UINTR_MISC);
    misc_msr &= UINTR_MASK_1;
    x86_wrmsr(MSR_IA32_UINTR_MISC, misc_msr);
    x86_wrmsr(MSR_IA32_UINTR_PD, 0);
    x86_wrmsr(MSR_IA32_UINTR_RR, 0);
    x86_wrmsr(MSR_IA32_UINTR_STACKADJUST, 0);
    x86_wrmsr(MSR_IA32_UINTR_HANDLER, 0);

	cur->upid_activated = false;
	set_bit(UINTR_UPID_STATUS_SN, (uint64_t *)&upid_ctx->upid.nc.status);

    // sub and release
    //put_upid_ref(upid_ctx);

    // Need to add
	//uintr_remove_task_wait(t);
    
    // Here we enable preemption
	// fpregs_unlock();

    return EXCEPTION_NONE;
}

exception_t handle_SysUintrVectorFd(void)
{
    uint64_t vector = getSyscallArg(0, NULL);
    uint32_t flags = getSyscallArg(1, NULL);

    if (flags)
        return EXCEPTION_SYSCALL_ERROR;

    return do_uintr_register_vector(vector);
}

static void uintr_set_sender_msrs(tcb_t *t)
{
	struct uintr_uitt_ctx *uitt_ctx = &t->uitt_ctx;

    x86_wrmsr(MSR_IA32_UINTR_TT, (uint64_t)uitt_ctx->uitt | 1);
	/* Modify only the relevant bits of the MISC MSR */
	uint64_t msr64 = x86_rdmsr(MSR_IA32_UINTR_MISC);
	msr64 &= UINTR_MASK_2;
	msr64 |= 256;
	x86_wrmsr(MSR_IA32_UINTR_MISC, msr64);

	t->uitt_activated = true;
}

exception_t handle_SysUintrRegisterSender(void)
{
    int32_t uvec_fd = getSyscallArg(0, NULL);
    uint32_t flags = getSyscallArg(1, NULL);

    printf("call register sender, fd: %u, flags: %u \n", uvec_fd, flags);

    if (flags)
        return EXCEPTION_SYSCALL_ERROR;

    tcb_t *t = getTcbById(uvec_fd);
    tcb_t* cur = NODE_STATE(ksCurThread);
    uint64_t uvec = t->uvec;
    struct uintr_upid_ctx *upid_ctx = &t->upid_ctx;

    if (!upid_ctx->receiver_active)
		return EXCEPTION_SYSCALL_ERROR;

    if (!cur->uitt_is_alloced) {
		alloc_uitt(cur);
        cur->uitt_is_alloced = 1;
	}

    struct uintr_uitt_ctx *uitt_ctx = &cur->uitt_ctx;
    int32_t entry = find_first_zero_bit((uint64_t *)uitt_ctx->uitt_mask, 256);
    if (entry >= 256)
		return EXCEPTION_SYSCALL_ERROR;

    set_bit(entry, (uint64_t*)uitt_ctx->uitt_mask);

    // TODOWJX: Here should lock
    //mutex_lock(&uitt_ctx->uitt_lock);

	struct uintr_uitt_entry *uitte = &uitt_ctx->uitt[entry];

	/* Program the UITT entry */
	uitte->user_vec = uvec;
    struct uintr_upid *upid = &upid_ctx->upid;
	uitte->target_upid_addr = (uint64_t)upid;
	uitte->valid = 1;

    printf("regsend, target_upid_add: %lx \n", (unsigned long)uitte->target_upid_addr);

    upid_ctx->refs += 1;
	uitt_ctx->r_upid_ctx[entry] = upid_ctx;

	//mutex_unlock(&uitt_ctx->uitt_lock);

    if (!is_uintr_sender(cur))
		uintr_set_sender_msrs(cur);

    setRegister(cur, badgeRegister, entry);

    return EXCEPTION_NONE;
}

exception_t handle_SysUintrUnRegisterSender(void)
{
    int32_t ipi_index = getSyscallArg(0, NULL);
    uint32_t flags = getSyscallArg(1, NULL);

    if (flags)
        return EXCEPTION_SYSCALL_ERROR;

    tcb_t* cur = NODE_STATE(ksCurThread);
    struct uintr_uitt_ctx *uitt_ctx = &cur->uitt_ctx;

    mark_uitte_invalid(uitt_ctx, ipi_index);
    free_uitt_entry(uitt_ctx, ipi_index);

    return EXCEPTION_NONE;
}

exception_t handle_SysUintrWait(void)
{
    return EXCEPTION_SYSCALL_ERROR;
}

exception_t handle_SysUintrRegisterSelf(void)
{
    return EXCEPTION_SYSCALL_ERROR;
}

exception_t handle_SysUintrAltStack(void)
{
    return EXCEPTION_SYSCALL_ERROR;
}

exception_t handle_SysUintrIpiFd(void)
{
    return EXCEPTION_SYSCALL_ERROR;
}
