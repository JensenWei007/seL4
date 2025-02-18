/*
 * Copyright 2025
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */

#include <stdint.h>
#include <arch/object/uintr.h>
#include <api/syscall.h>


exception_t handle_SysUintrRegisterHandler(void)
{
    uint64_t handler = getSyscallArg(0, NULL);
    uint32_t flags = getSyscallArg(1, NULL);

    if (flags & ~UINTR_HANDLER_FLAG_WAITING_ANY)
        return EXCEPTION_SYSCALL_ERROR;

    if (!handler)
        return EXCEPTION_SYSCALL_ERROR;

    tcb_t* cur = NODE_STATE(ksCurThread);
    if (is_uintr_receiver(cur))
        return EXCEPTION_SYSCALL_ERROR;
    
    uintr_upid_ctx *upid_ctx = cur->tcbArch.tcbContext.upid_ctx;
    if (!upid_ctx) {
		upid_ctx = alloc_upid();
		if (!upid_ctx)
            return EXCEPTION_SYSCALL_ERROR;
        cur->tcbArch.tcbContext.upid_ctx = upid_ctx;
	}
    return EXCEPTION_NONE;
}

exception_t handle_SysUintrUnRegisterHandler(void)
{
    return EXCEPTION_SYSCALL_ERROR;
}

exception_t handle_SysUintrVectorFd(void)
{
    return EXCEPTION_SYSCALL_ERROR;
}

exception_t handle_SysUintrRegisterSender(void)
{
    return EXCEPTION_SYSCALL_ERROR;
}

exception_t handle_SysUintrUnRegisterSender(void)
{
    return EXCEPTION_SYSCALL_ERROR;
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
