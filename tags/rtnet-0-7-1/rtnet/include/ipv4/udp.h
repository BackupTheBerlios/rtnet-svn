/***
 *
 *  include/ipv4/udp.h
 *
 *  RTnet - real-time networking subsystem
 *  Copyright (C) 1999,2000 Zentropic Computing, LLC
 *                2002 Ulrich Marx <marx@kammer.uni-hannover.de>
 *                2004 Jan Kiszka <jan.kiszka@web.de>
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 *
 */

#ifndef __RTNET_UDP_H_
#define __RTNET_UDP_H_

#include <linux/init.h>

#include <ipv4/protocol.h>


#define RT_UDP_SOCKETS      64  /* only increase with care (lookup delays!),
                                 * must be power of 2 */


extern struct rtinet_protocol udp_protocol;


extern int rt_udp_close(struct rtdm_dev_context *context, int call_flags);
extern int rt_udp_ioctl(struct rtdm_dev_context *context, int call_flags,
                        int request, void *arg);
extern ssize_t rt_udp_recvmsg(struct rtdm_dev_context *context, int call_flags,
                              struct msghdr *msg, int flags);
extern ssize_t rt_udp_sendmsg(struct rtdm_dev_context *context, int call_flags,
                              const struct msghdr *msg, int flags);

extern void __init rt_udp_init(void);
extern void rt_udp_release(void);


#endif  /* __RTNET_UDP_H_ */
