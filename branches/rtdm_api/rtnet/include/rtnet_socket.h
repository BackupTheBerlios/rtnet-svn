/***
 *
 *  include/rtnet_socket.h
 *
 *  RTnet - real-time networking subsystem
 *  Copyright (C) 1999      Lineo, Inc
 *                1999,2002 David A. Schleef <ds@schleef.org>
 *                2002      Ulrich Marx <marx@kammer.uni-hannover.de>
 *                2003,2004 Jan Kiszka <jan.kiszka@web.de>
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

#ifndef __RTNET_SOCKET_H_
#define __RTNET_SOCKET_H_

//#include <linux/init.h>
#include <linux/list.h>
//#include <linux/socket.h>

#include <rtdev.h>
#include <rtnet.h>
#include <rtnet_sys.h>
#include <stack_mgr.h>

#include <rtdm_driver.h>


/*#define RT_SOCKETS          64*/  /* only increase with care (lookup delays!),
                                 * must not be greater then 255 */
#define RT_SOCK_NONBLOCK    RTDM_USER_CONTEXT_FLAG


/*struct rtsocket_ops {
    int  (*bind)        (struct rtsocket *s, struct sockaddr *my_addr,
                         socklen_t addrlen);
    int  (*connect)     (struct rtsocket *s, const struct sockaddr *serv_addr,
                         socklen_t addrlen);
    int  (*getsockname) (struct rtsocket *s, struct sockaddr *addr,
                         socklen_t *addrlen);
    int  (*listen)      (struct rtsocket *s, int backlog);
    int  (*accept)      (struct rtsocket *s, struct sockaddr *addr,
                         socklen_t *addrlen);
    int  (*recvmsg)     (struct rtsocket *s, struct msghdr *msg,
                         size_t total_len, int flags);
    int  (*sendmsg)     (struct rtsocket *s, const struct msghdr *msg,
                         size_t total_len, int flags);
    int  (*close)       (struct rtsocket *s);
    int  (*setsockopt)  (struct rtsocket *s, int level, int optname,
                         const void *optval, socklen_t optlen);
};*/

struct rtsocket {
//    struct list_head    list_entry;

    unsigned short      protocol;

    struct rtskb_queue  skb_pool;
    unsigned int        pool_size;

    struct rtskb_queue  incoming;

    rtos_spinlock_t     param_lock;

    unsigned int        priority;
    rtos_time_t         timeout;    /* receive timeout, 0 for infinite */

    rtos_event_sem_t    wakeup_event; /* for blocking calls */

    void                (*callback_func)(struct rtdm_dev_context *, void *arg);
    void                *callback_arg;

    union {
        /* IP specific */
        struct {
            u32         saddr;      /* source ip-addr (bind) */
            u32         daddr;      /* destination ip-addr */
            u16         sport;      /* source port */
            u16         dport;      /* destination port */

            int         reg_index;  /* index in port registry */
            u8          tos;
            u8          state;
        } inet;

        /* packet socket specific */
        struct {
            struct rtpacket_type packet_type;
            int                  ifindex;
        } packet;
    } prot;
};


extern const char rtnet_rtdm_driver_name[];
extern const char rtnet_rtdm_provider_name[];


static inline struct rtdm_dev_context *rt_socket_context(struct rtsocket *sock)
{
    return (struct rtdm_dev_context *)((void *)sock -
        (void *)(&((struct rtdm_dev_context *)NULL)->dev_private));
}

#define rt_socket_reference(sock)   \
    atomic_inc(&(rt_socket_context(sock)->close_lock_count))
#define rt_socket_dereference(sock) \
    atomic_dec(&(rt_socket_context(sock)->close_lock_count))

extern int rt_socket_init(struct rtdm_dev_context *context);
extern int rt_socket_cleanup(struct rtdm_dev_context *context);
extern int rt_socket_common_ioctl(struct rtdm_dev_context *context,
                                  int call_flags, int request, void *arg);
extern int rt_socket_if_ioctl(struct rtdm_dev_context *context, int call_flags,
                              int request, void *arg);

#endif  /* __RTNET_SOCKET_H_ */
