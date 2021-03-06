/***
 *
 *  ipv4/icmp.c
 *
 *  rtnet - real-time networking subsystem
 *  Copyright (C) 1999,2000 Zentropic Computing, LLC
 *                2002 Ulrich Marx <marx@kammer.uni-hannover.de>
 *                2002 Vinay Sridhara <vinaysridhara@yahoo.com>
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

#include <linux/types.h>
#include <linux/icmp.h>
#include <net/checksum.h>

#include <rtskb.h>
#include <rtnet_socket.h>
#include <ipv4_chrdev.h>
#include <ipv4/icmp.h>
#include <ipv4/ip_output.h>
#include <ipv4/protocol.h>
#include <ipv4/route.h>


/***
 * Structure for sending the icmp packets
 */
struct icmp_bxm
{
    unsigned int        csum;
    size_t              head_len;
    size_t              data_len;
    off_t               offset;
    struct {
        struct icmphdr  icmph;
        nanosecs_t      timestamp;
    } head;
    union {
        struct rtskb    *skb;
        void            *buf;
    } data;
};

struct rt_icmp_control
{
    void    (*handler)(struct rtskb *skb);
    short   error;      /* This ICMP is classed as an error message */
};



static rtos_spinlock_t  echo_calls_lock;
LIST_HEAD(echo_calls);

/***
 *  Socket for icmp replies
 *  It is not part of the socket pool. It may furthermore be used concurrently
 *  by multiple tasks because all fields are static excect skb_pool, but that
 *  is spin lock protected.
 */
static struct rtsocket icmp_socket;



void rt_icmp_queue_echo_request(struct rt_proc_call *call)
{
    unsigned long   flags;


    rtos_spin_lock_irqsave(&echo_calls_lock, flags);
    list_add_tail(&call->list_entry, &echo_calls);
    rtos_spin_unlock_irqrestore(&echo_calls_lock, flags);
}



void rt_icmp_cleanup_echo_requests(void)
{
    unsigned long       flags;
    struct list_head    *entry = &echo_calls;
    struct list_head    *next;


    rtos_spin_lock_irqsave(&echo_calls_lock, flags);
    entry = echo_calls.next;
    INIT_LIST_HEAD(&echo_calls);
    rtos_spin_unlock_irqrestore(&echo_calls_lock, flags);

    while (entry != &echo_calls) {
        next = entry->next;
        rtpc_complete_call_nrt((struct rt_proc_call *)entry, -EINTR);
        entry = next;
    }
}



/***
 *  rt_icmp_discard - dummy function
 */
static void rt_icmp_discard(struct rtskb *skb)
{
}



static int rt_icmp_glue_reply_bits(const void *p, char *to,
                                   unsigned int offset, unsigned int fraglen)
{
    struct icmp_bxm *icmp_param = (struct icmp_bxm *)p;
    struct icmphdr *icmph;
    unsigned long csum;


    RTNET_ASSERT(offset == 0,
                 rtos_print("RTnet: %s() does not support fragmentation.",
                            __FUNCTION__);
                 return -1;);

    csum = csum_partial_copy_nocheck((void *)&icmp_param->head, to,
                                     icmp_param->head_len, icmp_param->csum);

    csum = rtskb_copy_and_csum_bits(icmp_param->data.skb,
                                    icmp_param->offset,
                                    to + icmp_param->head_len,
                                    fraglen - icmp_param->head_len,
                                    csum);

    icmph = (struct icmphdr *)to;

    icmph->checksum = csum_fold(csum);

    return 0;
}



/***
 *  common reply function
 */
static void rt_icmp_send_reply(struct icmp_bxm *icmp_param, struct rtskb *skb)
{
    struct dest_route   rt;
    u32                 daddr;
    int                 err;


    daddr = skb->nh.iph->saddr;

    icmp_param->head.icmph.checksum = 0;
    icmp_param->csum = 0;

    if (rt_ip_route_output(&rt, daddr) != 0)
        return;

    err = rt_ip_build_xmit(&icmp_socket, rt_icmp_glue_reply_bits, icmp_param,
                           sizeof(struct icmphdr) + icmp_param->data_len,
                           &rt, MSG_DONTWAIT);

    rtdev_dereference(rt.rtdev);

    RTNET_ASSERT(err == 0,
                 rtos_print("RTnet: %s() error in xmit\n", __FUNCTION__););
}



/***
 *  rt_icmp_echo - handles echo replies on our previously sent requests
 */
static void rt_icmp_echo_reply(struct rtskb *skb)
{
    unsigned long       flags;
    struct rt_proc_call *call;
    struct ipv4_cmd     *cmd;
    rtos_time_t         time;


    rtos_spin_lock_irqsave(&echo_calls_lock, flags);

    if (!list_empty(&echo_calls)) {
        call = (struct rt_proc_call *)echo_calls.next;
        list_del(&call->list_entry);

        rtos_spin_unlock_irqrestore(&echo_calls_lock, flags);
    } else {
        rtos_spin_unlock_irqrestore(&echo_calls_lock, flags);
        return;
    }

    cmd = rtpc_get_priv(call, struct ipv4_cmd);

    cmd->args.ping.ip_addr = skb->nh.iph->saddr;
    cmd->args.ping.rtt     = 0;

    if ((skb->h.icmph->un.echo.id == cmd->args.ping.id) &&
        (ntohs(skb->h.icmph->un.echo.sequence) == cmd->args.ping.sequence) &&
        skb->len == cmd->args.ping.msg_size) {
        if (skb->len >= sizeof(nanosecs_t)) {
            rtos_get_time(&time);
            cmd->args.ping.rtt =
                rtos_time_to_nanosecs(&time) - *((nanosecs_t *)skb->data);
        }
        rtpc_complete_call(call, sizeof(struct icmphdr) + skb->len);
    } else
        rtpc_complete_call(call, 0);
}



/***
 *  rt_icmp_echo_request - handles echo requests sent by other stations
 */
static void rt_icmp_echo_request(struct rtskb *skb)
{
    struct icmp_bxm icmp_param;


    icmp_param.head.icmph = *skb->h.icmph;
    icmp_param.head.icmph.type = ICMP_ECHOREPLY;
    icmp_param.data.skb = skb;
    icmp_param.offset = 0;
    icmp_param.data_len = skb->len;
    icmp_param.head_len = sizeof(struct icmphdr);

    rt_icmp_send_reply(&icmp_param, skb);

    return;
}



static int rt_icmp_glue_request_bits(const void *p, char *to,
                                     unsigned int offset, unsigned int fraglen)
{
    struct icmp_bxm *icmp_param = (struct icmp_bxm *)p;
    struct icmphdr *icmph;
    unsigned long csum;


    RTNET_ASSERT(offset == 0,
                 rtos_print("RTnet: %s() does not support fragmentation.",
                             __FUNCTION__);
                 return -1;);

    csum = csum_partial_copy_nocheck((void *)&icmp_param->head, to,
                                     icmp_param->head_len, icmp_param->csum);

    csum = csum_partial_copy_nocheck(icmp_param->data.buf,
                                     to + icmp_param->head_len,
                                     fraglen - icmp_param->head_len,
                                     csum);

    icmph = (struct icmphdr *)to;

    icmph->checksum = csum_fold(csum);

    return 0;
}



/***
 *  common request function
 */
static int rt_icmp_send_request(u32 daddr, struct icmp_bxm *icmp_param)
{
    struct dest_route   rt;
    int                 err;


    icmp_param->head.icmph.checksum = 0;
    icmp_param->csum = 0;

    if ((err = rt_ip_route_output(&rt, daddr)) < 0)
        return err;

    err = rt_ip_build_xmit(&icmp_socket, rt_icmp_glue_request_bits, icmp_param,
                           icmp_param->head_len + icmp_param->data_len,
                           &rt, MSG_DONTWAIT);

    rtdev_dereference(rt.rtdev);

    return err;
}



/***
 *  rt_icmp_echo_request - sends an echo request to the specified address
 */
int rt_icmp_send_echo(u32 daddr, u16 id, u16 sequence, size_t msg_size)
{
    struct icmp_bxm icmp_param;
    rtos_time_t     time;
    unsigned char   pattern_buf[msg_size];
    off_t           pos;


    icmp_param.head.icmph.type = ICMP_ECHO;
    icmp_param.head.icmph.code = 0;
    icmp_param.head.icmph.un.echo.id       = id;
    icmp_param.head.icmph.un.echo.sequence = htons(sequence);
    icmp_param.offset = 0;

    if (msg_size >= sizeof(nanosecs_t)) {
        icmp_param.head_len = sizeof(struct icmphdr) + sizeof(nanosecs_t);
        icmp_param.data_len = msg_size - sizeof(nanosecs_t);

        for (pos = 0; pos < icmp_param.data_len; pos++)
            pattern_buf[pos] = pos & 0xFF;

        rtos_get_time(&time);
        icmp_param.head.timestamp = rtos_time_to_nanosecs(&time);
    } else {
        icmp_param.head_len = sizeof(struct icmphdr) + msg_size;
        icmp_param.data_len = 0;

        for (pos = 0; pos < msg_size; pos++)
            pattern_buf[pos] = pos & 0xFF;
    }
    icmp_param.data.buf = pattern_buf;

    return rt_icmp_send_request(daddr, &icmp_param);
}



/***
 *  rt_icmp_socket
 */
int rt_icmp_socket(struct rtdm_dev_context *context, int call_flags)
{
    /* we don't support user-created ICMP sockets */
    return -ENOPROTOOPT;
}



static struct rt_icmp_control rt_icmp_pointers[NR_ICMP_TYPES+1] =
{
    /* ECHO REPLY (0) */
    { rt_icmp_echo_reply,       0 },
    { rt_icmp_discard,          1 },
    { rt_icmp_discard,          1 },

    /* DEST UNREACH (3) */
    { rt_icmp_discard,          1 },

    /* SOURCE QUENCH (4) */
    { rt_icmp_discard,          1 },

    /* REDIRECT (5) */
    { rt_icmp_discard,          1 },
    { rt_icmp_discard,          1 },
    { rt_icmp_discard,          1 },

    /* ECHO (8) */
    { rt_icmp_echo_request,     0 },
    { rt_icmp_discard,          1 },
    { rt_icmp_discard,          1 },

    /* TIME EXCEEDED (11) */
    { rt_icmp_discard,          1 },

    /* PARAMETER PROBLEM (12) */
    { rt_icmp_discard,          1 },

    /* TIMESTAMP (13) */
    { rt_icmp_discard,          0 },

    /* TIMESTAMP REPLY (14) */
    { rt_icmp_discard,          0 },

    /* INFO (15) */
    { rt_icmp_discard,          0 },

    /* INFO REPLY (16) */
    { rt_icmp_discard,          0 },

    /* ADDR MASK (17) */
    { rt_icmp_discard,          0 },

    /* ADDR MASK REPLY (18) */
    { rt_icmp_discard,          0 }
};



/***
 *  rt_icmp_dest_pool
 */
struct rtsocket *rt_icmp_dest_socket(struct rtskb *skb)
{
    /* Note that the socket's refcount is not used by this protocol.
     * The socket returned here is static and not part of the global pool. */
    return &icmp_socket;
}



/***
 *  rt_icmp_rcv
 */
int rt_icmp_rcv(struct rtskb *skb)
{
    struct icmphdr *icmpHdr = skb->h.icmph;
    unsigned int length = skb->len;

    /* check header sanity and don't accept fragmented packets */
    if ((length < sizeof(struct icmphdr)) || (skb->next != NULL))
    {
        rtos_print("RTnet: improper length in icmp packet\n");
        goto cleanup;
    }

    if (ip_compute_csum((unsigned char *)icmpHdr, length))
    {
        rtos_print("RTnet: invalid checksum in icmp packet %d\n", length);
        goto cleanup;
    }

    if (!rtskb_pull(skb, sizeof(struct icmphdr)))
    {
        rtos_print("RTnet: pull failed %p\n", (skb->sk));
        goto cleanup;
    }


    if (icmpHdr->type > NR_ICMP_TYPES)
    {
        rtos_print("RTnet: invalid icmp type\n");
        goto cleanup;
    }

    /* sane packet, process it */
    (rt_icmp_pointers[icmpHdr->type].handler)(skb);

  cleanup:
    kfree_rtskb(skb);
    return 0;
}



/***
 *  rt_icmp_rcv_err
 */
void rt_icmp_rcv_err(struct rtskb *skb)
{
    rtos_print("RTnet: rt_icmp_rcv err\n");
}



/***
 *  ICMP-Initialisation
 */
static struct rtinet_protocol icmp_protocol = {
    protocol:       IPPROTO_ICMP,
    dest_socket:    &rt_icmp_dest_socket,
    rcv_handler:    &rt_icmp_rcv,
    err_handler:    &rt_icmp_rcv_err,
    init_socket:    &rt_icmp_socket
};



/***
 *  rt_icmp_init
 */
void __init rt_icmp_init(void)
{
    unsigned int skbs;


    rtos_spin_lock_init(&echo_calls_lock);

    icmp_socket.protocol = IPPROTO_ICMP;
    icmp_socket.prot.inet.tos = 0;
    icmp_socket.priority = RT_ICMP_PRIO;

    /* create the rtskb pool */
    skbs = rtskb_pool_init(&icmp_socket.skb_pool, ICMP_REPLY_POOL_SIZE);
    if (skbs < ICMP_REPLY_POOL_SIZE)
        printk("RTnet: allocated only %d icmp rtskbs\n", skbs);

    rt_inet_add_protocol(&icmp_protocol);
}



/***
 *  rt_icmp_release
 */
void rt_icmp_release(void)
{
    rt_icmp_cleanup_echo_requests();
    rt_inet_del_protocol(&icmp_protocol);
    rtskb_pool_release(&icmp_socket.skb_pool);
}
