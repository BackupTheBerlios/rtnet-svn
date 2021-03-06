/***
 *
 *  ipv4/ip_output.c - prepare outgoing IP packets
 *
 *  Copyright (C) 2002 Ulrich Marx <marx@kammer.uni-hannover.de>
 *                2003, 2004 Jan Kiszka <jan.kiszka@web.de>
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

#include <net/checksum.h>

#include <rtnet_socket.h>
#include <stack_mgr.h>
#include <ipv4/ip_fragment.h>
#include <ipv4/ip_input.h>
#include <ipv4/route.h>


static rtos_spinlock_t  rt_ip_id_lock  = RTOS_SPIN_LOCK_UNLOCKED;
static u16              rt_ip_id_count = 0;

/***
 *  Slow path for fragmented packets
 */
int rt_ip_build_xmit_slow(struct rtsocket *sk,
        int getfrag(const void *, char *, unsigned int, unsigned int),
        const void *frag, unsigned length, struct dest_route *rt,
        int msg_flags)
{
    int             err, next_err;
    struct rtskb    *skb;
    struct rtskb    *next_skb;
    struct          iphdr *iph;

    struct          rtnet_device *rtdev = rt->rtdev;
    int             mtu = rtdev->mtu;
    unsigned int    fragdatalen;
    unsigned int    offset = 0;
    u16             msg_rt_ip_id;
    unsigned long   flags;
    unsigned int    rtskb_size;
    int             hh_len = (rtdev->hard_header_len + 15) & ~15;


    #define FRAGHEADERLEN sizeof(struct iphdr)

    fragdatalen  = ((mtu - FRAGHEADERLEN) & ~7);

    /* Store id in local variable */
    rtos_spin_lock_irqsave(&rt_ip_id_lock, flags);
    msg_rt_ip_id = rt_ip_id_count++;
    rtos_spin_unlock_irqrestore(&rt_ip_id_lock, flags);

    rtskb_size = mtu + hh_len + 15;

    /* Preallocate first rtskb */
    skb = alloc_rtskb(rtskb_size, &sk->skb_pool);
    if (skb == NULL)
        return -ENOBUFS;

    for (offset = 0; offset < length; offset += fragdatalen)
    {
        int fraglen; /* The length (IP, including ip-header) of this
                        very fragment */
        __u16 frag_off = offset >> 3 ;


        next_err = 0;
        if (offset >= length - fragdatalen)
        {
            /* last fragment */
            fraglen  = FRAGHEADERLEN + length - offset ;
            next_skb = NULL;
        }
        else
        {
            fraglen = FRAGHEADERLEN + fragdatalen;
            frag_off |= IP_MF;

            next_skb = alloc_rtskb(rtskb_size, &sk->skb_pool);
            if (next_skb == NULL) {
                frag_off &= ~IP_MF; /* cut the chain */
                next_err = -ENOBUFS;
            }
        }

        rtskb_reserve(skb, hh_len);

        skb->rtdev    = rtdev;
        skb->nh.iph   = iph = (struct iphdr *)rtskb_put(skb, fraglen);
        skb->priority = sk->priority;

        iph->version  = 4;
        iph->ihl      = 5;    /* 20 byte header - no options */
        iph->tos      = sk->prot.inet.tos;
        iph->tot_len  = htons(fraglen);
        iph->id       = htons(msg_rt_ip_id);
        iph->frag_off = htons(frag_off);
        iph->ttl      = 255;
        iph->protocol = sk->protocol;
        iph->saddr    = rtdev->local_ip;
        iph->daddr    = rt->ip;
        iph->check    = 0; /* required! */
        iph->check    = ip_fast_csum((unsigned char *)iph, 5 /*iph->ihl*/);

        if ( (err=getfrag(frag, ((char *)iph) + 5 /*iph->ihl*/ * 4, offset,
                          fraglen - FRAGHEADERLEN)) )
            goto error;

        if (rtdev->hard_header) {
            err = rtdev->hard_header(skb, rtdev, ETH_P_IP, rt->dev_addr,
                                     rtdev->dev_addr, skb->len);
            if (err < 0)
                goto error;
        }

        err = rtdev_xmit(skb);

        skb = next_skb;

        if (err != 0) {
            err = -EAGAIN;
            goto error;
        }

        if (next_err != 0)
            return next_err;
    }
    return 0;

  error:
    if (skb != NULL) {
        kfree_rtskb(skb);

        if (next_skb != NULL)
            kfree_rtskb(next_skb);
    }
    return err;
}



/***
 *  Fast path for unfragmented packets.
 */
int rt_ip_build_xmit(struct rtsocket *sk,
        int getfrag(const void *, char *, unsigned int, unsigned int),
        const void *frag, unsigned length, struct dest_route *rt,
        int msg_flags)
{
    int                     err=0;
    struct rtskb            *skb;
    struct iphdr            *iph;
    int                     hh_len;
    u16                     msg_rt_ip_id;
    unsigned long           flags;
    struct  rtnet_device    *rtdev = rt->rtdev;


    /*
     *  Try the simple case first. This leaves fragmented frames, and by choice
     *  RAW frames within 20 bytes of maximum size(rare) to the long path
     */
    length += sizeof(struct iphdr);

    if (length > rtdev->mtu)
        return rt_ip_build_xmit_slow(sk, getfrag, frag,
                                length - sizeof(struct iphdr), rt, msg_flags);

    /* Store id in local variable */
    rtos_spin_lock_irqsave(&rt_ip_id_lock, flags);
    msg_rt_ip_id = rt_ip_id_count++;
    rtos_spin_unlock_irqrestore(&rt_ip_id_lock, flags);

    hh_len = (rtdev->hard_header_len+15)&~15;

    skb = alloc_rtskb(length+hh_len+15, &sk->skb_pool);
    if (skb==NULL)
        return -ENOBUFS;

    rtskb_reserve(skb, hh_len);

    skb->rtdev    = rtdev;
    skb->nh.iph   = iph = (struct iphdr *) rtskb_put(skb, length);
    skb->priority = sk->priority;

    iph->version  = 4;
    iph->ihl      = 5;
    iph->tos      = sk->prot.inet.tos;
    iph->tot_len  = htons(length);
    iph->id       = htons(msg_rt_ip_id);
    iph->frag_off = htons(IP_DF);
    iph->ttl      = 255;
    iph->protocol = sk->protocol;
    iph->saddr    = rtdev->local_ip;
    iph->daddr    = rt->ip;
    iph->check    = 0; /* required! */
    iph->check    = ip_fast_csum((unsigned char *)iph, 5 /*iph->ihl*/);

    if ( (err=getfrag(frag, ((char *)iph) + 5 /*iph->ihl*/ * 4, 0,
                      length - 5 /*iph->ihl*/ * 4)) )
        goto error;

    if (rtdev->hard_header) {
        err = rtdev->hard_header(skb, rtdev, ETH_P_IP, rt->dev_addr,
                                 rtdev->dev_addr, skb->len);
        if (err < 0)
            goto error;
    }

    err = rtdev_xmit(skb);

    if (err)
        return -EAGAIN;
    else
        return 0;

  error:
    kfree_rtskb(skb);
    return err;
}



/***
 *  IP protocol layer initialiser
 */
static struct rtpacket_type ip_packet_type =
{
    name:       "IPv4",
    type:       __constant_htons(ETH_P_IP),
    handler:    &rt_ip_rcv
};



/***
 *  ip_init
 */
void __init rt_ip_init(void)
{
    rtdev_add_pack(&ip_packet_type);
    rt_ip_fragment_init();
}



/***
 *  ip_release
 */
void rt_ip_release(void)
{
    rt_ip_fragment_cleanup();
    rtdev_remove_pack(&ip_packet_type);
}
