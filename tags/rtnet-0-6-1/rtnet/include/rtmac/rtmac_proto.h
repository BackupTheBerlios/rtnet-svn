/* include/rtmac/rtmac_proto.h
 *
 * rtmac - real-time networking media access control subsystem
 * Copyright (C) 2002 Marc Kleine-Budde <kleine-budde@gmx.de>,
 *               2003 Jan Kiszka <Jan.Kiszka@web.de>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 */

#ifndef __RTMAC_PROTO_H_
#define __RTMAC_PROTO_H_

#ifdef __KERNEL__

#include <stack_mgr.h>


#define RTMAC_VERSION   0x1
#define ETH_RTMAC       0x9021

struct rtmac_hdr {
    u16 type;
    u8  ver;
    u8  res;    /* reserved for future use :) */
} __attribute__ ((packed));



static inline int rtmac_add_header(struct rtnet_device *rtdev, void *daddr,
                                   struct rtskb *skb, u16 type)
{
    struct rtmac_hdr *hdr =
        (struct rtmac_hdr *)rtskb_push(skb, sizeof(struct rtmac_hdr));


    hdr->type = __constant_htons(type);
    hdr->ver  = RTMAC_VERSION;

    skb->rtdev = rtdev;

    if (rtdev->hard_header &&
        (rtdev->hard_header(skb, rtdev, ETH_RTMAC, daddr,
                            rtdev->dev_addr, skb->len) < 0))
        return -1;

    return 0;
}



static inline int rtmac_xmit(struct rtskb *skb)
{
    struct rtnet_device *rtdev = skb->rtdev;
    int ret;


    RTNET_ASSERT(rtdev->mac_priv->hard_start_xmit != NULL,
                 kfree_rtskb(skb); return -1;);

    ret = rtdev->mac_priv->hard_start_xmit(skb, rtdev);
    if (ret != 0)
        kfree_rtskb(skb);

    return ret;
}


extern struct rtpacket_type rtmac_packet_type;

#define rtmac_proto_init()  rtdev_add_pack(&rtmac_packet_type)
extern void rtmac_proto_release(void);


#endif /* __KERNEL__ */

#endif /* __RTMAC_PROTO_H_ */
