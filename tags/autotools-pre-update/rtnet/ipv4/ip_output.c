/* ip_input.c
 *
 * Copyright (C) 2002 Ulrich Marx <marx@kammer.uni-hannover.de>
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
 
// $Log: ip_output.c,v $
// Revision 1.7  2003/05/17 19:28:11  hpbock
// rt_ip_build_xmit():
// deleted useless code
//
// Revision 1.6  2003/05/17 16:28:11  hpbock
// rtnet and rtnetproxy now use rtmac function hooks to send packets
// rtmac does not modify hard_start_xmit any more
//
// Revision 1.5  2003/05/16 19:31:52  hpbock
// big fat merge with pre-0-3-0
// compiles and hopefully also runs =8)
//
// Revision 1.4.2.1  2003/03/10 18:18:01  yamwong
// * Fixed bug: 680211 Using ifconfig on RTnet device crashes the system.
// * New device manager: decouple rtnet_device from net_device.
//   NOTE: Only 8139too-rt, eepro100-rt and tulip-rt were tested and known
//   to work.
// * Added new scripts for round trip examples.
//
// Revision 1.4  2003/02/12 07:49:15  hpbock
// rt_ip_build_xmit() returns -EAGAIN if packet could not be sent by rtdev_xmit()
//
// Revision 1.3  2003/02/06 14:34:06  hpbock
// skb was net freed, if rtdev->hard_header was NULL.
//

#include <net/checksum.h>

#include <rtnet.h>
#include <rtnet_internal.h>
#include <../rtmac/include/rtmac.h>

static u16 rt_ip_id_count = 0;

/*
 *	Fast path for unfragmented packets.
 */
int rt_ip_build_xmit(struct rtsocket *sk, 
	            int getfrag (const void *, char *, unsigned int, unsigned int),
		    const void *frag, 
		    unsigned length, 
		    struct rt_rtable *rt, 
		    int flags)
{
	int	err=0;
	struct	rtskb *skb;
	int	df;
	struct	iphdr *iph;
	
	struct	rtnet_device *rtdev=rt->rt_dev;

	/*
	 *	Try the simple case first. This leaves fragmented frames, and by
	 *	choice RAW frames within 20 bytes of maximum size(rare) to the long path
	 */
	length += sizeof(struct iphdr);
	
	df = htons(IP_DF);

	{
		int hh_len = (rtdev->hard_header_len+15)&~15;

		skb = alloc_rtskb(length+hh_len+15);
		if (skb==NULL)
			goto no_rtskb; 
		rtskb_reserve(skb, hh_len);
	}
	
	skb->dst=rt; 
	skb->rtdev=rt->rt_dev;
	skb->nh.iph = iph = (struct iphdr *) rtskb_put(skb, length);
	
	
	iph->version=4;
	iph->ihl=5;
	iph->tos=sk->tos;
	iph->tot_len = htons(length);
	iph->id=htons(rt_ip_id_count++);
	iph->frag_off = df;
	iph->ttl=255;
	iph->protocol=sk->protocol;
	iph->saddr=rt->rt_src;
	iph->daddr=rt->rt_dst;
	iph->check=0;
	iph->check = ip_fast_csum((unsigned char *)iph, iph->ihl);
	
	if ( (err=getfrag(frag, ((char *)iph)+iph->ihl*4, 0, length-iph->ihl*4)) )
		goto error;

	if ( !(rtdev->hard_header) ) {
	     goto error;
	} else if (rtdev->hard_header(skb, rtdev, ETH_P_IP, rt->rt_dst_mac_addr, rtdev->dev_addr, skb->len)<0) {
		goto error;
	}

	if ((skb->rtdev->rtmac) && /* This code lines are crappy! */
	    (skb->rtdev->rtmac->disc_type) &&
	    (skb->rtdev->rtmac->disc_type->rt_packet_tx)) {
	    err = skb->rtdev->rtmac->disc_type->rt_packet_tx(skb, skb->rtdev);
	} else {
	    err = rtdev_xmit(skb);
	}

	if (err) {
		return -EAGAIN;
	} else {
		return 0;
	}
	
error:
	kfree_rtskb(skb);
no_rtskb:
	return err; 
}










/***
 *	IP protocol layer initialiser
 */
static struct rtpacket_type ip_packet_type =
{
	type:		__constant_htons(ETH_P_IP),
	dev:		NULL,	/* All devices */
	handler:	&rt_ip_rcv,
	private:	(void*)1,
};



/***
 *	ip_init
 */
void rt_ip_init(void)
{
	rtdev_add_pack(&ip_packet_type);

}



/***
 *	ip_release
 */
void rt_ip_release(void)
{
	rtdev_remove_pack(&ip_packet_type);
}

